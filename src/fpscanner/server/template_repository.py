#!/usr/bin/env python3
"""
Repozytoria zaszyfrowanych szablonów biometrycznych.

Repozytorium przechowuje wyłącznie rekordy z `template_vault.encrypt_template`
(nieprzezroczyste bajty `FPT...`), pod kluczem `subject_id`. Nie zna kluczy ani
treści szablonów, więc kompromitacja samej bazy nie ujawnia danych biometrycznych.

Operacja `add` jest atomowa („utwórz, jeśli nie istnieje”): zapobiega wyścigowi
dwóch równoległych rejestracji tej samej osoby.

  * InMemoryTemplateRepository – do testów (dane znikają po restarcie),
  * PostgresTemplateRepository – PostgreSQL (kolumna BYTEA), pula połączeń, wiele procesów;
                                 wymaga `pip install 'fpscanner[postgres]'`.

Obie implementacje mają ten sam interfejs i przechodzą ten sam test kontraktowy
(tests/test_step3.py::_contract).
"""
from __future__ import annotations

import logging
import threading
from typing import Protocol

log = logging.getLogger("fp.repo")


class RepositoryUnavailable(Exception):
    """Baza jest nieosiągalna (sieć, pula, limit czasu). Wywołujący zwraca 503, nie 500."""


class TemplateRepository(Protocol):
    def add(self, subject_id: str, record: bytes) -> bool:
        """Zapisuje rekord. False, gdy `subject_id` już istnieje (nic nie zmienia)."""

    def get(self, subject_id: str) -> bytes | None:
        """Zwraca rekord albo None."""

    def delete(self, subject_id: str) -> bool:
        """Usuwa rekord. True, gdy istniał."""


class InMemoryTemplateRepository:
    def __init__(self):
        self._data: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def add(self, subject_id: str, record: bytes) -> bool:
        with self._lock:
            if subject_id in self._data:
                return False
            self._data[subject_id] = bytes(record)
            return True

    def get(self, subject_id: str) -> bytes | None:
        with self._lock:
            return self._data.get(subject_id)

    def delete(self, subject_id: str) -> bool:
        with self._lock:
            return self._data.pop(subject_id, None) is not None

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class PostgresTemplateRepository:
    """
    PostgreSQL (psycopg 3 + psycopg_pool). Wiele procesów i serwerów może pracować na tej samej bazie:
    `add` to `INSERT ... ON CONFLICT DO NOTHING` (atomowe „utwórz, jeśli nie istnieje”).

    `dsn` zawiera hasło: nigdy go nie logujemy ani nie dołączamy do wyjątków. Na produkcji dodaj do DSN
    `sslmode=verify-full` (i `sslrootcert=`), a użytkownikowi aplikacji nadaj wyłącznie
    SELECT/INSERT/UPDATE/DELETE na tabeli `templates`. Tabelę może utworzyć migracja (wtedy
    `create_schema=False`); domyślnie powstaje przy starcie, pod blokadą doradczą, żeby równoległy
    start wielu procesów nie wpadł w wyścig `CREATE TABLE IF NOT EXISTS`.
    """

    _SCHEMA = ("CREATE TABLE IF NOT EXISTS templates ("
               "subject_id TEXT PRIMARY KEY, record BYTEA NOT NULL, "
               "created_at TIMESTAMPTZ NOT NULL DEFAULT now())")
    _SCHEMA_LOCK = 0x66705F746D706C        # dowolna stała: klucz blokady doradczej inicjalizacji schematu

    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 10, connect_timeout_s: int = 5,
                 statement_timeout_ms: int = 5000, create_schema: bool = True):
        try:
            import psycopg
            from psycopg_pool import ConnectionPool, PoolTimeout
        except ImportError:
            raise RuntimeError("brak psycopg: pip install 'fpscanner[postgres]'") from None
        self._errors = (psycopg.OperationalError, PoolTimeout)
        self._pool = ConnectionPool(
            dsn, min_size=min_size, max_size=max_size, open=False, timeout=connect_timeout_s,
            kwargs={"connect_timeout": connect_timeout_s,
                    "options": f"-c statement_timeout={int(statement_timeout_ms)}"})
        try:
            self._pool.open(wait=True, timeout=connect_timeout_s)
            if create_schema:
                with self._pool.connection() as conn:
                    conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._SCHEMA_LOCK,))
                    conn.execute(self._SCHEMA)
        except self._errors as e:
            self._pool.close()
            raise RepositoryUnavailable(f"PostgreSQL niedostępny ({type(e).__name__})") from None

    def _run(self, sql: str, params: tuple, fetch: bool = False):
        try:
            with self._pool.connection() as conn:
                cur = conn.execute(sql, params)
                return cur.fetchall() if fetch else cur.rowcount
        except self._errors as e:
            log.error("PostgreSQL: operacja nie powiodła się (%s)", type(e).__name__)
            raise RepositoryUnavailable("baza szablonów niedostępna") from None

    def add(self, subject_id: str, record: bytes) -> bool:
        return self._run("INSERT INTO templates (subject_id, record) VALUES (%s, %s) "
                         "ON CONFLICT (subject_id) DO NOTHING", (subject_id, bytes(record))) == 1

    def get(self, subject_id: str) -> bytes | None:
        rows = self._run("SELECT record FROM templates WHERE subject_id = %s", (subject_id,), fetch=True)
        return bytes(rows[0][0]) if rows else None

    def delete(self, subject_id: str) -> bool:
        return self._run("DELETE FROM templates WHERE subject_id = %s", (subject_id,)) == 1

    def close(self) -> None:
        self._pool.close()

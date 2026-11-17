#!/usr/bin/env python3
"""
Budowanie serwisu API ze zmiennych środowiskowych (konfiguracja 12-factor).

    svc, trust = build_service()            # z os.environ
    svc, trust = build_service(env_dict)    # z podanego słownika (testy)

Każdy błąd konfiguracji kończy się `ConfigError` z czytelnym komunikatem
(bez wartości sekretów), więc serwer nie wstaje w półsprawnym stanie.

Zmienne (wymagane oznaczono *):
  FP_JWT_KEY*             klucz HMAC tokenów JWT (base64url, >= 32 B)
  FP_JWT_TTL_S            czas życia tokenu/sesji w s (domyślnie 900)
  FP_BIND_IP              1/0 – wiązanie tokenu z adresem IP (domyślnie 1)
  FP_KEY_PROVIDER         vault (domyślnie) | local (TYLKO testy i benchmarki)
  FP_KEK_<ID>*            [local] klucze główne KEK (base64url, 32 B); id = <ID> małymi literami
  FP_ACTIVE_KEK*          [local] id KEK-a używanego do nowych opakowań
  FP_VAULT_ADDR*          [vault] adres Vaulta (https://...; http tylko z FP_VAULT_ALLOW_HTTP=1)
  FP_VAULT_TOKEN | FP_VAULT_TOKEN_FILE*   [vault] token albo plik z tokenem (np. sink Vault Agent)
  FP_VAULT_KEY            [vault] nazwa klucza Transit (domyślnie fp-kek; derived=true, aes256-gcm96)
  FP_VAULT_MOUNT, FP_VAULT_NAMESPACE, FP_VAULT_CACERT, FP_VAULT_TIMEOUT_S, FP_VAULT_ALLOW_HTTP
  FP_SERVER_SIGNING_KEY*  klucz Ed25519 serwera (base64url, 32 B ziarna)
  FP_DEVICES_FILE*        plik JSON z rejestrem urządzeń (patrz fpscanner.tools.provision_dev)
  FP_REQUIRE_MTLS         1/0 (domyślnie 1)
  FP_REQUIRE_PROOF        1/0 (domyślnie 1)
  FP_TRUSTED_PROXIES      lista CIDR po przecinku (domyślnie brak => nagłówki ignorowane)
  FP_CERT_HEADER          nagłówek z odciskiem certyfikatu (domyślnie x-client-cert-fingerprint)
  FP_CERT_VERIFY_HEADER   nagłówek z wynikiem weryfikacji (np. x-client-cert-verify)
  FP_DATABASE_URL         DSN PostgreSQL; FP_PG_POOL_MAX (10). Bez niego szablony są w pamięci
                          procesu (tylko testy)
  FP_MATCH_THRESHOLD, FP_RETURN_SCORE, FP_MAX_FAILURES_DEVICE, FP_LOCKOUT_WINDOW_S,
  FP_MIN_MINUTIAE, FP_MAX_MINUTIAE      parametry ServiceSettings

Uwaga: KEK-i w zmiennych (FP_KEY_PROVIDER=local) i sekrety urządzeń z pliku to rozwiązanie
deweloperskie. Na produkcji: FP_KEY_PROVIDER=vault, a sekrety urządzeń w magazynie sekretów.
Nonce'y, sesje i limit prób są w pamięci procesu, więc serwer działa jako jeden proces
(patrz README, „Ograniczenia”).
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fpscanner.security.device_auth import (
    DevicePolicy,
    InMemoryDeviceRegistry,
    NetworkTrust,
    normalize_fingerprint,
)
from fpscanner.security.session_tokens import TokenService
from fpscanner.security.template_vault import KeyProvider, KeyProviderUnavailable, LocalKeyProvider
from fpscanner.security.vault_transit import VaultTransitKeyProvider
from fpscanner.server.api_service import ApiService, ServiceSettings
from fpscanner.server.template_repository import (
    InMemoryTemplateRepository,
    PostgresTemplateRepository,
    RepositoryUnavailable,
    TemplateRepository,
)

log = logging.getLogger("fp.config")
KEK_PREFIX = "FP_KEK_"


class ConfigError(Exception):
    """Niepoprawna lub niepełna konfiguracja serwera."""


def _get(env: Mapping[str, str], name: str, default: str | None = None) -> str:
    value = env.get(name, default)
    if value is None or value == "":
        raise ConfigError(f"brak wymaganej zmiennej {name}")
    return value


def _b64(value: str, name: str, length: int | None = None) -> bytes:
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ConfigError(f"{name}: niepoprawne base64url") from None
    if length is not None and len(raw) != length:
        raise ConfigError(f"{name}: oczekiwano {length} bajtów")
    return raw


def _num(env, name: str, cast, default):
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        return cast(raw)
    except ValueError:
        raise ConfigError(f"{name}: niepoprawna wartość") from None


def _flag(env, name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw in (None, ""):
        return default
    if raw.strip().lower() in ("1", "true", "yes", "tak"):
        return True
    if raw.strip().lower() in ("0", "false", "no", "nie"):
        return False
    raise ConfigError(f"{name}: oczekiwano 1/0")


def _load_devices(path: str, registry: InMemoryDeviceRegistry) -> None:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        raise ConfigError(f"FP_DEVICES_FILE: nie można odczytać pliku {path!r}") from None
    except ValueError:
        raise ConfigError("FP_DEVICES_FILE: niepoprawny JSON") from None
    if os.name == "posix" and p.stat().st_mode & 0o077:
        log.warning("plik %s zawiera sekrety i powinien mieć uprawnienia 0600", path)
    try:
        for d in data["devices"]:
            fp = d.get("cert_fingerprint")
            registry.register(d["device_id"], secret=_b64(d["secret"], "secret"),
                              cert_fingerprint=normalize_fingerprint(fp) if fp else None,
                              permissions=d.get("permissions"))
    except (KeyError, TypeError, AttributeError, ValueError) as e:
        raise ConfigError(f"FP_DEVICES_FILE: niepoprawny wpis urządzenia ({e})") from None


def build_key_provider(env: Mapping[str, str] | None = None) -> KeyProvider:
    """Dostawca kluczy wg FP_KEY_PROVIDER (vault | local). Domyślnie vault: brak ustawienia nie
    uruchamia po cichu słabszej ścieżki z kluczami w zmiennych środowiskowych."""
    env = os.environ if env is None else env
    kind = (env.get("FP_KEY_PROVIDER") or "vault").strip().lower()
    if kind == "vault":
        if any(n.startswith(KEK_PREFIX) and v for n, v in env.items()):
            log.warning("FP_KEY_PROVIDER=vault: zmienne %s* są ignorowane (usuń je z konfiguracji)",
                        KEK_PREFIX)
        try:
            return VaultTransitKeyProvider(
                _get(env, "FP_VAULT_ADDR"), env.get("FP_VAULT_KEY") or "fp-kek",
                token=env.get("FP_VAULT_TOKEN") or None,
                token_file=env.get("FP_VAULT_TOKEN_FILE") or None,
                mount=env.get("FP_VAULT_MOUNT") or "transit",
                namespace=env.get("FP_VAULT_NAMESPACE") or None,
                ca_cert=env.get("FP_VAULT_CACERT") or None,
                timeout_s=_num(env, "FP_VAULT_TIMEOUT_S", float, 5.0),
                allow_insecure_http=_flag(env, "FP_VAULT_ALLOW_HTTP", False))
        except ValueError as e:
            raise ConfigError(f"FP_VAULT_*: {e}") from None
        except KeyProviderUnavailable as e:
            raise ConfigError(f"Vault: {e}") from None
    if kind != "local":
        raise ConfigError("FP_KEY_PROVIDER: oczekiwano 'vault' lub 'local'")
    log.warning("FP_KEY_PROVIDER=local: KEK-i w zmiennych środowiskowych, tylko testy i benchmarki")
    keks = {name[len(KEK_PREFIX):].lower(): _b64(value, name, 32)
            for name, value in env.items() if name.startswith(KEK_PREFIX) and value}
    if not keks:
        raise ConfigError(f"brak kluczy KEK (zmienne {KEK_PREFIX}<id>)")
    try:
        return LocalKeyProvider(keks, _get(env, "FP_ACTIVE_KEK"))
    except ValueError as e:
        raise ConfigError(f"FP_ACTIVE_KEK/{KEK_PREFIX}*: {e}") from None


def build_repository(env: Mapping[str, str] | None = None) -> TemplateRepository:
    """Repozytorium szablonów: PostgreSQL (FP_DATABASE_URL); bez niego pamięć procesu (testy)."""
    env = os.environ if env is None else env
    dsn = env.get("FP_DATABASE_URL")
    if dsn:
        try:
            return PostgresTemplateRepository(dsn, max_size=_num(env, "FP_PG_POOL_MAX", int, 10))
        except (RepositoryUnavailable, RuntimeError) as e:        # RuntimeError: brak pakietu psycopg
            raise ConfigError(f"FP_DATABASE_URL: {e}") from None
    log.warning("FP_DATABASE_URL nie ustawiono: szablony w pamięci procesu (tylko testy)")
    return InMemoryTemplateRepository()


def build_service(env: Mapping[str, str] | None = None, *,
                  clock=None) -> tuple[ApiService, NetworkTrust]:
    env = os.environ if env is None else env

    try:
        jwt_key = _b64(_get(env, "FP_JWT_KEY"), "FP_JWT_KEY")
        tokens = TokenService(jwt_key, ttl_s=_num(env, "FP_JWT_TTL_S", int, 900),
                              bind_ip=_flag(env, "FP_BIND_IP", True))
    except ValueError as e:
        raise ConfigError(f"FP_JWT_KEY/FP_JWT_*: {e}") from None

    provider = build_key_provider(env)

    identity = Ed25519PrivateKey.from_private_bytes(
        _b64(_get(env, "FP_SERVER_SIGNING_KEY"), "FP_SERVER_SIGNING_KEY", 32))

    registry = InMemoryDeviceRegistry()
    _load_devices(_get(env, "FP_DEVICES_FILE"), registry)

    try:
        policy = DevicePolicy(_flag(env, "FP_REQUIRE_MTLS", True),
                              _flag(env, "FP_REQUIRE_PROOF", True))
        proxies = tuple(p.strip() for p in env.get("FP_TRUSTED_PROXIES", "").split(",") if p.strip())
        trust = NetworkTrust(
            trusted_proxies=proxies,
            cert_header=env.get("FP_CERT_HEADER") or "x-client-cert-fingerprint",
            verify_header=env.get("FP_CERT_VERIFY_HEADER") or None)
        settings = ServiceSettings(
            match_threshold=_num(env, "FP_MATCH_THRESHOLD", float, 0.25),
            return_score=_flag(env, "FP_RETURN_SCORE", False),
            max_failures_per_device=_num(env, "FP_MAX_FAILURES_DEVICE", int, 50),
            lockout_window_s=_num(env, "FP_LOCKOUT_WINDOW_S", int, 300),
            min_minutiae=_num(env, "FP_MIN_MINUTIAE", int, 12),
            max_minutiae=_num(env, "FP_MAX_MINUTIAE", int, 1000))
    except ValueError as e:
        raise ConfigError(str(e)) from None

    repo = build_repository(env)

    svc = ApiService(tokens=tokens, devices=registry, policy=policy, identity_key=identity,
                     vault_provider=provider, repo=repo, settings=settings, clock=clock)
    return svc, trust

#!/usr/bin/env python3
"""
Format wiadomości warstwy aplikacyjnej (to, co jest szyfrowane w SealedMessage)
oraz stałe protokołu: ścieżki API i cele wiadomości.

Treść żądań enroll/verify/erase:
    subject_len:u16 (big-endian) | subject_id (ASCII) | dane (np. szablon .tpl)
Odpowiedzi to kanoniczny JSON (UTF-8, klucze posortowane, bez spacji).

`subject_id` jest identyfikatorem osoby i trafia do AAD rekordu w bazie, więc
dopuszczamy wyłącznie bezpieczny zestaw znaków (bez spacji, ukośników i
znaków spoza ASCII): wyklucza to dwuznaczności i ataki przez normalizację
Unicode.
"""
from __future__ import annotations

import json
import re
import struct

# Ścieżki API
PATH_HANDSHAKE = "/v1/handshake"
PATH_ENROLL = "/v1/enroll"
PATH_VERIFY = "/v1/verify"
PATH_ERASE = "/v1/erase"
PATH_CLOSE = "/v1/session/close"

# Cele wiadomości (SealedMessage.purpose; 1–32 znaków [a-z0-9_.-])
PURPOSE_ENROLL = "enroll"
PURPOSE_VERIFY = "verify"
PURPOSE_ERASE = "erase"

MAX_SUBJECT_ID = 128
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,128}$")


class ProtocolError(Exception):
    """Niepoprawna treść wiadomości aplikacyjnej."""


def response_purpose(purpose: str) -> str:
    """Cel wiadomości zwrotnej serwera. Inny niż cel żądania, więc odpowiedź
    nie może zostać podstawiona jako żądanie (i odwrotnie)."""
    return purpose + ".resp"


def check_subject_id(subject_id: str) -> str:
    if not isinstance(subject_id, str) or not _SUBJECT_RE.match(subject_id):
        raise ProtocolError("subject_id: 1–128 znaków z zestawu [A-Za-z0-9._@:-]")
    return subject_id


def pack_subject_payload(subject_id: str, data: bytes = b"") -> bytes:
    check_subject_id(subject_id)
    raw = subject_id.encode("ascii")
    return struct.pack(">H", len(raw)) + raw + bytes(data)


def unpack_subject_payload(raw: bytes) -> tuple[str, bytes]:
    if len(raw) < 2:
        raise ProtocolError("treść żądania jest za krótka")
    (n,) = struct.unpack_from(">H", raw, 0)
    if n == 0 or n > MAX_SUBJECT_ID or len(raw) < 2 + n:
        raise ProtocolError("niepoprawna długość subject_id")
    try:
        subject = raw[2:2 + n].decode("ascii")
    except UnicodeDecodeError as e:
        raise ProtocolError("subject_id musi być ASCII") from e
    return check_subject_id(subject), raw[2 + n:]


def pack_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def unpack_json(raw: bytes) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ProtocolError("niepoprawny JSON") from e
    if not isinstance(obj, dict):
        raise ProtocolError("oczekiwano obiektu JSON")
    return obj

#!/usr/bin/env python3
"""
Konfiguracja TLS 1.3 i mTLS oraz generator deweloperskiego PKI.

`server_ssl_context` / `client_ssl_context` budują konteksty `ssl` z minimalną
wersją TLS 1.3. mTLS: serwer wymaga certyfikatu klienta podpisanego przez
nasze CA (CERT_REQUIRED), klient weryfikuje serwer względem tego samego CA.

`generate_dev_pki` tworzy CA, certyfikat serwera i certyfikaty urządzeń (ECDSA
P-256) wyłącznie do ROZWOJU i testów. Na produkcji CA powinno być w HSM/Vault
PKI, a klucze urządzeń generowane na urządzeniu (nigdy kopiowane).

Uwaga o uvicorn: nie przyjmuje gotowego `SSLContext`, więc samo `--ssl-*` nie
wymusi TLS 1.3. Zalecany układ: reverse proxy (TLS 1.3 + weryfikacja
certyfikatu klienta) przed aplikacją; patrz device_auth.NetworkTrust.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fpscanner.security.device_auth import fingerprint_der


# --------------------------------------------------------------------------- #
# Konteksty ssl
# --------------------------------------------------------------------------- #
def server_ssl_context(certfile: str, keyfile: str, client_ca_file: str, *,
                       require_client_cert: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    ctx.load_verify_locations(client_ca_file)
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    return ctx


def client_ssl_context(ca_file: str, certfile: str | None = None,
                       keyfile: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_file)
    if certfile:
        ctx.load_cert_chain(certfile, keyfile)
    return ctx


# --------------------------------------------------------------------------- #
# Deweloperskie PKI
# --------------------------------------------------------------------------- #
def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "fp-dev"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _issue(cn: str, pub, issuer_name: x509.Name, issuer_key, issuer_pub, *, ca: bool = False,
           eku=None, sans=None, days: int = 365):
    now = datetime.datetime.now(datetime.UTC)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(issuer_name)
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                            critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                            critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _write(path: Path, data: bytes, secret: bool = False) -> str:
    path.write_bytes(data)
    if secret:
        os.chmod(path, 0o600)
    return str(path)


def _pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def generate_dev_pki(directory: str | Path, device_ids: list[str], *,
                     server_names: tuple = ("localhost",),
                     server_ips: tuple = ("127.0.0.1",),
                     extra_ca_names: tuple = ()) -> dict:
    """
    Zapisuje w `directory`: ca.pem, ca.key, server.pem, server.key oraz
    device-<id>.pem/.key. Zwraca ścieżki i odciski certyfikatów urządzeń.
    `extra_ca_names`: nazwy dodatkowych, niezależnych CA (do testów negatywnych)
    zapisywane jako other-<nazwa>-ca.pem i device-<nazwa>.pem/.key.
    """
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)

    def new_ca(cn: str):
        key = ec.generate_private_key(ec.SECP256R1())
        name = _name(cn)
        now = datetime.datetime.now(datetime.UTC)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                               critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    def leaf(cn, ca_key, ca_cert, eku, sans=None):
        key = ec.generate_private_key(ec.SECP256R1())
        return key, _issue(cn, key.public_key(), ca_cert.subject, ca_key, ca_cert.public_key(),
                           eku=eku, sans=sans)

    ca_key, ca_cert = new_ca("fp-dev-ca")
    out: dict = {"ca": _write(d / "ca.pem", _pem_cert(ca_cert)),
                 "ca_key": _write(d / "ca.key", _pem_key(ca_key), True), "devices": {}}

    sans = [x509.DNSName(n) for n in server_names] + [x509.IPAddress(ipaddress.ip_address(i))
                                                      for i in server_ips]
    skey, scert = leaf("fp-server", ca_key, ca_cert, ExtendedKeyUsageOID.SERVER_AUTH, sans)
    out["server_cert"] = _write(d / "server.pem", _pem_cert(scert))
    out["server_key"] = _write(d / "server.key", _pem_key(skey), True)

    for dev in device_ids:
        k, c = leaf(dev, ca_key, ca_cert, ExtendedKeyUsageOID.CLIENT_AUTH)
        out["devices"][dev] = {
            "cert": _write(d / f"device-{dev}.pem", _pem_cert(c)),
            "key": _write(d / f"device-{dev}.key", _pem_key(k), True),
            "fingerprint": fingerprint_der(c.public_bytes(serialization.Encoding.DER)),
        }

    for name in extra_ca_names:                       # obce CA: do testów odrzucania
        okey, ocert = new_ca(f"other-{name}-ca")
        k, c = leaf(name, okey, ocert, ExtendedKeyUsageOID.CLIENT_AUTH)
        out[f"other_{name}"] = {
            "ca": _write(d / f"other-{name}-ca.pem", _pem_cert(ocert)),
            "cert": _write(d / f"device-{name}.pem", _pem_cert(c)),
            "key": _write(d / f"device-{name}.key", _pem_key(k), True),
        }
    return out

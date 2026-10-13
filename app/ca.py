"""Explicitly initialized local teaching CA and its X.509 certificate profile."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


DEFAULT_CA_DIR = Path(os.environ.get(
    "CRYPTOLAB_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".local-data")
)) / "ca"
KEY_VERSION = 1


@dataclass(frozen=True)
class TeachingCA:
    key: rsa.RSAPrivateKey
    certificate: x509.Certificate


def _usage(*, ca: bool = False, signature: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=signature, content_commitment=False,
        key_encipherment=not ca and not signature, data_encipherment=False,
        key_agreement=False, key_cert_sign=ca, crl_sign=ca,
        encipher_only=False, decipher_only=False,
    )


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def initialize_ca(directory: Path) -> str:
    """Create a new CA only in an absent directory; never rotate it implicitly."""
    directory = Path(directory)
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.mkdir(mode=0o700, exist_ok=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoLab local teaching CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CryptoLab Local Root CA"),
    ])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_usage(ca=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_exclusive(directory / "ca-key.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ), 0o600)
    _write_exclusive(directory / "ca-cert.pem", cert.public_bytes(serialization.Encoding.PEM), 0o644)
    return cert.fingerprint(hashes.SHA256()).hex(":")


def load_ca(directory: Path) -> TeachingCA:
    directory = Path(directory)
    cert = x509.load_pem_x509_certificate((directory / "ca-cert.pem").read_bytes())
    key = serialization.load_pem_private_key((directory / "ca-key.pem").read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.public_key() != cert.public_key():
        raise ValueError("Закрытый ключ CA не соответствует корневому сертификату")
    verify_root(cert)
    return TeachingCA(key, cert)


def verify_root(cert: x509.Certificate, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    if cert.subject != cert.issuer or not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Корневой сертификат недействителен")
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Корневой сертификат не является CA")
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.key_cert_sign or usage.digital_signature or usage.key_encipherment:
        raise ValueError("Неверное назначение корневого сертификата")
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())


def issue_student_certificate(
    ca: TeachingCA, actor_id: str, purpose: str, public_key: rsa.RSAPublicKey,
    version: int = KEY_VERSION, now: datetime | None = None,
) -> x509.Certificate:
    if purpose not in {"encryption", "signature"}:
        raise ValueError("Неизвестное назначение сертификата")
    now = now or datetime.now(timezone.utc)
    if not ca.certificate.not_valid_before_utc <= now <= ca.certificate.not_valid_after_utc:
        raise ValueError("Срок корневого сертификата истёк")
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoLab local teaching CA"),
        x509.NameAttribute(NameOID.USER_ID, actor_id),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"key-version:{version}"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"CryptoLab student {purpose}"),
    ])
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(ca.certificate.subject)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(min(now + timedelta(days=7), ca.certificate.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_usage(signature=purpose == "signature"), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ), critical=False)
        .sign(ca.key, hashes.SHA256())
    )
    verify_student_certificate(cert, ca.certificate, actor_id, purpose, version, public_key, now=now)
    return cert


def verify_student_certificate(
    cert: x509.Certificate, root: x509.Certificate, actor_id: str,
    purpose: str, version: int, public_key: rsa.RSAPublicKey,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(timezone.utc)
    verify_root(root, now=now)
    if cert.issuer != root.subject or not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Срок или издатель сертификата неверен")
    root.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
    attrs = cert.subject
    if attrs.get_attributes_for_oid(NameOID.USER_ID)[0].value != actor_id:
        raise ValueError("Сертификат принадлежит другой учебной записи")
    if attrs.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value != f"key-version:{version}":
        raise ValueError("Неверная версия ключа")
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Студенческий сертификат не должен быть CA")
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if usage.digital_signature != (purpose == "signature") or usage.key_encipherment != (purpose == "encryption") or usage.key_cert_sign:
        raise ValueError("Неверное назначение сертификата")
    if cert.public_key() != public_key:
        raise ValueError("Сертификат относится к другому открытому ключу")


def main() -> None:
    parser = argparse.ArgumentParser(description="Local CryptoLab teaching CA")
    parser.add_argument("command", choices=["init", "fingerprint"])
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_CA_DIR)
    args = parser.parse_args()
    if args.command == "init":
        fingerprint = initialize_ca(args.data_dir)
    else:
        fingerprint = load_ca(args.data_dir).certificate.fingerprint(hashes.SHA256()).hex(":")
    print(f"CA SHA-256: {fingerprint}")


if __name__ == "__main__":
    main()

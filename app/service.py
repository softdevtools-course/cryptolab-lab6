"""Separate persistent RSA-OAEP identity for the teaching server participant."""

import argparse
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app.ca import DEFAULT_CA_DIR, load_ca, verify_root

DEFAULT_SERVICE_DIR = Path(os.environ.get(
    "CRYPTOLAB_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".local-data")
)) / "service"
ACTOR_ID = "service:cryptolab"


def initialize_service(directory: Path = DEFAULT_SERVICE_DIR, ca_dir: Path = DEFAULT_CA_DIR) -> None:
    directory = Path(directory)
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.mkdir(mode=0o700, exist_ok=False)
    ca = load_ca(ca_dir)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoLab local teaching CA"),
        x509.NameAttribute(NameOID.USER_ID, ACTOR_ID),
        x509.NameAttribute(NameOID.COMMON_NAME, "CryptoLab service encryption"),
    ])
    usage = x509.KeyUsage(False, False, True, False, False, False, False, False, False)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.certificate.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(min(now + timedelta(days=365), ca.certificate.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(usage, critical=True).sign(ca.key, hashes.SHA256()))
    for path, data, mode in (
        (directory / "service-key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600),
        (directory / "service-cert.pem", cert.public_bytes(serialization.Encoding.PEM), 0o644),
    ):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(data)


def load_service(directory: Path, ca_dir: Path, now: datetime | None = None):
    ca = load_ca(ca_dir)
    cert = x509.load_pem_x509_certificate((Path(directory) / "service-cert.pem").read_bytes())
    key = serialization.load_pem_private_key((Path(directory) / "service-key.pem").read_bytes(), password=None)
    now = now or datetime.now(timezone.utc)
    verify_root(ca.certificate, now)
    if not isinstance(key, rsa.RSAPrivateKey) or key.public_key() != cert.public_key() or cert.issuer != ca.certificate.subject or not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Сертификат серверного участника недействителен")
    ca.certificate.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
    if cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value != ACTOR_ID or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Неверный владелец сертификата сервиса")
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.key_encipherment or usage.digital_signature or usage.key_cert_sign:
        raise ValueError("Неверное назначение сертификата сервиса")
    return key, cert


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init"])
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_SERVICE_DIR)
    parser.add_argument("--ca-dir", type=Path, default=DEFAULT_CA_DIR)
    args = parser.parse_args()
    initialize_service(args.data_dir, args.ca_dir)
    print("Сертификат серверного участника создан")

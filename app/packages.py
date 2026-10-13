"""Version 1 of the small, ASCII-only teaching package format."""

import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES-256-GCM+RSA-OAEP-SHA256"
AAD_FIELDS = ("version", "package_id", "lab_id", "sender_actor_id", "recipient_actor_id", "recipient_certificate_serial", "algorithm")
PACKAGE_FIELDS = set(AAD_FIELDS) | {"wrapped_key", "iv", "ciphertext", "created_at"}


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Некорректный base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64e(raw) != value:
        raise ValueError("Неканонический base64url")
    return raw


def aad(packet: dict) -> bytes:
    # Fixed order and compact ASCII JSON are part of format v1. Metadata values
    # are restricted to ASCII, so JS JSON.stringify produces identical bytes.
    return json.dumps({name: packet[name] for name in AAD_FIELDS}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate(packet: dict) -> None:
    if not isinstance(packet, dict) or set(packet) != PACKAGE_FIELDS:
        raise ValueError("Неверный состав полей пакета")
    if type(packet["version"]) is not int or packet["version"] != 1 or type(packet["lab_id"]) is not int or packet["lab_id"] != 6 or packet["algorithm"] != ALGORITHM:
        raise ValueError("Неподдерживаемая версия или алгоритм")
    for name in ("package_id", "sender_actor_id", "recipient_actor_id", "recipient_certificate_serial", "created_at"):
        value = packet[name]
        if not isinstance(value, str) or not 1 <= len(value) <= 100 or not re.fullmatch(r"[A-Za-z0-9:_.+\-]+", value):
            raise ValueError(f"Неверное поле {name}")
    for name in ("wrapped_key", "iv", "ciphertext"):
        if len(packet[name]) > 10000:
            raise ValueError("Пакет слишком велик")
        b64d(packet[name])
    if len(b64d(packet["iv"])) != 12 or len(b64d(packet["wrapped_key"])) != 256:
        raise ValueError("Неверная длина IV или обёрнутого ключа")


def packet_hash(packet: dict) -> str:
    validate(packet)
    # All accepted JSON values are ASCII strings or small integers. Sorting
    # property names and compact escaping is RFC 8785 for this constrained set.
    canonical = json.dumps(packet, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def encrypt(text: str, recipient_key, *, package_id: str, sender: str, recipient: str, serial: str, created_at: str | None = None) -> dict:
    packet = {
        "version": 1, "package_id": package_id, "lab_id": 6,
        "sender_actor_id": sender, "recipient_actor_id": recipient,
        "recipient_certificate_serial": serial, "algorithm": ALGORITHM,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    packet["wrapped_key"] = b64e(recipient_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
    packet["iv"] = b64e(iv)
    packet["ciphertext"] = b64e(AESGCM(key).encrypt(iv, text.encode("utf-8"), aad(packet)))
    validate(packet)
    return packet


def decrypt(packet: dict, private_key) -> str:
    validate(packet)
    key = private_key.decrypt(b64d(packet["wrapped_key"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    if len(key) != 32:
        raise ValueError("Неверная длина AES-ключа")
    return AESGCM(key).decrypt(b64d(packet["iv"]), b64d(packet["ciphertext"]), aad(packet)).decode("utf-8")

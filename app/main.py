"""Local CryptoLab server for decryption, personal keys, certificates and signatures."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from app.ca import DEFAULT_CA_DIR, KEY_VERSION, issue_student_certificate, load_ca, verify_student_certificate
from app.packages import encrypt as encrypt_package, decrypt as decrypt_package, packet_hash
from app.service import ACTOR_ID as SERVICE_ACTOR, DEFAULT_SERVICE_DIR, load_service
from app.state import DEFAULT_DB_PATH, StateStore, STEPS


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
WEB = ROOT / "web"
EXAMPLE_FILES = {"training-key.pem", "wrong-key.pem", "ciphertext.txt"}
COOKIE_NAME = "cryptolab_stage1"


class AnswerRequest(BaseModel):
    answer: str = Field(min_length=1, max_length=128)


class PublicKeysRequest(BaseModel):
    encryption_spki: str = Field(min_length=1, max_length=1024)
    signing_spki: str = Field(min_length=1, max_length=1024)


class KeyProofRequest(AnswerRequest):
    signature: str = Field(min_length=1, max_length=1024)


class CertificateCheckRequest(BaseModel):
    ca_fingerprint_sha256: str = Field(min_length=1, max_length=128)


class SignatureEvidenceRequest(BaseModel):
    own_signature: str = Field(min_length=1, max_length=1024)
    temporary_spki: str = Field(min_length=1, max_length=1024)
    temporary_signature: str = Field(min_length=1, max_length=1024)
    altered_text: str = Field(min_length=1, max_length=256)


class PackageRequest(BaseModel):
    package: dict = Field(default_factory=dict)


class StudentRequest(BaseModel):
    surname: str = Field(min_length=2, max_length=80)
    group: str = Field(min_length=2, max_length=40)

    @field_validator("surname", "group")
    @classmethod
    def normalize(cls, value: str, info):
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Уберите переносы строк и управляющие символы")
        value = re.sub(r" +", " ", value.strip())
        if info.field_name == "surname":
            if not (2 <= len(value) <= 80 and value[0].isalpha()
                    and all(char.isalpha() or char in " -'’" for char in value)):
                raise ValueError("Укажите фамилию буквами")
        elif not (2 <= len(value) <= 40 and re.fullmatch(r"\w[\w .()/\-]*", value)):
            raise ValueError("Укажите код группы буквами и цифрами")
        return value


def decode_base64url(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise HTTPException(status_code=422, detail="Ожидался base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Некорректный base64url") from error


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def rsa_public_key(value: str) -> tuple[rsa.RSAPublicKey, bytes]:
    raw = decode_base64url(value)
    try:
        key = serialization.load_der_public_key(raw)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Некорректный открытый ключ SPKI") from error
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048 or key.public_numbers().e != 65537:
        raise HTTPException(status_code=422, detail="Нужен открытый ключ RSA 2048, e=65537")
    canonical_spki = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, canonical_spki


def create_app(
    *, clock: Callable[[], float] = time.time, challenge_ttl: int = 300,
    ca_dir: Path = DEFAULT_CA_DIR,
    service_dir: Path = DEFAULT_SERVICE_DIR, db_path: Path | None = None,
    certificate_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> FastAPI:
    app = FastAPI(title="CryptoLab — учебная лабораторная №6")
    training_key = serialization.load_pem_private_key(
        (EXAMPLES / "training-key.pem").read_bytes(), password=None
    )
    state_store = StateStore(db_path) if db_path is not None else None
    sessions: dict[str, dict] = state_store.load() if state_store else {}
    challenges: dict[str, dict] = {}
    key_challenges: dict[str, dict] = {}
    signature_challenges: dict[str, dict] = {}
    outbound_challenges: dict[str, dict] = {}
    inbound_challenges: dict[str, dict] = {}

    @app.middleware("http")
    async def local_session(request: Request, call_next):
        session_id = request.cookies.get(COOKIE_NAME)
        new_session = not session_id or session_id not in sessions
        if new_session:
            session_id = secrets.token_urlsafe(32)
            sessions[session_id] = {
                "actor_id": f"student:{secrets.token_urlsafe(12)}",
                "student": None,
                "completed": False,
                "keys_verified": False,
                "public_keys": None,
                "active_key_challenge": None,
                "certificates": None,
                "certificates_verified": False,
                "certificates_ready": False,
                "signature_verified": False,
                "active_signature_challenge": None,
                "outbound_verified": False,
                "inbound_verified": False,
                "submitted_at": None,
                "outbound_hash": None,
                "inbound_package_id": None,
            }
        request.state.session_id = session_id
        response = await call_next(request)
        if state_store:
            state_store.save(session_id, sessions[session_id])
        if new_session:
            response.set_cookie(
                COOKIE_NAME,
                session_id,
                httponly=True,
                samesite="lax",
                secure=os.environ.get("CRYPTOLAB_COOKIE_SECURE") == "1",
                max_age=30 * 24 * 60 * 60,
            )
        return response

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html", media_type="text/html")

    @app.get("/app.js")
    def javascript():
        return FileResponse(WEB / "app.js", media_type="text/javascript")

    @app.get("/crypto.js")
    def crypto_module():
        return FileResponse(WEB / "crypto.js", media_type="text/javascript")

    @app.get("/personal-keys.js")
    def personal_keys_module():
        return FileResponse(WEB / "personal-keys.js", media_type="text/javascript")

    @app.get("/key-store.js")
    def key_store_module():
        return FileResponse(WEB / "key-store.js", media_type="text/javascript")

    @app.get("/signature.js")
    def signature_module():
        return FileResponse(WEB / "signature.js", media_type="text/javascript")

    @app.get("/packages.js")
    def packages_module():
        return FileResponse(WEB / "packages.js", media_type="text/javascript")

    @app.get("/styles.css")
    def stylesheet():
        return FileResponse(WEB / "styles.css", media_type="text/css")

    @app.get("/examples/{name}")
    def example(name: str):
        if name not in EXAMPLE_FILES:
            raise HTTPException(status_code=404, detail="Пример не найден")
        return FileResponse(EXAMPLES / name, media_type="text/plain; charset=utf-8")

    @app.get("/api/state")
    def state(request: Request):
        session = sessions[request.state.session_id]
        certificates = session["certificates"]
        current = certificates is not None and all(
            cert.not_valid_before_utc <= certificate_clock() <= cert.not_valid_after_utc
            for cert in certificates.values()
        )
        return {
            "actor_id": session["actor_id"],
            "student": session.get("student"),
            "completed": session["completed"],
            "keys_verified": session["keys_verified"],
            "certificates_issued": session["certificates"] is not None,
            "certificates_verified": session["certificates_verified"],
            "certificates_current": current,
            "certificates_ready": current and session["certificates_ready"],
            "signature_verified": session["signature_verified"],
            "outbound_verified": session["outbound_verified"],
            "inbound_verified": session["inbound_verified"],
            "submitted_at": session.get("submitted_at"),
            "steps_done": sum(int(session[name]) for name in STEPS),
            "steps_total": 6,
        }

    @app.post("/api/student")
    def save_student(request: Request, body: StudentRequest):
        session = sessions[request.state.session_id]
        if session.get("submitted_at") and session.get("student"):
            raise HTTPException(status_code=409, detail="Работа уже отправлена; данные для сдачи закреплены")
        session["student"] = body.model_dump()
        return session["student"]

    def teaching_ca():
        try:
            return load_ca(ca_dir)
        except FileNotFoundError as error:
            raise HTTPException(status_code=503, detail="Учебный CA ещё не инициализирован") from error

    @app.get("/api/ca")
    def ca_root():
        ca = teaching_ca()
        return {
            "certificate_pem": ca.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "fingerprint_sha256": ca.certificate.fingerprint(hashes.SHA256()).hex(":"),
            "valid_until": ca.certificate.not_valid_after_utc.isoformat(),
        }

    def certificate_payload(session: dict, ca: x509.Certificate) -> dict:
        def describe(cert: x509.Certificate, purpose: str) -> dict:
            return {
                "purpose": purpose,
                "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "serial_number": format(cert.serial_number, "x"),
                "valid_from": cert.not_valid_before_utc.isoformat(),
                "valid_until": cert.not_valid_after_utc.isoformat(),
                "ca_fingerprint_sha256": ca.fingerprint(hashes.SHA256()).hex(":"),
            }

        return {
            "actor_id": session["actor_id"],
            "key_version": KEY_VERSION,
            "ca_fingerprint_sha256": ca.fingerprint(hashes.SHA256()).hex(":"),
            "encryption": describe(session["certificates"]["encryption"], "encryption"),
            "signature": describe(session["certificates"]["signature"], "signature"),
        }

    @app.post("/api/certificates")
    def issue_certificates(request: Request):
        session = sessions[request.state.session_id]
        if not session["keys_verified"]:
            raise HTTPException(status_code=409, detail="Сначала подтвердите владение личными ключами")
        ca = teaching_ca()
        now = certificate_clock()
        previous = session["certificates"]
        if previous is None or any(now > cert.not_valid_after_utc for cert in previous.values()):
            public = session["public_keys"]
            try:
                renewed = {
                    purpose: issue_student_certificate(
                        ca, session["actor_id"], purpose,
                        serialization.load_der_public_key(public[name]), now=now,
                    )
                    for purpose, name in (("encryption", "encryption_spki"), ("signature", "signing_spki"))
                }
            except ValueError as error:
                raise HTTPException(status_code=503, detail=str(error)) from error
            session["certificates"] = renewed
            session["certificates_ready"] = False
        return certificate_payload(session, ca.certificate)

    @app.get("/api/certificates")
    def get_certificates(request: Request):
        session = sessions[request.state.session_id]
        if session["certificates"] is None:
            raise HTTPException(status_code=404, detail="Сертификаты ещё не выпущены")
        return certificate_payload(session, teaching_ca().certificate)

    @app.post("/api/certificates/verify")
    def verify_certificates(body: CertificateCheckRequest, request: Request):
        session = sessions[request.state.session_id]
        if session["certificates"] is None:
            raise HTTPException(status_code=409, detail="Сначала получите сертификаты")
        ca = teaching_ca()
        now = certificate_clock()
        if any(not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc for cert in session["certificates"].values()):
            raise HTTPException(status_code=410, detail="Срок сертификатов истёк. Получите новые сертификаты")
        expected = ca.certificate.fingerprint(hashes.SHA256()).hex()
        supplied = body.ca_fingerprint_sha256.strip().lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", supplied) or not hmac.compare_digest(supplied, expected):
            return {"verified": False, "already_completed": False}
        try:
            for purpose, name in (("encryption", "encryption_spki"), ("signature", "signing_spki")):
                verify_student_certificate(
                    session["certificates"][purpose], ca.certificate,
                    session["actor_id"], purpose, KEY_VERSION,
                    serialization.load_der_public_key(session["public_keys"][name]), now=now,
                )
        except (ValueError, InvalidSignature) as error:
            raise HTTPException(status_code=422, detail="Сертификаты не прошли проверку") from error
        already_completed = session["certificates_verified"]
        session["certificates_verified"] = True
        session["certificates_ready"] = True
        return {"verified": True, "already_completed": already_completed}

    def current_signing_certificate(session: dict) -> x509.Certificate:
        certs = session["certificates"]
        if not certs or not session["certificates_ready"]:
            raise HTTPException(status_code=409, detail="Сначала подтвердите сертификаты")
        cert = certs["signature"]
        ca = teaching_ca()
        try:
            verify_student_certificate(
                cert, ca.certificate, session["actor_id"], "signature", KEY_VERSION,
                serialization.load_der_public_key(session["public_keys"]["signing_spki"]),
                now=certificate_clock(),
            )
        except ValueError as error:
            raise HTTPException(status_code=410, detail="Сертификат подписи недействителен. Получите новый") from error
        except InvalidSignature as error:
            raise HTTPException(status_code=409, detail="Сертификат подписи не прошёл проверку CA") from error
        return cert

    def current_encryption_certificate(session: dict) -> x509.Certificate:
        certs = session["certificates"]
        if not certs or not session["certificates_ready"]:
            raise HTTPException(status_code=409, detail="Сначала подтвердите сертификаты")
        cert = certs["encryption"]
        try:
            verify_student_certificate(
                cert, teaching_ca().certificate, session["actor_id"], "encryption", KEY_VERSION,
                serialization.load_der_public_key(session["public_keys"]["encryption_spki"]),
                now=certificate_clock(),
            )
        except (ValueError, InvalidSignature) as error:
            raise HTTPException(status_code=410, detail="Сертификат шифрования недействителен. Получите новый") from error
        return cert

    def service_identity():
        try:
            return load_service(service_dir, ca_dir, now=certificate_clock())
        except FileNotFoundError as error:
            raise HTTPException(status_code=503, detail="Серверный участник ещё не инициализирован") from error
        except (ValueError, InvalidSignature) as error:
            raise HTTPException(status_code=503, detail="Сертификат серверного участника недействителен") from error

    @app.get("/api/service-certificate")
    def service_certificate():
        _, cert = service_identity()
        return {
            "actor_id": SERVICE_ACTOR, "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "encryption_spki": encode_base64url(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            "serial_number": format(cert.serial_number, "x"), "valid_until": cert.not_valid_after_utc.isoformat(),
            "ca_fingerprint_sha256": teaching_ca().certificate.fingerprint(hashes.SHA256()).hex(":"),
        }

    @app.post("/api/outbound-packages/challenges")
    def create_outbound_challenge(request: Request):
        session = sessions[request.state.session_id]
        if not session["signature_verified"]:
            raise HTTPException(status_code=409, detail="Сначала завершите упражнение с подписью")
        _, cert = service_identity()
        package_id = secrets.token_urlsafe(24)
        expires_at = clock() + challenge_ttl
        outbound_challenges[package_id] = {"session_id": request.state.session_id, "serial": format(cert.serial_number, "x"), "expires_at": expires_at, "used": False, "hash": None}
        return {"package_id": package_id, "sender_actor_id": session["actor_id"], "recipient_actor_id": SERVICE_ACTOR,
                "recipient_certificate_serial": format(cert.serial_number, "x"),
                "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat()}

    @app.post("/api/outbound-packages/{package_id}/verify")
    def verify_outbound(package_id: str, body: PackageRequest, request: Request):
        challenge = outbound_challenges.get(package_id)
        if not challenge or challenge["session_id"] != request.state.session_id:
            raise HTTPException(status_code=404, detail="Задание пакета не найдено")
        if clock() > challenge["expires_at"]:
            raise HTTPException(status_code=410, detail="Время задания истекло")
        session = sessions[request.state.session_id]
        key, cert = service_identity()
        packet = body.package
        if (packet.get("package_id") != package_id or packet.get("sender_actor_id") != session["actor_id"]
                or packet.get("recipient_actor_id") != SERVICE_ACTOR or packet.get("recipient_certificate_serial") != challenge["serial"]
                or packet.get("recipient_certificate_serial") != format(cert.serial_number, "x")):
            raise HTTPException(status_code=422, detail="Пакет адресован другому участнику или сертификату")
        try:
            digest = packet_hash(packet)
            plaintext = decrypt_package(packet, key)
        except (ValueError, KeyError, TypeError, UnicodeError) as error:
            raise HTTPException(status_code=422, detail="Неверный формат пакета") from error
        except Exception as error:
            raise HTTPException(status_code=422, detail="Не удалось расшифровать или аутентифицировать пакет") from error
        if not 1 <= len(plaintext) <= 500:
            raise HTTPException(status_code=422, detail="Учебный текст должен содержать 1–500 символов")
        if challenge["used"] and challenge["hash"] != digest:
            raise HTTPException(status_code=409, detail="Этот ID уже использован другим пакетом")
        already = session["outbound_verified"]
        challenge["used"] = True
        challenge["hash"] = digest
        session["outbound_verified"] = True
        session["outbound_hash"] = digest
        # Only a digest and completion marker survive this request.
        return {"verified": True, "already_completed": already, "package_hash_sha256": digest}

    @app.post("/api/inbound-packages")
    def create_inbound(request: Request):
        session = sessions[request.state.session_id]
        if not session["outbound_verified"]:
            raise HTTPException(status_code=409, detail="Сначала отправьте пакет серверу")
        cert = current_encryption_certificate(session)
        package_id = secrets.token_urlsafe(24)
        secret = secrets.token_urlsafe(20)
        packet = encrypt_package(secret, cert.public_key(), package_id=package_id,
                                 sender=SERVICE_ACTOR, recipient=session["actor_id"], serial=format(cert.serial_number, "x"))
        expires_at = clock() + challenge_ttl
        inbound_challenges[package_id] = {"session_id": request.state.session_id, "serial": format(cert.serial_number, "x"),
                                          "answer_digest": hashlib.sha256(secret.encode()).digest(), "expires_at": expires_at, "used": False}
        return {"package": packet, "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat()}

    @app.post("/api/inbound-packages/{package_id}/verify")
    def verify_inbound(package_id: str, body: AnswerRequest, request: Request):
        challenge = inbound_challenges.get(package_id)
        if not challenge or challenge["session_id"] != request.state.session_id:
            raise HTTPException(status_code=404, detail="Задание пакета не найдено")
        if clock() > challenge["expires_at"]:
            raise HTTPException(status_code=410, detail="Время задания истекло")
        session = sessions[request.state.session_id]
        cert = current_encryption_certificate(session)
        if format(cert.serial_number, "x") != challenge["serial"]:
            raise HTTPException(status_code=409, detail="Сертификат изменился. Получите новое задание")
        verified = hmac.compare_digest(hashlib.sha256(body.answer.encode()).digest(), challenge["answer_digest"])
        already = challenge["used"] or session["inbound_verified"]
        if verified:
            challenge["used"] = True
            session["inbound_verified"] = True
            session["inbound_package_id"] = package_id
        return {"verified": verified, "already_completed": already if verified else False}

    @app.post("/api/submissions")
    def submit_lab(request: Request):
        session = sessions[request.state.session_id]
        if not all(session[name] for name in STEPS):
            raise HTTPException(status_code=409, detail="Сначала завершите все шесть технических шагов")
        if not session.get("student"):
            raise HTTPException(status_code=409, detail="Укажите и сохраните фамилию и группу")
        already = bool(session.get("submitted_at"))
        if not already:
            session["submitted_at"] = datetime.now(timezone.utc).isoformat()
        return {"status": "Ожидает проверки", "submitted_at": session["submitted_at"], "already_submitted": already}

    @app.post("/api/signature-challenges")
    def create_signature_challenge(request: Request):
        session = sessions[request.state.session_id]
        cert = current_signing_certificate(session)
        challenge_id = secrets.token_urlsafe(24)
        text = f"CryptoLab · подпишите одноразовый текст {secrets.token_urlsafe(18)}"
        expires_at = clock() + challenge_ttl
        signature_challenges[challenge_id] = {
            "session_id": request.state.session_id,
            "certificate_serial_number": cert.serial_number,
            "text": text,
            "expires_at": expires_at,
            "used": False,
        }
        session["active_signature_challenge"] = challenge_id
        return {
            "challenge_id": challenge_id,
            "text": text,
            "certificate_serial_number": format(cert.serial_number, "x"),
            "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        }

    @app.post("/api/signature-challenges/{challenge_id}/verify")
    def verify_signature_challenge(challenge_id: str, body: SignatureEvidenceRequest, request: Request):
        challenge = signature_challenges.get(challenge_id)
        if not challenge or challenge["session_id"] != request.state.session_id:
            raise HTTPException(status_code=404, detail="Задание подписи не найдено")
        session = sessions[request.state.session_id]
        if session["active_signature_challenge"] != challenge_id:
            raise HTTPException(status_code=409, detail="Выдано новое задание подписи")
        if clock() > challenge["expires_at"]:
            raise HTTPException(status_code=410, detail="Время задания подписи истекло")
        cert = current_signing_certificate(session)
        if cert.serial_number != challenge["certificate_serial_number"]:
            raise HTTPException(status_code=409, detail="Сертификат подписи изменился. Получите новое задание")

        original = challenge["text"].encode("utf-8")
        own_signature = decode_base64url(body.own_signature)
        temporary_signature = decode_base64url(body.temporary_signature)
        temporary_key, temporary_spki = rsa_public_key(body.temporary_spki)
        student_spki = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

        def matches(key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
            try:
                key.verify(signature, message, pss, hashes.SHA256())
                return True
            except InvalidSignature:
                return False

        own_valid = matches(cert.public_key(), own_signature, original)
        temporary_valid = matches(temporary_key, temporary_signature, original)
        temporary_rejected = (
            temporary_valid and temporary_spki != student_spki
            and not matches(cert.public_key(), temporary_signature, original)
        )
        changed_one_character = (
            len(body.altered_text) == len(challenge["text"])
            and sum(a != b for a, b in zip(body.altered_text, challenge["text"])) == 1
        )
        changed_rejected = (
            own_valid and changed_one_character
            and not matches(cert.public_key(), own_signature, body.altered_text.encode("utf-8"))
        )
        verified = own_valid and temporary_valid and temporary_rejected and changed_rejected
        already_completed = challenge["used"] or session["signature_verified"]
        if verified:
            challenge["used"] = True
            session["signature_verified"] = True
        return {
            "verified": verified,
            "own_valid": own_valid,
            "temporary_valid": temporary_valid,
            "temporary_rejected_by_certificate": temporary_rejected,
            "changed_text_rejected": changed_rejected,
            "already_completed": already_completed if verified else False,
        }

    @app.post("/api/challenges")
    def create_challenge(request: Request):
        answer = secrets.token_urlsafe(18)
        ciphertext = training_key.public_key().encrypt(
            answer.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        challenge_id = secrets.token_urlsafe(24)
        expires_at = clock() + challenge_ttl
        challenges[challenge_id] = {
            "session_id": request.state.session_id,
            "answer_digest": hashlib.sha256(answer.encode("utf-8")).digest(),
            "expires_at": expires_at,
            "used": False,
        }
        return {
            "challenge_id": challenge_id,
            "ciphertext": encode_base64url(ciphertext),
            "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        }

    @app.post("/api/challenges/{challenge_id}/verify")
    def verify_challenge(challenge_id: str, body: AnswerRequest, request: Request):
        challenge = challenges.get(challenge_id)
        if not challenge or challenge["session_id"] != request.state.session_id:
            raise HTTPException(status_code=404, detail="Задание не найдено")
        if clock() > challenge["expires_at"]:
            raise HTTPException(status_code=410, detail="Время задания истекло")
        answer_digest = hashlib.sha256(body.answer.encode("utf-8")).digest()
        verified = hmac.compare_digest(answer_digest, challenge["answer_digest"])
        if not verified:
            return {"verified": False, "completed": sessions[request.state.session_id]["completed"], "already_completed": False}
        session = sessions[request.state.session_id]
        already_completed = challenge["used"] or session["completed"]
        challenge["used"] = True
        session["completed"] = True
        return {"verified": True, "completed": True, "already_completed": already_completed}

    @app.post("/api/key-proofs")
    def create_key_proof(body: PublicKeysRequest, request: Request):
        session = sessions[request.state.session_id]
        if not session["completed"]:
            raise HTTPException(status_code=409, detail="Сначала завершите подготовительное расшифрование")
        if session["keys_verified"]:
            raise HTTPException(status_code=409, detail="Личные ключи уже подтверждены")

        encryption_key, encryption_spki = rsa_public_key(body.encryption_spki)
        signing_key, signing_spki = rsa_public_key(body.signing_spki)
        if encryption_spki == signing_spki:
            raise HTTPException(status_code=422, detail="Для шифрования и подписи нужны разные пары ключей")

        answer = secrets.token_urlsafe(18)
        ciphertext = encryption_key.encrypt(
            answer.encode("utf-8"),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        signing_text = f"CryptoLab proof {secrets.token_urlsafe(18)}"
        challenge_id = secrets.token_urlsafe(24)
        expires_at = clock() + challenge_ttl
        key_challenges[challenge_id] = {
            "session_id": request.state.session_id,
            "answer_digest": hashlib.sha256(answer.encode("utf-8")).digest(),
            "signing_text": signing_text,
            "signing_key": signing_key,
            "encryption_spki": encryption_spki,
            "signing_spki": signing_spki,
            "expires_at": expires_at,
            "used": False,
        }
        session["active_key_challenge"] = challenge_id
        return {
            "challenge_id": challenge_id,
            "ciphertext": encode_base64url(ciphertext),
            "signing_text": signing_text,
            "encryption_fingerprint": hashlib.sha256(encryption_spki).hexdigest(),
            "signing_fingerprint": hashlib.sha256(signing_spki).hexdigest(),
            "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        }

    @app.post("/api/key-proofs/{challenge_id}/verify")
    def verify_key_proof(challenge_id: str, body: KeyProofRequest, request: Request):
        challenge = key_challenges.get(challenge_id)
        if not challenge or challenge["session_id"] != request.state.session_id:
            raise HTTPException(status_code=404, detail="Задание не найдено")
        session = sessions[request.state.session_id]
        if session["active_key_challenge"] != challenge_id:
            raise HTTPException(status_code=409, detail="Выдано новое задание для ключей")
        if clock() > challenge["expires_at"]:
            raise HTTPException(status_code=410, detail="Время задания истекло")

        answer_digest = hashlib.sha256(body.answer.encode("utf-8")).digest()
        encryption_verified = hmac.compare_digest(answer_digest, challenge["answer_digest"])
        try:
            signature = decode_base64url(body.signature)
            challenge["signing_key"].verify(
                signature, challenge["signing_text"].encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256(),
            )
            signature_verified = True
        except InvalidSignature:
            signature_verified = False

        verified = encryption_verified and signature_verified
        already_completed = challenge["used"] or session["keys_verified"]
        if verified:
            challenge["used"] = True
            session["keys_verified"] = True
            session["public_keys"] = {
                "encryption_spki": challenge["encryption_spki"],
                "signing_spki": challenge["signing_spki"],
            }
        return {
            "verified": verified,
            "encryption_verified": encryption_verified,
            "signature_verified": signature_verified,
            "already_completed": already_completed if verified else False,
        }

    return app


app = create_app(db_path=DEFAULT_DB_PATH)

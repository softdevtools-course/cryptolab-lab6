"""Full local exchange, tamper rejection, durable progress and submission."""

from pathlib import Path
import json
import shutil
import subprocess
import base64

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.ca import initialize_ca, load_ca
from app.main import create_app
from app.packages import aad, decrypt as decrypt_package, encrypt as encrypt_package, packet_hash
from app.service import initialize_service, load_service
from app.export import export
from test_api import decrypt, key_pair_payload, submit_key_proof, signature_evidence


def ready_client(tmp_path):
    ca_dir, service_dir, db_path = tmp_path / "ca", tmp_path / "service", tmp_path / "state.sqlite3"
    initialize_ca(ca_dir)
    initialize_service(service_dir, ca_dir)
    app = create_app(ca_dir=ca_dir, service_dir=service_dir, db_path=db_path)
    client = TestClient(app)
    prep = client.post("/api/challenges").json()
    assert client.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])}).json()["verified"]
    encryption_key, signing_key, payload = key_pair_payload()
    proof = client.post("/api/key-proofs", json=payload).json()
    assert submit_key_proof(client, proof, encryption_key, signing_key).json()["verified"]
    client.post("/api/certificates")
    fingerprint = load_ca(ca_dir).certificate.fingerprint(hashes.SHA256()).hex(":")
    assert client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint}).json()["verified"]
    challenge = client.post("/api/signature-challenges").json()
    proof = signature_evidence(challenge["text"], signing_key)
    assert client.post(f"/api/signature-challenges/{challenge['challenge_id']}/verify", json=proof).json()["verified"]
    return client, ca_dir, service_dir, db_path, encryption_key


def test_package_aad_and_hash_reject_tampering(tmp_path):
    ca_dir, service_dir = tmp_path / "ca", tmp_path / "service"
    initialize_ca(ca_dir)
    initialize_service(service_dir, ca_dir)
    key, cert = load_service(service_dir, ca_dir)
    packet = encrypt_package("Привет", cert.public_key(), package_id="abc", sender="student:abc",
                             recipient="service:cryptolab", serial=format(cert.serial_number, "x"), created_at="2026-10-13T00:00:00Z")
    assert decrypt_package(packet, key) == "Привет"
    assert packet_hash(packet) == packet_hash(dict(reversed(list(packet.items()))))
    assert packet_hash(packet) != packet_hash({**packet, "created_at": "2026-10-13T00:00:01Z"})
    for name, changed in (("sender_actor_id", "student:other"), ("package_id", "other"),
                          ("recipient_certificate_serial", "deadbeef"), ("iv", "AAAAAAAAAAAAAAAA")):
        altered = {**packet, name: changed}
        with pytest.raises((ValueError, InvalidTag)):
            decrypt_package(altered, key)
    assert b'"package_id":"abc"' in aad(packet)


def test_browser_package_interoperates_with_python_service(tmp_path):
    if shutil.which("node") is None:
        pytest.skip("Node.js is not installed")
    ca_dir, service_dir = tmp_path / "ca", tmp_path / "service"
    initialize_ca(ca_dir)
    initialize_service(service_dir, ca_dir)
    key, cert = load_service(service_dir, ca_dir)
    spki = base64.urlsafe_b64encode(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )).rstrip(b"=").decode()
    script = """
import { encryptPackage } from './web/packages.js';
const challenge = { package_id: 'cross', sender_actor_id: 'student:test',
  recipient_actor_id: 'service:cryptolab', recipient_certificate_serial: process.argv[2] };
process.stdout.write(JSON.stringify(await encryptPackage('Межъязыковой пакет', challenge, process.argv[1])));
"""
    result = subprocess.run(["node", "--input-type=module", "-e", script, spki, format(cert.serial_number, "x")],
                            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=True)
    packet = json.loads(result.stdout)
    assert decrypt_package(packet, key) == "Межъязыковой пакет"


def test_python_package_opens_with_browser_crypto():
    if shutil.which("node") is None:
        pytest.skip("Node.js is not installed")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    packet = encrypt_package("Ответ сервера", key.public_key(), package_id="reply",
                             sender="service:cryptolab", recipient="student:test", serial="abc")
    private_der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    script = """
import { decryptPackage } from './web/packages.js';
const privateKey = await crypto.subtle.importKey('pkcs8', Buffer.from(process.argv[1], 'base64url'),
  { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
process.stdout.write(await decryptPackage(JSON.parse(process.argv[2]), privateKey));
"""
    result = subprocess.run(["node", "--input-type=module", "-e", script,
                             base64.urlsafe_b64encode(private_der).rstrip(b"=").decode(), json.dumps(packet)],
                            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=True)
    assert result.stdout == "Ответ сервера"


def test_full_exchange_restart_and_submission(tmp_path):
    client, ca_dir, service_dir, db_path, encryption_key = ready_client(tmp_path)
    assert client.post("/api/submissions").status_code == 409
    service = client.get("/api/service-certificate").json()
    assert "PRIVATE KEY" not in str(service)
    challenge = client.post("/api/outbound-packages/challenges").json()
    key, cert = load_service(service_dir, ca_dir)
    packet = encrypt_package("Учебное сообщение", cert.public_key(), package_id=challenge["package_id"],
                             sender=challenge["sender_actor_id"], recipient=challenge["recipient_actor_id"],
                             serial=challenge["recipient_certificate_serial"])
    url = f"/api/outbound-packages/{challenge['package_id']}/verify"
    assert client.post(url, json={"package": {**packet, "recipient_actor_id": "student:other"}}).status_code == 422
    bad = dict(packet)
    bad["created_at"] = "2026-10-13T00:00:00Z"
    # created_at is outside v1 AAD; the canonical package hash still changes.
    assert packet_hash(bad) != packet_hash(packet)
    bad = {**packet, "sender_actor_id": "student:other"}
    assert client.post(url, json={"package": bad}).status_code == 422
    broken = {**packet, "ciphertext": "AAAA"}
    assert client.post(url, json={"package": broken}).status_code == 422
    assert client.post(url, json={"package": packet}).json()["verified"]
    assert client.post(url, json={"package": packet}).json()["already_completed"]
    assert client.get("/api/state").json()["steps_done"] == 5

    issued = client.post("/api/inbound-packages").json()
    inbound = issued["package"]
    answer = decrypt_package(inbound, encryption_key)
    assert inbound["recipient_actor_id"] == client.get("/api/state").json()["actor_id"]
    assert client.post(f"/api/inbound-packages/{inbound['package_id']}/verify", json={"answer": "wrong"}).json()["verified"] is False
    verify_url = f"/api/inbound-packages/{inbound['package_id']}/verify"
    assert client.post(verify_url, json={"answer": answer}).json()["verified"]
    assert client.post(verify_url, json={"answer": answer}).json()["already_completed"]
    assert client.get("/api/state").json()["steps_done"] == 6
    assert client.post("/api/submissions").status_code == 409
    assert client.post("/api/student", json={"surname": "Иванов", "given_name": "Иван", "group": "23-ИС-12с"}).status_code == 200
    assert client.post("/api/submissions").json()["already_submitted"] is False
    assert client.post("/api/submissions").json()["already_submitted"] is True
    assert client.post("/api/student", json={"surname": "Петров", "given_name": "Иван", "group": "23-ИС-12с"}).status_code == 409

    cookie = client.cookies.get("cryptolab_stage1")
    restarted = TestClient(create_app(ca_dir=ca_dir, service_dir=service_dir, db_path=db_path))
    restarted.cookies.set("cryptolab_stage1", cookie)
    state = restarted.get("/api/state").json()
    assert state["actor_id"] == challenge["sender_actor_id"]
    assert state["steps_done"] == 6
    assert state["submitted_at"]
    assert state["student"] == {"surname": "Иванов", "given_name": "Иван", "group": "23-ИС-12с"}
    assert restarted.post("/api/submissions").json()["already_submitted"] is True
    assert Path(db_path).exists()
    output_dir = tmp_path / "export"
    export(db_path, output_dir)
    assert "6" in (output_dir / "progress.csv").read_text()
    assert "Ожидает проверки" in (output_dir / "submissions.csv").read_text()
    assert "Иванов;Иван;23-ИС-12с" in (output_dir / "submissions.csv").read_text()
    assert "outbound_verified" in (output_dir / "events.csv").read_text()

import base64
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from app.main import create_app
from app.ca import initialize_ca, load_ca, verify_student_certificate


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def decrypt(ciphertext_b64: str) -> str:
    key = serialization.load_pem_private_key((EXAMPLES / "training-key.pem").read_bytes(), password=None)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + "=" * (-len(ciphertext_b64) % 4))
    plaintext = key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return plaintext.decode("utf-8")


def key_pair_payload():
    encryption_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def spki(key):
        raw = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return encryption_key, signing_key, {
        "encryption_spki": spki(encryption_key), "signing_spki": spki(signing_key)
    }


def submit_key_proof(client, challenge, encryption_key, signing_key):
    ciphertext = base64.urlsafe_b64decode(challenge["ciphertext"] + "=" * (-len(challenge["ciphertext"]) % 4))
    answer = encryption_key.decrypt(
        ciphertext, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode("utf-8")
    signature = signing_key.sign(
        challenge["signing_text"].encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256(),
    )
    return client.post(
        f"/api/key-proofs/{challenge['challenge_id']}/verify",
        json={"answer": answer, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")},
    )


def test_public_example_can_be_fetched_and_decrypted():
    client = TestClient(create_app())
    key = client.get("/examples/training-key.pem")
    ciphertext = client.get("/examples/ciphertext.txt")
    assert key.status_code == 200
    assert key.text.startswith("-----BEGIN PRIVATE KEY-----")
    assert ciphertext.status_code == 200
    assert decrypt(ciphertext.text.strip()).startswith("Ключ подходит:")
    assert client.get("/examples/../app/main.py").status_code == 404


def test_workbench_page_and_browser_module_are_served():
    client = TestClient(create_app())
    page = client.get("/")
    assert page.status_code == 200
    assert "Учебный ключ" in page.text
    assert "Сравните три проверки" in page.text
    assert client.get("/app.js").status_code == 200
    assert client.get("/crypto.js").status_code == 200
    assert client.get("/signature.js").status_code == 200


def test_correct_answer_completes_one_step_and_replay_is_idempotent():
    client = TestClient(create_app())
    state = client.get("/api/state").json()
    assert state["completed"] is False
    assert state["keys_verified"] is False
    assert state["steps_done"] == 0
    assert state["steps_total"] == 6
    assert state["actor_id"].startswith("student:")
    issued = client.post("/api/challenges").json()
    assert issued["challenge_id"]
    answer = decrypt(issued["ciphertext"])
    result = client.post(f"/api/challenges/{issued['challenge_id']}/verify", json={"answer": answer})
    assert result.json() == {"verified": True, "completed": True, "already_completed": False}
    replay = client.post(f"/api/challenges/{issued['challenge_id']}/verify", json={"answer": answer})
    assert replay.json() == {"verified": True, "completed": True, "already_completed": True}
    final_state = client.get("/api/state").json()
    assert final_state["completed"] is True
    assert final_state["steps_done"] == 1
    assert final_state["steps_total"] == 6


def test_wrong_answer_and_another_session_do_not_complete_challenge():
    app = create_app()
    owner = TestClient(app)
    stranger = TestClient(app)
    owner.get("/api/state")
    stranger.get("/api/state")
    issued = owner.post("/api/challenges").json()
    challenge_url = f"/api/challenges/{issued['challenge_id']}/verify"
    assert owner.post(challenge_url, json={"answer": "неверно"}).json()["verified"] is False
    assert stranger.post(challenge_url, json={"answer": decrypt(issued["ciphertext"])}).status_code == 404
    assert owner.get("/api/state").json()["completed"] is False
    assert stranger.get("/api/state").json()["completed"] is False


def test_expired_challenge_is_rejected():
    current = [1000.0]
    client = TestClient(create_app(clock=lambda: current[0], challenge_ttl=10))
    client.get("/api/state")
    issued = client.post("/api/challenges").json()
    current[0] = 1011.0
    response = client.post(
        f"/api/challenges/{issued['challenge_id']}/verify",
        json={"answer": decrypt(issued["ciphertext"])},
    )
    assert response.status_code == 410
    assert client.get("/api/state").json()["completed"] is False


def test_key_proof_requires_preparatory_step_and_both_private_keys():
    client = TestClient(create_app())
    encryption_key, signing_key, payload = key_pair_payload()
    assert client.post("/api/key-proofs", json=payload).status_code == 409
    prep = client.post("/api/challenges").json()
    client.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])})

    challenge = client.post("/api/key-proofs", json=payload)
    assert challenge.status_code == 200
    issued = challenge.json()
    assert issued["challenge_id"] and issued["ciphertext"] and issued["signing_text"]
    wrong_signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    invalid = submit_key_proof(client, issued, encryption_key, wrong_signing_key)
    assert invalid.json()["verified"] is False
    assert invalid.json()["encryption_verified"] is True
    assert invalid.json()["signature_verified"] is False
    assert client.get("/api/state").json()["steps_done"] == 1

    good = submit_key_proof(client, issued, encryption_key, signing_key)
    assert good.json()["verified"] is True
    assert good.json()["already_completed"] is False
    assert submit_key_proof(client, issued, encryption_key, signing_key).json()["already_completed"] is True
    state = client.get("/api/state").json()
    assert state["keys_verified"] is True
    assert state["steps_done"] == 2
    assert client.post("/api/key-proofs", json=payload).status_code == 409


def test_key_proof_rejects_other_session_and_expiry():
    current = [1000.0]
    app = create_app(clock=lambda: current[0], challenge_ttl=10)
    owner, stranger = TestClient(app), TestClient(app)
    prep = owner.post("/api/challenges").json()
    owner.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])})
    encryption_key, signing_key, payload = key_pair_payload()
    issued = owner.post("/api/key-proofs", json=payload).json()
    assert submit_key_proof(stranger, issued, encryption_key, signing_key).status_code == 404
    current[0] = 1011.0
    assert submit_key_proof(owner, issued, encryption_key, signing_key).status_code == 410
    assert owner.get("/api/state").json()["steps_done"] == 1


def test_key_proof_rejects_malformed_and_reused_public_keys():
    client = TestClient(create_app())
    prep = client.post("/api/challenges").json()
    client.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])})
    _, _, payload = key_pair_payload()
    assert client.post("/api/key-proofs", json={**payload, "signing_spki": payload["encryption_spki"]}).status_code == 422
    assert client.post("/api/key-proofs", json={**payload, "signing_spki": "bad!"}).status_code == 422
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_spki = weak_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert client.post("/api/key-proofs", json={
        **payload, "signing_spki": base64.urlsafe_b64encode(weak_spki).rstrip(b"=").decode("ascii")
    }).status_code == 422

    original = base64.urlsafe_b64decode(payload["encryption_spki"] + "=" * (-len(payload["encryption_spki"]) % 4))
    with_null = bytes.fromhex("300d06092a864886f70d0101010500")
    without_null = bytes.fromhex("300b06092a864886f70d010101")
    assert original.startswith(b"\x30\x82") and with_null in original
    alternate = original.replace(with_null, without_null, 1)
    alternate = alternate[:2] + (len(alternate) - 4).to_bytes(2, "big") + alternate[4:]
    alternate_b64 = base64.urlsafe_b64encode(alternate).rstrip(b"=").decode("ascii")
    assert client.post("/api/key-proofs", json={**payload, "signing_spki": alternate_b64}).status_code == 422


def test_new_key_proof_supersedes_the_previous_challenge():
    client = TestClient(create_app())
    prep = client.post("/api/challenges").json()
    client.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])})
    first_encryption, first_signing, first_keys = key_pair_payload()
    first = client.post("/api/key-proofs", json=first_keys).json()
    second_encryption, second_signing, second_keys = key_pair_payload()
    second = client.post("/api/key-proofs", json=second_keys).json()
    assert submit_key_proof(client, first, first_encryption, first_signing).status_code == 409
    assert submit_key_proof(client, second, second_encryption, second_signing).json()["verified"] is True


def test_local_actor_cookie_survives_browser_close_while_server_runs():
    client = TestClient(create_app())
    response = client.get("/api/state")
    assert "Max-Age=2592000" in response.headers["set-cookie"]
    assert "httponly" in response.headers["set-cookie"].lower()
    actor_id = response.json()["actor_id"]
    assert client.get("/api/state").json()["actor_id"] == actor_id


def test_https_proxy_marks_session_cookie_secure(monkeypatch):
    monkeypatch.setenv("CRYPTOLAB_COOKIE_SECURE", "1")
    response = TestClient(create_app()).get("/api/state")
    assert "secure" in response.headers["set-cookie"].lower()


def verified_key_client(ca_dir):
    client = TestClient(create_app(ca_dir=ca_dir))
    prep = client.post("/api/challenges").json()
    client.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])})
    encryption_key, signing_key, payload = key_pair_payload()
    proof = client.post("/api/key-proofs", json=payload).json()
    assert submit_key_proof(client, proof, encryption_key, signing_key).json()["verified"]
    return client, encryption_key, signing_key


def test_ca_initialization_is_explicit_persistent_and_private(tmp_path):
    ca_dir = tmp_path / "ca"
    assert not ca_dir.exists()
    with pytest.raises(FileNotFoundError):
        load_ca(ca_dir)
    fingerprint = initialize_ca(ca_dir)
    assert ca_dir.stat().st_mode & 0o777 == 0o700
    assert (ca_dir / "ca-key.pem").stat().st_mode & 0o777 == 0o600
    assert load_ca(ca_dir).certificate.fingerprint(hashes.SHA256()).hex(":") == fingerprint
    with pytest.raises(FileExistsError):
        initialize_ca(ca_dir)
    assert load_ca(ca_dir).certificate.fingerprint(hashes.SHA256()).hex(":") == fingerprint


def test_certificates_require_proven_keys_and_separate_fingerprint_check(tmp_path):
    ca_dir = tmp_path / "ca"
    fingerprint = initialize_ca(ca_dir)
    client = TestClient(create_app(ca_dir=ca_dir))
    root = client.get("/api/ca").json()
    assert root["fingerprint_sha256"] == fingerprint
    assert "BEGIN CERTIFICATE" in root["certificate_pem"]
    assert "PRIVATE KEY" not in str(root)
    assert client.post("/api/certificates").status_code == 409
    assert client.get("/api/certificates").status_code == 404

    client, encryption_key, signing_key = verified_key_client(ca_dir)
    state = client.get("/api/state").json()
    actor_id = state["actor_id"]
    assert state["steps_done"] == 2
    issued = client.post("/api/certificates")
    assert issued.status_code == 200
    body = issued.json()
    assert body == client.get("/api/certificates").json()
    assert body == client.post("/api/certificates").json()
    assert body["actor_id"] == actor_id
    assert body["key_version"] == 1
    assert body["ca_fingerprint_sha256"] == fingerprint
    assert body["encryption"]["purpose"] == "encryption"
    assert body["signature"]["purpose"] == "signature"
    assert body["encryption"]["serial_number"] != body["signature"]["serial_number"]
    assert client.get("/api/state").json()["steps_done"] == 2

    root_cert = x509.load_pem_x509_certificate(root["certificate_pem"].encode())
    for purpose, key in (("encryption", encryption_key), ("signature", signing_key)):
        cert = x509.load_pem_x509_certificate(body[purpose]["certificate_pem"].encode())
        assert cert.public_key() == key.public_key()
        assert cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value == actor_id
        verify_student_certificate(cert, root_cert, actor_id, purpose, 1, key.public_key())

    wrong = client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": "00:" * 31 + "00"})
    assert wrong.status_code == 200 and wrong.json()["verified"] is False
    assert client.get("/api/state").json()["steps_done"] == 2
    good = client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint})
    assert good.json()["verified"] is True
    assert good.json()["already_completed"] is False
    assert client.get("/api/state").json()["steps_done"] == 3
    assert client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint}).json()["already_completed"] is True


def test_certificate_validation_rejects_wrong_actor_purpose_and_root(tmp_path):
    first_dir, second_dir = tmp_path / "first", tmp_path / "second"
    initialize_ca(first_dir)
    initialize_ca(second_dir)
    client, encryption_key, signing_key = verified_key_client(first_dir)
    actor = client.get("/api/state").json()["actor_id"]
    body = client.post("/api/certificates").json()
    root = load_ca(first_dir).certificate
    other_root = load_ca(second_dir).certificate
    cert = x509.load_pem_x509_certificate(body["signature"]["certificate_pem"].encode())
    verify_student_certificate(cert, root, actor, "signature", 1, signing_key.public_key())
    with pytest.raises(ValueError):
        verify_student_certificate(cert, root, actor + "x", "signature", 1, signing_key.public_key())
    with pytest.raises(ValueError):
        verify_student_certificate(cert, root, actor, "encryption", 1, encryption_key.public_key())
    with pytest.raises((ValueError, InvalidSignature)):
        verify_student_certificate(cert, other_root, actor, "signature", 1, signing_key.public_key())


def test_uninitialized_ca_cannot_issue_certificates(tmp_path):
    client, _, _ = verified_key_client(tmp_path / "missing")
    assert client.get("/api/ca").status_code == 503
    assert client.post("/api/certificates").status_code == 503
    assert client.get("/api/state").json()["steps_done"] == 2


def test_expired_certificates_can_be_reissued_and_reverified(tmp_path):
    ca_dir = tmp_path / "ca"
    fingerprint = initialize_ca(ca_dir)
    now = [datetime.now(timezone.utc)]
    client = TestClient(create_app(ca_dir=ca_dir, certificate_clock=lambda: now[0]))
    prep = client.post("/api/challenges").json()
    client.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])})
    encryption_key, signing_key, payload = key_pair_payload()
    proof = client.post("/api/key-proofs", json=payload).json()
    assert submit_key_proof(client, proof, encryption_key, signing_key).json()["verified"]

    first = client.post("/api/certificates").json()
    assert client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint}).json()["verified"]
    assert client.get("/api/state").json()["steps_done"] == 3
    now[0] += timedelta(days=8)
    state = client.get("/api/state").json()
    assert state["certificates_current"] is False
    assert state["certificates_ready"] is False
    assert state["steps_done"] == 3  # A confirmed historical step is not erased.
    expired = client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint})
    assert expired.status_code == 410

    second = client.post("/api/certificates").json()
    assert second["encryption"]["serial_number"] != first["encryption"]["serial_number"]
    assert second["signature"]["serial_number"] != first["signature"]["serial_number"]
    assert client.get("/api/state").json()["certificates_current"] is True
    assert client.get("/api/state").json()["certificates_ready"] is False
    assert client.get("/api/state").json()["steps_done"] == 3
    assert client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint}).json()["verified"]
    assert client.get("/api/state").json()["certificates_ready"] is True
    assert client.get("/api/state").json()["steps_done"] == 3


def sign_text(key, text):
    raw = key.sign(
        text.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256(),
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verified_certificate_client(ca_dir, *, app=None):
    client = TestClient(app or create_app(ca_dir=ca_dir))
    prep = client.post("/api/challenges").json()
    client.post(f"/api/challenges/{prep['challenge_id']}/verify", json={"answer": decrypt(prep["ciphertext"])})
    encryption_key, signing_key, payload = key_pair_payload()
    proof = client.post("/api/key-proofs", json=payload).json()
    assert submit_key_proof(client, proof, encryption_key, signing_key).json()["verified"]
    client.post("/api/certificates")
    fingerprint = load_ca(ca_dir).certificate.fingerprint(hashes.SHA256()).hex(":")
    assert client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint}).json()["verified"]
    return client, signing_key


def signature_evidence(text, signing_key, *, own_key=None, temporary_key=None, altered_text=None):
    temporary_key = temporary_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    temp_spki = temporary_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "own_signature": sign_text(own_key or signing_key, text),
        "temporary_spki": base64.urlsafe_b64encode(temp_spki).rstrip(b"=").decode("ascii"),
        "temporary_signature": sign_text(temporary_key, text),
        "altered_text": altered_text or text[:-1] + ("X" if text[-1] != "X" else "Y"),
    }


def test_signature_exercise_requires_current_verified_certificate_and_three_proofs(tmp_path):
    ca_dir = tmp_path / "ca"
    initialize_ca(ca_dir)
    unready = TestClient(create_app(ca_dir=ca_dir))
    assert unready.post("/api/signature-challenges").status_code == 409

    client, signing_key = verified_certificate_client(ca_dir)
    issued = client.post("/api/signature-challenges")
    assert issued.status_code == 200
    challenge = issued.json()
    assert challenge["text"] and challenge["challenge_id"] and challenge["expires_at"]
    assert challenge["certificate_serial_number"]
    assert client.get("/api/state").json()["steps_done"] == 3
    url = f"/api/signature-challenges/{challenge['challenge_id']}/verify"
    wrong_own = signature_evidence(challenge["text"], signing_key,
                                   own_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    failed = client.post(url, json=wrong_own).json()
    assert failed["verified"] is False
    assert failed["own_valid"] is False
    assert client.get("/api/state").json()["steps_done"] == 3

    good = signature_evidence(challenge["text"], signing_key)
    result = client.post(url, json=good).json()
    assert result == {
        "verified": True, "own_valid": True,
        "temporary_valid": True, "temporary_rejected_by_certificate": True,
        "changed_text_rejected": True, "already_completed": False,
    }
    assert client.get("/api/state").json()["signature_verified"] is True
    assert client.get("/api/state").json()["steps_done"] == 4
    assert client.post(url, json=good).json()["already_completed"] is True


def test_signature_exercise_rejects_false_negative_evidence_and_other_session(tmp_path):
    ca_dir = tmp_path / "ca"
    initialize_ca(ca_dir)
    client, signing_key = verified_certificate_client(ca_dir)
    stranger = TestClient(client.app)
    stranger.get("/api/state")
    challenge = client.post("/api/signature-challenges").json()
    url = f"/api/signature-challenges/{challenge['challenge_id']}/verify"
    good = signature_evidence(challenge["text"], signing_key)
    assert stranger.post(url, json=good).status_code == 404
    same_key = key_pair_payload()[1]
    bad_temp = signature_evidence(challenge["text"], signing_key)
    bad_temp["temporary_signature"] = sign_text(same_key, challenge["text"])
    assert client.post(url, json=bad_temp).json()["temporary_valid"] is False
    own_spki = signing_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    same_as_certificate = {
        **good,
        "temporary_spki": base64.urlsafe_b64encode(own_spki).rstrip(b"=").decode("ascii"),
        "temporary_signature": good["own_signature"],
    }
    same_result = client.post(url, json=same_as_certificate).json()
    assert same_result["temporary_valid"] is True
    assert same_result["temporary_rejected_by_certificate"] is False
    unchanged = {**good, "altered_text": challenge["text"]}
    assert client.post(url, json=unchanged).json()["changed_text_rejected"] is False
    end = challenge["text"][-2:]
    changed_end = "".join("X" if letter != "X" else "Y" for letter in end)
    two_changes = {**good, "altered_text": challenge["text"][:-2] + changed_end}
    assert client.post(url, json=two_changes).json()["changed_text_rejected"] is False
    assert client.get("/api/state").json()["steps_done"] == 3


def test_signature_challenge_expires_and_new_one_supersedes_old(tmp_path):
    ca_dir = tmp_path / "ca"
    initialize_ca(ca_dir)
    now = [1000.0]
    app = create_app(ca_dir=ca_dir, clock=lambda: now[0], challenge_ttl=10)
    client, signing_key = verified_certificate_client(ca_dir, app=app)
    first = client.post("/api/signature-challenges").json()
    second = client.post("/api/signature-challenges").json()
    assert client.post(
        f"/api/signature-challenges/{first['challenge_id']}/verify",
        json=signature_evidence(first["text"], signing_key),
    ).status_code == 409
    now[0] = 1011.0
    assert client.post(
        f"/api/signature-challenges/{second['challenge_id']}/verify",
        json=signature_evidence(second["text"], signing_key),
    ).status_code == 410
    assert client.get("/api/state").json()["steps_done"] == 3


def test_signature_exercise_requires_reverified_certificate_after_renewal(tmp_path):
    ca_dir = tmp_path / "ca"
    fingerprint = initialize_ca(ca_dir)
    now = [datetime.now(timezone.utc)]
    app = create_app(ca_dir=ca_dir, certificate_clock=lambda: now[0])
    client, _ = verified_certificate_client(ca_dir, app=app)
    assert client.post("/api/signature-challenges").status_code == 200

    now[0] += timedelta(days=8)
    assert client.post("/api/signature-challenges").status_code == 410
    assert client.post("/api/certificates").status_code == 200
    assert client.post("/api/signature-challenges").status_code == 409
    assert client.post("/api/certificates/verify", json={"ca_fingerprint_sha256": fingerprint}).json()["verified"]
    assert client.post("/api/signature-challenges").status_code == 200

"""Small durable local progress journal; never stores plaintext or private keys."""

import base64
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

DEFAULT_DB_PATH = Path(os.environ.get(
    "CRYPTOLAB_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".local-data")
)) / "state.sqlite3"
FLAGS = ("completed", "keys_verified", "certificates_verified", "certificates_ready", "signature_verified", "outbound_verified", "inbound_verified")
STEPS = ("completed", "keys_verified", "certificates_verified", "signature_verified", "outbound_verified", "inbound_verified")


class StateStore:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, data TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS lab_events (session_id TEXT NOT NULL, criterion TEXT NOT NULL, verified_at TEXT NOT NULL, evidence_id TEXT, PRIMARY KEY(session_id,criterion))")
        self.db.execute("CREATE TABLE IF NOT EXISTS lab_submissions (session_id TEXT PRIMARY KEY, submitted_at TEXT NOT NULL)")
        self.db.commit()

    def load(self) -> dict:
        result = {}
        for session_id, raw in self.db.execute("SELECT session_id, data FROM sessions"):
            value = json.loads(raw)
            value["public_keys"] = {k: base64.b64decode(v) for k, v in value["public_keys"].items()} if value.get("public_keys") else None
            value["certificates"] = {k: x509.load_pem_x509_certificate(v.encode("ascii")) for k, v in value["certificates"].items()} if value.get("certificates") else None
            value["active_key_challenge"] = None
            value["active_signature_challenge"] = None
            for name in FLAGS:
                value.setdefault(name, False)
            result[session_id] = value
        return result

    def save(self, session_id: str, session: dict) -> None:
        value = {k: v for k, v in session.items() if k not in ("active_key_challenge", "active_signature_challenge")}
        value["public_keys"] = {k: base64.b64encode(v).decode("ascii") for k, v in session["public_keys"].items()} if session["public_keys"] else None
        value["certificates"] = {k: v.public_bytes(serialization.Encoding.PEM).decode("ascii") for k, v in session["certificates"].items()} if session["certificates"] else None
        now = datetime.now(timezone.utc).isoformat()
        with self.lock, self.db:
            self.db.execute("INSERT INTO sessions VALUES (?,?) ON CONFLICT(session_id) DO UPDATE SET data=excluded.data", (session_id, json.dumps(value)))
            for criterion in STEPS:
                if session[criterion]:
                    evidence_id = session.get("outbound_hash") if criterion == "outbound_verified" else session.get("inbound_package_id") if criterion == "inbound_verified" else None
                    self.db.execute("INSERT OR IGNORE INTO lab_events VALUES (?,?,?,?)", (session_id, criterion, now, evidence_id))
            if session.get("submitted_at"):
                self.db.execute("INSERT OR IGNORE INTO lab_submissions VALUES (?,?)", (session_id, session["submitted_at"]))

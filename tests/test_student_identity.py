"""Student-declared surname and group stay with the technical session."""

import json
import sqlite3

from fastapi.testclient import TestClient

from app.main import create_app


def test_student_details_are_validated_and_survive_restart(tmp_path):
    db_path = tmp_path / "state.sqlite3"
    client = TestClient(create_app(db_path=db_path))
    before = client.get("/api/state").json()
    assert before["student"] is None
    for payload in (
        {"surname": "", "group": "23-ИС-12с"},
        {"surname": "Иванов", "group": ""},
        {"surname": "=HYPERLINK(\"bad\")", "group": "23-ИС-12с"},
        {"surname": "Иванов", "group": "=1+1"},
        {"surname": "Иванов\nДругой", "group": "23-ИС-12с"},
    ):
        assert client.post("/api/student", json=payload).status_code == 422
    assert client.get("/api/state").json()["student"] is None

    saved = client.post("/api/student", json={"surname": "  Иванов-Петров  ", "group": " 23-ИС-12с "})
    assert saved.status_code == 200
    assert saved.json() == {"surname": "Иванов-Петров", "group": "23-ИС-12с"}
    assert client.get("/api/state").json()["student"] == saved.json()
    assert client.get("/api/state").json()["actor_id"] == before["actor_id"]

    restarted = TestClient(create_app(db_path=db_path))
    restarted.cookies.set("cryptolab_stage1", client.cookies.get("cryptolab_stage1"))
    assert restarted.get("/api/state").json()["student"] == saved.json()
    corrected = restarted.post("/api/student", json={"surname": "Сидоров", "group": "23-ИС-12с"})
    assert corrected.status_code == 200
    assert corrected.json()["surname"] == "Сидоров"


def test_older_submission_can_add_missing_details_once(tmp_path):
    db_path = tmp_path / "state.sqlite3"
    client = TestClient(create_app(db_path=db_path))
    client.get("/api/state")
    cookie = client.cookies.get("cryptolab_stage1")
    with sqlite3.connect(db_path) as db:
        state = json.loads(db.execute("SELECT data FROM sessions WHERE session_id=?", (cookie,)).fetchone()[0])
        state.pop("student")
        state["submitted_at"] = "2026-10-14T00:00:00+00:00"
        db.execute("UPDATE sessions SET data=? WHERE session_id=?", (json.dumps(state), cookie))
    resumed = TestClient(create_app(db_path=db_path))
    resumed.cookies.set("cryptolab_stage1", cookie)
    assert resumed.get("/api/state").json()["student"] is None
    assert resumed.post("/api/student", json={"surname": "Иванов", "group": "23-ИС-12с"}).status_code == 200
    assert resumed.post("/api/student", json={"surname": "Петров", "group": "23-ИС-12с"}).status_code == 409

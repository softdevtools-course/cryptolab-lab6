"""Public proxy safeguards keep student sessions usable without exe.dev login."""

from fastapi.testclient import TestClient

from app.main import create_app


ORIGIN = "https://lab-06.course.denrad.dev"


def test_public_mode_rejects_cross_site_writes_and_limits_request_size(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOLAB_PUBLIC_ORIGIN", ORIGIN)
    app = create_app(db_path=tmp_path / "state.sqlite3")
    client = TestClient(app)
    page = client.get("/")
    assert page.status_code == 200
    assert "set-cookie" not in page.headers
    state = client.get("/api/state")
    assert state.status_code == 200
    assert "httponly" in state.headers["set-cookie"].lower()
    payload = {"surname": "Иванов", "given_name": "Иван", "group": "23-ИС-12с"}
    assert client.post("/api/student", json=payload).status_code == 403
    assert client.post("/api/student", json=payload, headers={"Origin": "https://other.example"}).status_code == 403
    saved = client.post("/api/student", json=payload, headers={"Origin": ORIGIN})
    assert saved.status_code == 200
    assert saved.json() == payload
    assert client.post("/api/student", content="x" * 70000, headers={"Origin": ORIGIN}).status_code == 413


def test_public_mode_throttles_new_sessions(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOLAB_PUBLIC_ORIGIN", ORIGIN)
    monkeypatch.setenv("CRYPTOLAB_NEW_SESSIONS_PER_MIN", "2")
    app = create_app(db_path=tmp_path / "state.sqlite3")
    for expected in (200, 200, 429):
        assert TestClient(app).get("/api/state").status_code == expected

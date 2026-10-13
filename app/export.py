"""Local teacher-only CSV export from the SQLite result journal."""

import argparse
import csv
import json
import sqlite3
from pathlib import Path

from app.state import DEFAULT_DB_PATH, STEPS


def export(db_path: Path, output_dir: Path) -> None:
    if not db_path.is_file():
        raise FileNotFoundError(f"База не найдена: {db_path}")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    sessions = [(session_id, json.loads(raw)) for session_id, raw in db.execute("SELECT session_id, data FROM sessions ORDER BY session_id")]
    with (output_dir / "progress.csv").open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(("actor_id", *STEPS, "steps_done", "submitted_at"))
        for _, value in sessions:
            writer.writerow((value["actor_id"], *(int(bool(value.get(step))) for step in STEPS),
                             sum(bool(value.get(step)) for step in STEPS), value.get("submitted_at") or ""))
    actors = {session_id: value["actor_id"] for session_id, value in sessions}
    with (output_dir / "events.csv").open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(("actor_id", "criterion", "verified_at", "evidence_id"))
        for session_id, criterion, verified_at, evidence_id in db.execute(
            "SELECT session_id, criterion, verified_at, evidence_id FROM lab_events ORDER BY verified_at, session_id, criterion"
        ):
            writer.writerow((actors[session_id], criterion, verified_at, evidence_id or ""))
    with (output_dir / "submissions.csv").open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(("actor_id", "submitted_at", "status"))
        for session_id, submitted_at in db.execute("SELECT session_id, submitted_at FROM lab_submissions ORDER BY submitted_at"):
            writer.writerow((actors[session_id], submitted_at, "Ожидает проверки"))
    db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CryptoLab local CSV export")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    export(args.db, args.output_dir)
    print(f"CSV сохранены в {args.output_dir}")


if __name__ == "__main__":
    main()

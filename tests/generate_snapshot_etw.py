"""Create a tiny collector DB and preceding process snapshot for case smoke."""

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)


def ticks(iso):
    delta = datetime.fromisoformat(iso.replace("Z", "+00:00")) - epoch
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


(out / "snapshot.json").write_text(json.dumps({
    "captured_iso8601_utc": "2026-01-03T00:00:00Z",
    "processes": [{"pid": 123, "image": "existing.exe",
                   "create_time_100ns": ticks("2026-01-02T23:00:00Z")}],
}), encoding="utf-8")

with sqlite3.connect(out / "collector.db") as db:
    db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp_100ns INTEGER, "
               "pid INTEGER, kind INTEGER, event_id INTEGER, name TEXT, attrs TEXT, provider INTEGER)")
    db.execute("INSERT INTO events VALUES (1,?,?,?,?,?,?,?)",
               (ticks("2026-01-03T00:00:01Z"), 123, 7, 16,
                "C:\\Lab\\output.txt", "{}", 2))

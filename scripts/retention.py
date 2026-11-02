"""
AI-DAMS retention: remove records older than N days from the audit log and the
captured query text. Dry run by default; pass --apply to delete.
Usage: python scripts/retention.py [DAYS] [--apply]
"""
import datetime as dt
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGETS = [
    (ROOT / "dashboard-server" / "audit.log", "ts"),
    (ROOT / "ml-engine" / "data" / "captured_query_text.jsonl", "captured_at"),
]
args = [a for a in sys.argv[1:] if not a.startswith("--")]
DAYS = int(args[0]) if args else 90
APPLY = "--apply" in sys.argv
if APPLY and DAYS < 1:
    sys.exit("Refusing to delete with a retention window under 1 day.")
cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=DAYS)

summary = []
for path, key in TARGETS:
    if not path.exists():
        print(f"{path.name}: not found, skipped")
        continue
    keep, dropped = [], 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            ts = dt.datetime.fromisoformat(json.loads(line)[key].replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=dt.timezone.utc)
        except Exception:
            keep.append(line)  # keep anything that cannot be read
            continue
        if ts < cutoff:
            dropped += 1
        else:
            keep.append(line)
    mode = "removed" if APPLY else "would remove (dry run)"
    print(f"{path.name}: {mode} {dropped} records older than {DAYS} days; {len(keep)} kept")
    summary.append(f"{path.name}:{dropped}")
    if APPLY and dropped:
        path.write_text("\n".join(keep) + ("\n" if keep else ""))

import hashlib


def _last_hash(path):
    try:
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        return json.loads(lines[-1]).get("hash", "GENESIS") if lines else "GENESIS"
    except Exception:
        return "GENESIS"


if APPLY:
    audit_path = ROOT / "dashboard-server" / "audit.log"
    entry = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "user": "system",
             "action": "retention", "outcome": f"{DAYS}d: " + ", ".join(summary), "ip": None}
    entry["prev"] = _last_hash(audit_path)
    entry["hash"] = hashlib.sha256("|".join([entry["prev"], entry["ts"], entry["user"], entry["action"], entry["outcome"], ""]).encode()).hexdigest()
    with open(audit_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

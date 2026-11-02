"""
AI-DAMS data-subject requests: export or erase everything AI-DAMS holds about one student.

Usage:
  python scripts/subject_request.py export 2300010
  python scripts/subject_request.py erase  2300010            (dry run: counts only)
  python scripts/subject_request.py erase  2300010 --apply    (deletes; irreversible, no backup is kept)

Stores covered: live_alerts.jsonl, captured_query_text.jsonl, and alerts.json and risk_scores.csv in both
ml-engine/data and dashboard-server/data (the copies the dashboard serves).
Not covered, on purpose: audit.log (records staff actions, and its integrity matters),
ground_truth.csv (synthetic training data), and the MySQL application tables (the university
system, not AI-DAMS).

Each export or erasure appends a receipt to dashboard-server/subject_requests.log, a hash chain in
the same format as audit.log (verify with: python scripts/verify_audit.py dashboard-server/subject_requests.log).
The receipt holds a request number and counts, and no student identifier, so it does not
keep what was erased. Stop the live scorers before --apply: they append to live_alerts.jsonl
and a record written during the rewrite could be lost. The dashboard server may keep alerts in
memory until it is restarted.
"""
import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "ml-engine" / "data"
DASH = ROOT / "dashboard-server" / "data"   # copies the dashboard serves
LOG = ROOT / "dashboard-server" / "subject_requests.log"
EXPORTS = ROOT / "subject_exports"


def account_for(cid):
    return "student_00" + cid[-2:]


def atomic_write(path, text):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def scan_jsonl(path, match):
    """Return (kept_lines, matched_records); unreadable lines are kept."""
    keep, hit = [], []
    if not path.exists():
        return keep, hit
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            keep.append(line)
            continue
        (hit if match(rec) else keep).append(rec if match(rec) else line)
    return keep, hit


def alerts_store(path, acct):
    allr = json.loads(path.read_text()) if path.exists() else []
    return {"path": path, "kind": "json", "keep": [x for x in allr if x.get("account") != acct],
            "hit": [x for x in allr if x.get("account") == acct]}


def risk_store(path, cid):
    rows, fields = [], None
    if path.exists():
        with open(path, newline="") as fh:
            rd = csv.DictReader(fh)
            fields = rd.fieldnames
            rows = list(rd)
    return {"path": path, "kind": "csv", "fields": fields,
            "keep": [r for r in rows if r.get("customer_id") != cid],
            "hit": [r for r in rows if r.get("customer_id") == cid]}


def collect(cid):
    acct = account_for(cid)
    out = {}
    keep, hit = scan_jsonl(DATA / "live_alerts.jsonl", lambda r: str(r.get("customer_id")) == cid or r.get("account") == acct)
    out["live_alerts"] = {"path": DATA / "live_alerts.jsonl", "kind": "jsonl", "keep": keep, "hit": hit}
    keep, hit = scan_jsonl(DATA / "captured_query_text.jsonl", lambda r: r.get("account") == acct)
    out["captured_statements"] = {"path": DATA / "captured_query_text.jsonl", "kind": "jsonl", "keep": keep, "hit": hit}
    out["batch_alerts"] = alerts_store(DATA / "alerts.json", acct)
    out["risk_scores"] = risk_store(DATA / "risk_scores.csv", cid)
    out["dashboard_alerts"] = alerts_store(DASH / "alerts.json", acct)
    out["dashboard_risk_scores"] = risk_store(DASH / "risk_scores.csv", cid)
    return out


def write_back(store):
    p, k = store["path"], store["kind"]
    if not p.exists():
        return
    if k == "jsonl":
        lines = [l if isinstance(l, str) else json.dumps(l) for l in store["keep"]]
        atomic_write(p, "\n".join(lines) + ("\n" if lines else ""))
    elif k == "json":
        atomic_write(p, json.dumps(store["keep"], indent=2))
    else:
        import io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=store["fields"], lineterminator="\n")
        w.writeheader()
        w.writerows(store["keep"])
        atomic_write(p, buf.getvalue())


def receipt(action, outcome):
    lines = [l for l in LOG.read_text().splitlines() if l.strip()] if LOG.exists() else []
    prev = json.loads(lines[-1])["hash"] if lines else "0" * 64
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    user = os.environ.get("USER", "unknown")
    h = hashlib.sha256("|".join([prev, ts, user, action, outcome, ""]).encode()).hexdigest()
    entry = {"ts": ts, "user": user, "action": action, "outcome": outcome, "ip": None, "prev": prev, "hash": h}
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def scorers_running():
    try:
        r = subprocess.run(["pgrep", "-f", "live_.*scorer.py"], capture_output=True, text=True)
        return bool(r.stdout.strip())
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["export", "erase"])
    ap.add_argument("customer_id", help="student number, for example 2300010")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--force", action="store_true", help="erase even if a live scorer is running")
    a = ap.parse_args()
    cid = a.customer_id
    if not (len(cid) == 7 and cid.isdigit() and cid.startswith("23000")):
        sys.exit("customer_id must look like 2300010")
    stores = collect(cid)
    counts = {k: len(v["hit"]) for k, v in stores.items()}
    req = uuid.uuid4().hex[:8]
    summary = " ".join(f"{k}={n}" for k, n in counts.items())
    if a.action == "export":
        EXPORTS.mkdir(exist_ok=True)
        out = EXPORTS / f"{cid}-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}.json"
        bundle = {"subject_account": account_for(cid), "exported_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "stores": {k: {"file": str(v["path"].relative_to(ROOT)), "records": v["hit"]} for k, v in stores.items()}}
        out.write_text(json.dumps(bundle, indent=2))
        os.chmod(out, 0o600)
        receipt("subject_export", f"req={req} {summary}")
        print(f"exported {sum(counts.values())} records to {out} (request {req})")
        return
    print(("would remove " if not a.apply else "removing ") + summary)
    if not a.apply:
        print("dry run: nothing changed; add --apply to delete")
        return
    if scorers_running() and not a.force:
        sys.exit("a live scorer is running; stop it first (or use --force)")
    for v in stores.values():
        if v["hit"]:
            write_back(v)
    receipt("subject_erase", f"req={req} {summary}")
    print(f"erased {sum(counts.values())} records (request {req}); receipt written to {LOG.name}")


if __name__ == "__main__":
    main()

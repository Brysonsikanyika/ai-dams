"""
AI-DAMS technical control checks. Prints PASS / FAIL / SKIP per control and exits 1 on any FAIL.

What this is: automated tests that each technical control behaves as the report says it does.
What it is not: a legal assessment. It does not show compliance with the Data Protection Act
2021 or the GDPR; it shows that the controls the compliance mapping relies on work.

File-based checks run on temporary copies, never on live data. Checks that need the dashboard
server use AIDAMS_API (default http://localhost:4000); the role check also needs
AIDAMS_ADMIN_USER / AIDAMS_ADMIN_PASS / AIDAMS_ANALYST_USER / AIDAMS_ANALYST_PASS and is skipped
without them. The lockout check uses a made-up username, so no real account is locked.
"""
import datetime as dt
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
API = os.environ.get("AIDAMS_API", "http://localhost:4000")
PY = sys.executable
RESULTS = []


def rec(control, status, detail):
    RESULTS.append((control, status, detail))
    print(f"{status:5s} {control}: {detail}", flush=True)


def chain_line(prev, ts, user, action, outcome, ip=None):
    h = hashlib.sha256("|".join([prev, ts, user or "", action, str(outcome), ip or ""]).encode()).hexdigest()
    return {"ts": ts, "user": user, "action": action, "outcome": outcome, "ip": ip, "prev": prev, "hash": h}


def make_chain(n, start):
    lines, prev = [], "0" * 64
    for i in range(n):
        ts = (start + dt.timedelta(hours=i)).isoformat()
        e = chain_line(prev, ts, "analyst", "view_alerts", "ok", "127.0.0.1")
        lines.append(e)
        prev = e["hash"]
    return lines


def run(script, *args):
    p = subprocess.run([PY, str(script), *args], capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def write_lines(path, items):
    path.write_text("\n".join(json.dumps(x) if not isinstance(x, str) else x for x in items) + "\n")


def check_audit_chain(tmp):
    verify = ROOT / "scripts" / "verify_audit.py"
    now = dt.datetime.now(dt.timezone.utc)
    lines = make_chain(8, now - dt.timedelta(days=1))
    good = tmp / "audit_good.log"
    write_lines(good, lines)
    rc, out = run(verify, str(good))
    ok_good = rc == 0
    edited = [dict(x) for x in lines]
    edited[3]["outcome"] = "denied"
    p2 = tmp / "audit_edited.log"
    write_lines(p2, edited)
    rc2, out2 = run(verify, str(p2))
    p3 = tmp / "audit_removed.log"
    write_lines(p3, lines[:3] + lines[4:])
    rc3, out3 = run(verify, str(p3))
    if ok_good and rc2 != 0 and rc3 != 0:
        rec("Audit log integrity", "PASS", "intact chain verifies; an edited line and a removed line are both reported")
    else:
        rec("Audit log integrity", "FAIL", f"intact rc={rc}, edited rc={rc2}, removed rc={rc3}: {out[:80]} | {out2[:80]} | {out3[:80]}")


def check_retention(tmp):
    root = tmp / "ret"
    for d in ("scripts", "dashboard-server", "ml-engine/data"):
        (root / d).mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / "retention.py", root / "scripts" / "retention.py")
    shutil.copy(ROOT / "scripts" / "verify_audit.py", root / "scripts" / "verify_audit.py")
    now = dt.datetime.now(dt.timezone.utc)
    audit = make_chain(6, now - dt.timedelta(days=200)) + []
    prev = audit[-1]["hash"]
    for i in range(4):
        e = chain_line(prev, (now - dt.timedelta(days=3 - i)).isoformat(), "admin", "view_audit", "ok", "127.0.0.1")
        audit.append(e)
        prev = e["hash"]
    cap = [{"captured_at": (now - dt.timedelta(days=d)).isoformat(), "sql_text": f"SELECT {d}"} for d in (300, 200, 100, 5, 2)]
    a_path = root / "dashboard-server" / "audit.log"
    c_path = root / "ml-engine" / "data" / "captured_query_text.jsonl"
    write_lines(a_path, audit)
    write_lines(c_path, cap)
    before = (a_path.read_bytes(), c_path.read_bytes())
    rc, out = run(root / "scripts" / "retention.py", "90")
    unchanged = (a_path.read_bytes(), c_path.read_bytes()) == before
    rc2, out2 = run(root / "scripts" / "retention.py", "90", "--apply")
    cutoff = now - dt.timedelta(days=90)

    def old_left(path, key):
        n = 0
        for l in path.read_text().splitlines():
            if l.strip() and dt.datetime.fromisoformat(json.loads(l)[key]) < cutoff:
                n += 1
        return n

    cap_left = [json.loads(l) for l in c_path.read_text().splitlines() if l.strip()]
    rcv, outv = run(root / "scripts" / "verify_audit.py", str(a_path))
    problems = []
    if not unchanged: problems.append("dry run changed files")
    if old_left(a_path, "ts") or old_left(c_path, "captured_at"): problems.append("old records remain after --apply")
    if len(cap_left) != 2: problems.append(f"expected 2 recent captured records, found {len(cap_left)}")
    if rcv != 0: problems.append("audit chain broken after purge: " + outv[:80])
    if problems:
        rec("Retention", "FAIL", "; ".join(problems))
    else:
        rec("Retention", "PASS", "dry run changes nothing; --apply removes records older than the window, keeps recent ones, and the audit chain still verifies")


def http(method, path, body=None, token=None):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}
    except Exception as e:
        return None, {"error": str(e)}


def check_lockout():
    user = "lockout_probe_" + str(random.randint(10**6, 10**7))
    codes = [http("POST", "/api/login", {"username": user, "password": "wrong-" + str(i)})[0] for i in range(7)]
    if codes[0] is None:
        rec("Login lockout", "SKIP", "dashboard server not reachable at " + API)
    elif codes[:5] == [401] * 5 and codes[5] == 429 and codes[6] == 429:
        rec("Login lockout", "PASS", f"five failures return 401, then 429 (responses: {codes})")
    else:
        rec("Login lockout", "FAIL", f"expected five 401s then 429, got {codes}")


def login(user, pw):
    code, j = http("POST", "/api/login", {"username": user, "password": pw})
    return j.get("token") or j.get("accessToken") if code == 200 else None


def check_roles():
    e = os.environ
    need = ["AIDAMS_ADMIN_USER", "AIDAMS_ADMIN_PASS", "AIDAMS_ANALYST_USER", "AIDAMS_ANALYST_PASS"]
    if not all(e.get(k) for k in need):
        rec("Role separation", "SKIP", "set " + ", ".join(need) + " to run")
        return
    anon, _ = http("GET", "/api/alerts")
    if anon is None:
        rec("Role separation", "SKIP", "dashboard server not reachable")
        return
    t_an, t_ad = login(e[need[2]], e[need[3]]), login(e[need[0]], e[need[1]])
    if not t_an or not t_ad:
        rec("Role separation", "SKIP", "could not log in with the supplied credentials; check them (this says nothing about the control)")
        return
    an_alerts, body = http("GET", "/api/alerts", token=t_an)
    leaked = sorted({k for a in (body if isinstance(body, list) else [])[:200] for k in a if k in ("account", "truth")})
    if an_alerts == 200:
        if leaked:
            rec("Analyst alert view", "FAIL", "GET /api/alerts returns fields an analyst should not receive: " + ", ".join(leaked))
        else:
            rec("Analyst alert view", "PASS", "GET /api/alerts as an analyst returns no account name and no ground-truth label")
    live_an_code, live_an = http("GET", "/api/live-alerts", token=t_an)
    live_ad_code, live_ad = http("GET", "/api/live-alerts", token=t_ad)
    if live_an_code != 200:
        rec("Analyst live-alert view", "FAIL", f"GET /api/live-alerts as an analyst returned {live_an_code}")
    elif not (isinstance(live_an, list) and live_an):
        rec("Analyst live-alert view", "SKIP", "no live alerts to inspect; run the live demo first")
    else:
        leaked_live = sorted({k for a in live_an[:200] for k in a if k in ("account", "customer_id", "truth")})
        admin_sees = live_ad_code == 200 and isinstance(live_ad, list) and any("account" in a for a in live_ad)
        if leaked_live:
            rec("Analyst live-alert view", "FAIL", "GET /api/live-alerts returns fields an analyst should not receive: " + ", ".join(leaked_live))
        elif not admin_sees:
            rec("Analyst live-alert view", "FAIL", "analyst view is clean, but the admin no longer sees the account either")
        else:
            rec("Analyst live-alert view", "PASS", "GET /api/live-alerts as an analyst returns no account name and no customer id; the admin still sees the account")
    an_audit, _ = http("GET", "/api/audit", token=t_an)
    ad_audit, _ = http("GET", "/api/audit", token=t_ad)
    if anon == 401 and an_alerts == 200 and an_audit == 403 and ad_audit == 200:
        rec("Role separation", "PASS", "no token: 401; analyst reads alerts (200) but not the audit log (403); admin reads the audit log (200)")
    else:
        rec("Role separation", "FAIL", f"no token {anon}, analyst alerts {an_alerts}, analyst audit {an_audit}, admin audit {ad_audit}")


def check_masking():
    ID = re.compile(r"\b23\d{5}\b")
    problems, scanned = [], 0
    live = ROOT / "ml-engine" / "data" / "live_alerts.jsonl"
    if live.exists():
        for l in live.read_text().splitlines():
            if l.strip():
                scanned += 1
                if ID.search(json.loads(l).get("sql_text", "")):
                    problems.append("live alert text holds a student number")
                    break
    for al in (ROOT / "ml-engine" / "data" / "alerts.json", ROOT / "dashboard-server" / "data" / "alerts.json"):
        if not al.exists():
            continue
        for a in json.loads(al.read_text()):
            scanned += 1
            if ID.search(str(a.get("explanation", "")) + str(a.get("headline", ""))) or ID.fullmatch(str(a.get("pseudonym", ""))):
                problems.append("batch alert text or pseudonym holds a student number in " + al.parent.parent.name)
                break
    audit = ROOT / "dashboard-server" / "audit.log"
    allowed = {"ts", "user", "action", "outcome", "ip", "prev", "hash"}
    if audit.exists():
        for l in audit.read_text().splitlines():
            if l.strip() and not set(json.loads(l)) <= allowed:
                problems.append("audit entry has fields beyond the allowed set")
                break
    if not scanned:
        rec("Masking in stored alerts", "SKIP", "no alert files found")
    elif problems:
        rec("Masking in stored alerts", "FAIL", "; ".join(problems))
    else:
        rec("Masking in stored alerts", "PASS", f"{scanned} alert records: no student numbers in alert text, pseudonyms are not numbers, audit entries hold only the allowed fields")
    rec("Risk console endpoint", "INFO", "/api/risk-scores serves student numbers and ground-truth labels to any logged-in user; the console is an evaluation view over synthetic data, not an analyst view")
    cap = ROOT / "ml-engine" / "data" / "captured_query_text.jsonl"
    if cap.exists():
        rec("Captured statements", "INFO", "captured_query_text.jsonl stores raw statements, student numbers unmasked; it is protected by access to the server and by the retention script only")


def check_subject(tmp):
    root = tmp / "subj"
    for d in ("scripts", "dashboard-server", "ml-engine/data"):
        (root / d).mkdir(parents=True)
    src = ROOT / "scripts" / "subject_request.py"
    if not src.exists():
        rec("Subject access and erasure", "SKIP", "scripts/subject_request.py not found")
        return
    for f in ("subject_request.py", "verify_audit.py"):
        shutil.copy(ROOT / "scripts" / f, root / "scripts" / f)
    d = root / "ml-engine" / "data"
    write_lines(d / "live_alerts.jsonl", [{"customer_id": 2300010, "account": "student_0010", "sql_text": "x"},
                                          {"customer_id": 2300011, "account": "student_0011", "sql_text": "y"},
                                          {"customer_id": 2300010, "account": "student_0010", "sql_text": "z"}])
    write_lines(d / "captured_query_text.jsonl", [{"account": "student_0010", "sql_text": "a"}, {"account": "student_0011", "sql_text": "b"}, {"account": "root", "sql_text": "c"}])
    (d / "alerts.json").write_text(json.dumps([{"alert_id": "A1", "account": "student_0010"}, {"alert_id": "A2", "account": "student_0011"}]))
    (d / "risk_scores.csv").write_text("customer_id,time_bucket,combined_risk\n2300010,2026-10-07 07:30:00,0.9\n2300011,2026-10-07 07:30:00,0.1\n2300010,2026-10-07 07:45:00,0.2\n")
    dd = root / "dashboard-server" / "data"
    dd.mkdir(parents=True, exist_ok=True)
    (dd / "alerts.json").write_text(json.dumps([{"alert_id": "A1", "account": "student_0010"}, {"alert_id": "A2", "account": "student_0011"}]))
    (dd / "risk_scores.csv").write_text("customer_id,time_bucket,combined_risk\n2300010,2026-10-07 07:30:00,0.9\n2300011,2026-10-07 07:30:00,0.1\n")
    sr = root / "scripts" / "subject_request.py"
    problems = []
    rc, out = run(sr, "export", "2300010")
    exp = list((root / "subject_exports").glob("2300010-*.json"))
    if rc != 0 or len(exp) != 1:
        problems.append("export failed: " + out[:80])
    else:
        b = json.loads(exp[0].read_text())["stores"]
        got = {k: len(v["records"]) for k, v in b.items()}
        if got != {"live_alerts": 2, "captured_statements": 1, "batch_alerts": 1, "risk_scores": 2, "dashboard_alerts": 1, "dashboard_risk_scores": 1}:
            problems.append(f"export counts wrong: {got}")
    snap = {p.name: p.read_bytes() for p in d.iterdir()}
    run(sr, "erase", "2300010")
    if {p.name: p.read_bytes() for p in d.iterdir()} != snap:
        problems.append("dry run changed data")
    rc, out = run(sr, "erase", "2300010", "--apply", "--force")
    if rc != 0:
        problems.append("erase failed: " + out[:80])
    left = (d / "live_alerts.jsonl").read_text() + (d / "captured_query_text.jsonl").read_text() + (d / "alerts.json").read_text() + (d / "risk_scores.csv").read_text() + (dd / "alerts.json").read_text() + (dd / "risk_scores.csv").read_text()
    if "student_0010" in left or "2300010" in left:
        problems.append("records of the subject remain after erase")
    if not all(t in left for t in ("student_0011", "2300011", "root")):
        problems.append("other people's records were damaged")
    rcv, outv = run(root / "scripts" / "verify_audit.py", str(root / "dashboard-server" / "subject_requests.log"))
    if rcv != 0:
        problems.append("receipt chain does not verify: " + outv[:80])
    if "2300010" in (root / "dashboard-server" / "subject_requests.log").read_text():
        problems.append("receipt log holds the student number")
    if problems:
        rec("Subject access and erasure", "FAIL", "; ".join(problems))
    else:
        rec("Subject access and erasure", "PASS", "export returns the subject's records; dry run changes nothing; erase removes only that student's records from six stores; the receipt chain verifies and holds no student number")


def main():
    print(f"AI-DAMS control checks, {dt.datetime.now().isoformat(timespec='seconds')}\n")
    with tempfile.TemporaryDirectory() as t:
        tmp = pathlib.Path(t)
        check_audit_chain(tmp)
        check_retention(tmp)
        check_subject(tmp)
    check_lockout()
    check_roles()
    check_masking()
    bad = [r for r in RESULTS if r[1] == "FAIL"]
    c = {k: sum(1 for r in RESULTS if r[1] == k) for k in ("PASS", "FAIL", "SKIP", "INFO")}
    print(f"\n{c['PASS']} passed, {c['FAIL']} failed, {c['SKIP']} skipped, {c['INFO']} info")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

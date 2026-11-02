"""
Paced live traffic for the behavioural live test.

The batch generator replays 21 simulated days in minutes, which would make
normal traffic look like a burst in real time. This script keeps the normal
rate close to the training data (about one statement per student every 20
minutes at the default gap) and inserts a few known bursts. Every burst is
written to live_traffic_truth.jsonl, so score_live_test.py can count hits and
false alarms against what was actually sent.

Bursts follow the generator's own anomaly shapes (many reads of other students'
grades; a scan across tables), so detection here is by construction. The
informative number is the false-alarm count on the quiet traffic.
"""
import argparse
import datetime as dt
import json
import os
import random
import time

import pymysql

from academic_workload import BENIGN_KINDS

HOST = os.environ.get("MYSQL_HOST", "localhost")
PORT = int(os.environ.get("MYSQL_PORT", "3306"))
DB = os.environ.get("MYSQL_DATABASE", "aidams_demo")
PW = os.environ["STUDENT_ACCOUNT_PASSWORD"]
SIDS = [f"23000{i:02d}" for i in range(1, 21)]
CONNS = {}


def conn(sid):
    if sid not in CONNS:
        CONNS[sid] = pymysql.connect(host=HOST, port=PORT, user="student_00" + sid[-2:], password=PW,
                                     database=DB, autocommit=True)
    return CONNS[sid]


def run(sid, sql, params=None):
    c = conn(sid)  # a bad password or host must stop the run, not be swallowed
    try:
        with c.cursor() as cur:
            cur.execute(sql, params)
    except pymysql.MySQLError:
        pass


def now():
    return dt.datetime.now(dt.timezone.utc)


def quiet_event():
    sid = random.choice(SIDS)
    table, op, sql, pf = BENIGN_KINDS[random.choice(list(BENIGN_KINDS))]
    run(sid, sql, pf(sid))


def burst(kind, n, rate, truth):
    sid = random.choice(SIDS)
    start = now()
    sent = 0
    if kind == "hf":
        for _ in range(n):
            run(sid, "SELECT * FROM grades WHERE student_id = %s", (random.choice(SIDS),))
            sent += 1
            time.sleep(1.0 / rate)
    else:
        for tab in ("students", "fees", "library_loans", "grades"):
            for _ in range(max(1, n // 4)):
                run(sid, f"SELECT * FROM {tab} WHERE student_id = %s", (random.choice(SIDS),))
                sent += 1
                time.sleep(1.0 / rate)
    rec = {"kind": kind, "account": "student_00" + sid[-2:], "start": start.isoformat(), "end": now().isoformat(), "statements": sent}
    truth.write(json.dumps(rec) + "\n")
    truth.flush()
    print("BURST", rec, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--mean-gap", type=float, default=60, help="mean seconds between quiet statements, all students together")
    ap.add_argument("--bursts", type=int, default=3)
    ap.add_argument("--burst-n", type=int, default=40)
    ap.add_argument("--burst-rate", type=float, default=4)
    ap.add_argument("--truth", default="live_traffic_truth.jsonl")
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    random.seed(a.seed)
    total = a.minutes * 60
    t0 = time.time()
    burst_at = sorted(random.uniform(0.2, 0.85) * total for _ in range(a.bursts))
    kinds = ["hf", "scan"] * a.bursts
    quiet = 0
    next_q = t0 + random.expovariate(1 / a.mean_gap)
    with open(a.truth, "a") as truth:
        truth.write(json.dumps({"run_start": now().isoformat(), "minutes": a.minutes, "mean_gap": a.mean_gap}) + "\n")
        while time.time() - t0 < total:
            el = time.time() - t0
            if burst_at and el >= burst_at[0]:
                burst_at.pop(0)
                burst(kinds.pop(0), a.burst_n, a.burst_rate, truth)
                next_q = max(next_q, time.time() + 5)
                continue
            if time.time() >= next_q:
                quiet_event()
                quiet += 1
                next_q = time.time() + random.expovariate(1 / a.mean_gap)
            time.sleep(0.2)
        truth.write(json.dumps({"run_end": now().isoformat(), "quiet_statements": quiet}) + "\n")
    print(f"Done. quiet statements sent: {quiet}")


if __name__ == "__main__":
    main()

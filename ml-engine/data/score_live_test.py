"""Counts live behavioural alerts against the bursts live_traffic_demo.py actually sent."""
import datetime as dt
import json
import sys

truth_path = sys.argv[1] if len(sys.argv) > 1 else "live_traffic_truth.jsonl"
alerts_path = sys.argv[2] if len(sys.argv) > 2 else "live_alerts.jsonl"
P = dt.datetime.fromisoformat

runs = [json.loads(l) for l in open(truth_path)]
starts = [r for r in runs if "run_start" in r]
if not starts:
    sys.exit("no run in truth file")
last = max(i for i, r in enumerate(runs) if "run_start" in r)
runs = runs[last:]
t_start = P(runs[0]["run_start"])
ends = [r for r in runs if "run_end" in r]
t_end = P(ends[-1]["run_end"]) if ends else dt.datetime.now(dt.timezone.utc)
quiet = ends[-1]["quiet_statements"] if ends else None
bursts = [r for r in runs if "kind" in r]
alerts = [json.loads(l) for l in open(alerts_path)]
alerts = [a for a in alerts if a.get("source") == "live_behaviour" and t_start <= P(a["scored_at"]) <= t_end + dt.timedelta(seconds=30)]

hit = set()
fp = []
for a in alerts:
    ta = P(a["scored_at"])
    m = [i for i, b in enumerate(bursts) if b["account"] == a["account"]
         and P(b["start"]) - dt.timedelta(seconds=2) <= ta <= P(b["end"]) + dt.timedelta(seconds=30)]
    if m:
        hit.add(m[0])
    else:
        fp.append(a)
print(f"run: {t_start:%H:%M:%S} to {t_end:%H:%M:%S} UTC   quiet statements: {quiet}   bursts sent: {len(bursts)}")
print(f"alerts: {len(alerts)}   bursts detected: {len(hit)}/{len(bursts)}   false alerts: {len(fp)}")
for i, b in enumerate(bursts):
    a = [x for x in alerts if x["account"] == b["account"] and P(b["start"]) - dt.timedelta(seconds=2) <= P(x["scored_at"]) <= P(b["end"]) + dt.timedelta(seconds=30)]
    lag = (P(a[0]["scored_at"]) - P(b["start"])).total_seconds() if a else None
    print(f"  burst {i+1} {b['kind']:4s} {b['account']} {b['statements']} statements  ->  {'DETECTED after %.1f s' % lag if a else 'MISSED'}")
for a in fp:
    print("  FALSE ALERT", a["account"], a["scored_at"], a["sql_text"][:110])

"""Checks parse_sql() against ground_truth.csv, joined on the evt tag in captured_query_text.jsonl."""
import json
import re
import pandas as pd
from live_behaviour import parse_sql

TAG = re.compile(r"/\*\s*evt:([0-9a-f]{8}-\d+)\s*\*/")
gt = pd.read_csv("ground_truth.csv").set_index("event_id")
n = ok_op = ok_tab = ok_tgt = 0
bad = []
for line in open("captured_query_text.jsonl"):
    r = json.loads(line)
    m = TAG.search(r.get("sql_text") or "")
    if not m or m.group(1) not in gt.index:
        continue
    g = gt.loc[m.group(1)]
    if isinstance(g, pd.DataFrame):
        g = g.iloc[0]
    op, tab, tgt = parse_sql(r["sql_text"], r.get("account"))
    n += 1
    a, b, c = op == g["operation"], tab == g["table"], tgt == int(g["target_customer_id"])
    ok_op += a; ok_tab += b; ok_tgt += c
    if not (a and b and c) and len(bad) < 8:
        bad.append((m.group(1), (op, tab, tgt), (g["operation"], g["table"], int(g["target_customer_id"])), r["sql_text"][:90]))
print(f"matched {n} captured statements to ground truth")
if n:
    print(f"operation {ok_op/n:.4f}   table {ok_tab/n:.4f}   target {ok_tgt/n:.4f}")
for b in bad:
    print("MISMATCH", b)

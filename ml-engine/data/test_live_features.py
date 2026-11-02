"""Proves the live feature code equals the batch feature code on ground_truth.csv."""
import sys
import numpy as np
import pandas as pd
from behaviour_features import engineer, feature_columns
from live_behaviour import LiveFeatures

raw = pd.read_csv(sys.argv[1] if len(sys.argv) > 1 else "ground_truth.csv", parse_dates=["simulated_timestamp"])
df = engineer(raw.copy(), tables=False)
cols = feature_columns(df, tables=False)
lf = LiveFeatures()
rows = []
for r in df.itertuples(index=False):
    op = [o for o in ("DELETE", "INSERT", "SELECT", "UPDATE") if getattr(r, "op_" + o)][0]
    rows.append(lf.update(r.customer_id, r.simulated_timestamp.to_pydatetime(), op, r.table, r.target_customer_id))
live = pd.DataFrame(rows)[cols]
bad = {c: int((~np.isclose(live[c].astype(float), df[c].astype(float))).sum()) for c in cols}
print("rows:", len(df), " columns:", len(cols))
print("mismatches per column:", bad)
print("RESULT:", "IDENTICAL" if sum(bad.values()) == 0 else "DIFFERENT")

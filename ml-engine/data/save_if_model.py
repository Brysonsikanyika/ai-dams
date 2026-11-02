"""
Fit the deployed Isolation Forest once and save it with its feature order and
alert cutoff, so the live scorer does not refit at start-up.

Same settings as train_isolation_forest.py (200 trees, contamination 0.11, seed 42).
The cutoff is the 0.995 quantile of per-account 15-minute bucket-max scores on
the fitting data, the same rule as rolling_baseline.py (about one flagged
bucket per day). It is fixed here, not tuned on labels.
"""
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from behaviour_features import engineer, feature_columns

PCT = 0.995
raw = pd.read_csv("ground_truth.csv", parse_dates=["simulated_timestamp"])
df = engineer(raw.copy(), tables=False).reset_index(drop=True)
cols = feature_columns(df, tables=False)
X = df[cols].fillna(0)
model = IsolationForest(n_estimators=200, contamination=0.11, random_state=42).fit(X)
df["s"] = -model.decision_function(X)
df["bkey"] = df["customer_id"].astype(str) + "|" + df["simulated_timestamp"].dt.floor("15min").astype(str)
bmax = df.groupby("bkey")["s"].max()
cutoff = float(bmax.quantile(PCT))
joblib.dump({"model": model, "cols": cols, "cutoff": cutoff, "pct": PCT, "n_buckets": int(len(bmax))}, "if_live_model.joblib")
print(f"saved if_live_model.joblib  cols={len(cols)}  buckets={len(bmax)}  cutoff(p{PCT})={cutoff:.4f}")
print(f"buckets above cutoff on the fitting data: {(bmax > cutoff).sum()}")

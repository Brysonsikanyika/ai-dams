"""
AI-DAMS walk-forward baseline (objective 1: dynamic behavioural baseline).

For each simulated day after the first TRAIN_DAYS, fit an Isolation Forest on the
previous TRAIN_DAYS days of events, set the alert cutoff from that window's own
scores (no labels used), then score the next day. A frozen baseline fitted once on
the first TRAIN_DAYS days is scored on the same days for comparison.
Labels (is_anomaly) are used only to evaluate, never to fit or set cutoffs.
Isolation Forest only: the LSTM takes 30-60 s per fit and is not rolled here.
"""
import pandas as pd
from sklearn.ensemble import IsolationForest
from behaviour_features import feature_columns
from train_isolation_forest import engineer_features

INPUT_PATH = "ground_truth.csv"
TRAIN_DAYS = 7
BUCKET = "15min"
PCT = 0.95   # cutoff = 95th percentile of bucket-max scores in the training window


def fit(X):
    return IsolationForest(n_estimators=200, contamination=0.11, random_state=42).fit(X)


def bucket_table(model, X, df_part):
    s = -model.decision_function(X)
    g = pd.DataFrame({"bkey": df_part["bkey"].values, "s": s, "truth": ((df_part["is_anomaly"] == 1) & (df_part["anomaly_type"] != "sql_injection")).astype(int).values})
    return g.groupby("bkey").agg(s=("s", "max"), truth=("truth", "max"))


def cutoff_from(model, X, df_part):
    return float(bucket_table(model, X, df_part)["s"].quantile(PCT))


def evaluate(model, cutoff, X, df_part):
    b = bucket_table(model, X, df_part)
    flag = b["s"] > cutoff
    tp = int((flag & (b["truth"] == 1)).sum())
    fp = int((flag & (b["truth"] == 0)).sum())
    fn = int((~flag & (b["truth"] == 1)).sum())
    return len(b), int(b["truth"].sum()), tp, fp, fn


def pr(tp, fp, fn):
    return (tp / (tp + fp) if tp + fp else 0.0), (tp / (tp + fn) if tp + fn else 0.0)


def main():
    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    df = engineer_features(raw.copy()).reset_index(drop=True)
    cols = feature_columns(df, tables=False)
    X = df[cols].fillna(0)
    df["day"] = df["simulated_timestamp"].dt.floor("D")
    df["bkey"] = df["customer_id"].astype(str) + "|" + df["simulated_timestamp"].dt.floor(BUCKET).astype(str)
    days = sorted(df["day"].unique())
    print(f"{len(df)} events over {len(days)} days; training window = {TRAIN_DAYS} days")

    first = df["day"].isin(days[:TRAIN_DAYS])
    static_model = fit(X[first])
    static_cut = cutoff_from(static_model, X[first], df[first])

    rows = []
    tot = {"roll": [0, 0, 0], "static": [0, 0, 0]}
    for i in range(TRAIN_DAYS, len(days)):
        tr = df["day"].isin(days[i - TRAIN_DAYS:i])
        te = df["day"] == days[i]
        if te.sum() == 0:
            continue
        m = fit(X[tr])
        cut = cutoff_from(m, X[tr], df[tr])
        n, a, tp, fp, fn = evaluate(m, cut, X[te], df[te])
        _, _, stp, sfp, sfn = evaluate(static_model, static_cut, X[te], df[te])
        for k, v in (("roll", (tp, fp, fn)), ("static", (stp, sfp, sfn))):
            for j in range(3):
                tot[k][j] += v[j]
        rows.append({"day": str(days[i])[:10], "cutoff_rolling": round(cut, 4), "cutoff_static": round(static_cut, 4),
                     "buckets": n, "anomalous": a, "tp": tp, "fp": fp, "fn": fn})
        print(f"{str(days[i])[:10]}  cutoff {cut:.4f} (frozen {static_cut:.4f})  buckets {n:4d}  anomalous {a:3d}  TP {tp:3d} FP {fp:3d} FN {fn:3d}")

    pd.DataFrame(rows).to_csv("rolling_baseline_log.csv", index=False)
    for k, label in (("roll", "Rolling (refit daily on last 7 days)"), ("static", "Frozen (fit once on first 7 days)")):
        p, r = pr(*tot[k])
        print(f"{label}: TP {tot[k][0]} FP {tot[k][1]} FN {tot[k][2]}  precision {p:.3f}  recall {r:.3f}")
    print("Wrote rolling_baseline_log.csv")


if __name__ == "__main__":
    main()

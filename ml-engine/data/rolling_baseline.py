"""
AI-DAMS walk-forward baseline (objective 1: dynamic behavioural baseline).

For each simulated day after the first TRAIN_DAYS, fit an Isolation Forest on the
previous TRAIN_DAYS days of events, set the alert cutoff from that window's own
scores (no labels used), then score the next day. A frozen baseline fitted once on
the first TRAIN_DAYS days is scored on the same days for comparison.
The cutoff is a percentile of bucket-max scores in the training window. Several
percentiles are reported from the same fits; the headline percentile was fixed
before the run (0.995, about one flagged bucket per day) and is not chosen from
the results. Labels (is_anomaly) are used only to evaluate.
Isolation Forest only: the LSTM takes 30-60 s per fit and is not rolled here.
"""
import argparse
import pandas as pd
from sklearn.ensemble import IsolationForest
from behaviour_features import feature_columns
from train_isolation_forest import engineer_features

INPUT_PATH = "ground_truth.csv"
TRAIN_DAYS = 7
BUCKET = "15min"


def fit(X):
    return IsolationForest(n_estimators=200, contamination=0.11, random_state=42).fit(X)


def bucket_table(model, X, df_part):
    s = -model.decision_function(X)
    g = pd.DataFrame({"bkey": df_part["bkey"].values, "s": s,
                      "truth": ((df_part["is_anomaly"] == 1) & (df_part["anomaly_type"] != "sql_injection")).astype(int).values})
    return g.groupby("bkey").agg(s=("s", "max"), truth=("truth", "max"))


def evaluate(b, cutoff):
    flag = b["s"] > cutoff
    tp = int((flag & (b["truth"] == 1)).sum())
    fp = int((flag & (b["truth"] == 0)).sum())
    fn = int((~flag & (b["truth"] == 1)).sum())
    return tp, fp, fn


def pr(tp, fp, fn):
    return (tp / (tp + fp) if tp + fp else 0.0), (tp / (tp + fn) if tp + fn else 0.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcts", default="0.95,0.99,0.995,0.999")
    ap.add_argument("--headline", type=float, default=0.995)
    a = ap.parse_args()
    pcts = [float(x) for x in a.pcts.split(",")]
    if a.headline not in pcts:
        pcts.append(a.headline)

    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    df = engineer_features(raw.copy()).reset_index(drop=True)
    cols = feature_columns(df, tables=False)
    X = df[cols].fillna(0)
    df["day"] = df["simulated_timestamp"].dt.floor("D")
    df["bkey"] = df["customer_id"].astype(str) + "|" + df["simulated_timestamp"].dt.floor(BUCKET).astype(str)
    days = sorted(df["day"].unique())
    print(f"{len(df)} events over {len(days)} days; training window = {TRAIN_DAYS} days; headline percentile {a.headline}")

    first = df["day"].isin(days[:TRAIN_DAYS])
    static_model = fit(X[first])
    static_tb = bucket_table(static_model, X[first], df[first])

    tot = {(k, p): [0, 0, 0] for k in ("roll", "static") for p in pcts}
    ndays = 0
    rows = []
    for i in range(TRAIN_DAYS, len(days)):
        tr = df["day"].isin(days[i - TRAIN_DAYS:i])
        te = df["day"] == days[i]
        if te.sum() == 0:
            continue
        ndays += 1
        m = fit(X[tr])
        tb = bucket_table(m, X[tr], df[tr])
        test_roll = bucket_table(m, X[te], df[te])
        test_static = bucket_table(static_model, X[te], df[te])
        for p in pcts:
            for kind, test, cut in (("roll", test_roll, float(tb["s"].quantile(p))),
                                    ("static", test_static, float(static_tb["s"].quantile(p)))):
                r = evaluate(test, cut)
                for j in range(3):
                    tot[(kind, p)][j] += r[j]
                if kind == "roll" and p == a.headline:
                    rows.append({"day": str(days[i])[:10], "cutoff": round(cut, 4), "buckets": len(test),
                                 "anomalous": int(test["truth"].sum()), "tp": r[0], "fp": r[1], "fn": r[2]})
                    print(f"{str(days[i])[:10]}  cutoff {cut:.4f}  buckets {len(test):4d}  anomalous {int(test['truth'].sum()):3d}  TP {r[0]:3d} FP {r[1]:3d} FN {r[2]:3d}")

    pd.DataFrame(rows).to_csv("rolling_baseline_log.csv", index=False)
    print(f"\n{ndays} test days. Precision / recall by cutoff percentile:")
    print("percentile  | rolling: TP FP FN  prec  rec  FP/day | frozen: TP FP FN  prec  rec  FP/day")
    for p in sorted(pcts):
        out = []
        for kind in ("roll", "static"):
            tp, fp, fn = tot[(kind, p)]
            pp, rr = pr(tp, fp, fn)
            out.append(f"{tp:3d} {fp:4d} {fn:3d}  {pp:.3f} {rr:.3f} {fp/ndays:5.1f}")
        mark = "  <- headline" if p == a.headline else ""
        print(f"{p:<11} | {out[0]} | {out[1]}{mark}")
    print("Wrote rolling_baseline_log.csv (headline percentile)")


if __name__ == "__main__":
    main()

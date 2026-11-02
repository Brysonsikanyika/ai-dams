"""
Walk-forward test of the LSTM autoencoder (objective 1: dynamic baseline).

For each simulated day after the first TRAIN_DAYS: fit the feature scaler and the
autoencoder on windows from the previous TRAIN_DAYS days (only windows with no
labelled anomaly are used for fitting, the same rule as train_lstm_autoencoder.py),
set the cutoff from a percentile of that window's own bucket-max reconstruction
errors (no labels), then score the next day. A frozen model fitted once on the first
TRAIN_DAYS days is scored on the same days. Labels are used only to evaluate.
Truth is burst-only, as in rolling_baseline.py (injections belong to the classifier).
The headline percentile is fixed in advance (0.995); the others are sensitivity.
"""
import argparse
import os
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from behaviour_features import feature_columns, LSTM_NUMERIC
from train_lstm_autoencoder import engineer_features, build_windows, build_autoencoder, WINDOW_SIZE

INPUT_PATH = "ground_truth.csv"
TRAIN_DAYS = 7
BUCKET = "15min"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcts", default="0.95,0.99,0.995,0.999")
    ap.add_argument("--headline", type=float, default=0.995)
    a = ap.parse_args()
    pcts = [float(x) for x in a.pcts.split(",")]
    if a.headline not in pcts:
        pcts.append(a.headline)

    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    df = engineer_features(raw.copy())
    cols = feature_columns(df, tables=True)
    num_idx = [cols.index(c) for c in LSTM_NUMERIC]
    X, y, types, cids, ends = build_windows(df, cols, WINDOW_SIZE)
    X = np.asarray(X, dtype="float32"); y = np.asarray(y); types = np.asarray(types)
    ends = pd.Series(pd.to_datetime(ends))
    day = ends.dt.floor("D").values
    bkey = (pd.Series(cids).astype(str) + "|" + ends.dt.floor(BUCKET).astype(str)).values
    ev = df[["customer_id", "simulated_timestamp", "is_anomaly", "anomaly_type"]].copy()
    ev["burst"] = ((ev["is_anomaly"] == 1) & (ev["anomaly_type"] != "sql_injection")).astype(int)
    key = ev.groupby(["customer_id", "simulated_timestamp"])["burst"].max()
    truth = key.reindex(pd.MultiIndex.from_arrays([cids, ends])).fillna(0).astype(int).values  # window ends on a burst event
    days = sorted(pd.unique(day))
    print(f"{len(X)} windows over {len(days)} days; training window = {TRAIN_DAYS} days; headline percentile {a.headline}", flush=True)

    def fit_fold(train_mask):
        sc = StandardScaler().fit(X[train_mask][:, :, num_idx].reshape(-1, len(num_idx)))

        def scale(A):
            A = A.copy()
            sh = A[:, :, num_idx].shape
            A[:, :, num_idx] = sc.transform(A[:, :, num_idx].reshape(-1, len(num_idx))).reshape(sh)
            return A

        Xtr = scale(X[train_mask])
        clean = Xtr[y[train_mask] == 0]
        keras.utils.set_random_seed(42)
        model = build_autoencoder(WINDOW_SIZE, X.shape[2])
        model.fit(clean, clean, epochs=20, batch_size=32, validation_split=0.1, verbose=0)

        def errs(mask):
            A = scale(X[mask])
            return np.mean(np.square(A - model.predict(A, verbose=0)), axis=(1, 2))
        return errs

    def btable(e, mask):
        g = pd.DataFrame({"b": bkey[mask], "s": e, "t": truth[mask]})
        return g.groupby("b").agg(s=("s", "max"), t=("t", "max"))

    def evaluate(tb, cut):
        flag = tb["s"] > cut
        return (int((flag & (tb["t"] == 1)).sum()), int((flag & (tb["t"] == 0)).sum()), int((~flag & (tb["t"] == 1)).sum()))

    first = np.isin(day, days[:TRAIN_DAYS])
    f_errs = fit_fold(first)
    f_tb = btable(f_errs(first), first)

    tot = {(k, p): [0, 0, 0] for k in ("roll", "static") for p in pcts}
    ndays, rows = 0, []
    for i in range(TRAIN_DAYS, len(days)):
        tr = (day >= days[i - TRAIN_DAYS]) & (day < days[i])
        te = day == days[i]
        if te.sum() == 0:
            continue
        ndays += 1
        errs = fit_fold(tr)
        tb = btable(errs(tr), tr)
        t_roll = btable(errs(te), te)
        t_stat = btable(f_errs(te), te)
        for p in pcts:
            for kind, test, cut in (("roll", t_roll, float(tb["s"].quantile(p))), ("static", t_stat, float(f_tb["s"].quantile(p)))):
                r = evaluate(test, cut)
                for j in range(3):
                    tot[(kind, p)][j] += r[j]
                if kind == "roll" and p == a.headline:
                    rows.append({"day": str(days[i])[:10], "cutoff": round(cut, 5), "buckets": len(test), "anomalous": int(test["t"].sum()), "tp": r[0], "fp": r[1], "fn": r[2]})
                    print(f"{str(days[i])[:10]}  cutoff {cut:.5f}  buckets {len(test):4d}  anomalous {int(test['t'].sum()):3d}  TP {r[0]:3d} FP {r[1]:3d} FN {r[2]:3d}", flush=True)
    pd.DataFrame(rows).to_csv("rolling_lstm_log.csv", index=False)

    def pr(tp, fp, fn):
        return (tp / (tp + fp) if tp + fp else 0.0), (tp / (tp + fn) if tp + fn else 0.0)
    print(f"\n{ndays} test days. LSTM precision / recall by cutoff percentile:")
    print("percentile  | rolling: TP FP FN  prec  rec  FP/day | frozen: TP FP FN  prec  rec  FP/day")
    for p in sorted(pcts):
        out = []
        for kind in ("roll", "static"):
            tp, fp, fn = tot[(kind, p)]
            pp, rr = pr(tp, fp, fn)
            out.append(f"{tp:3d} {fp:4d} {fn:3d}  {pp:.3f} {rr:.3f} {fp / ndays:5.1f}")
        print(f"{p:<11} | {out[0]} | {out[1]}{'  <- headline' if p == a.headline else ''}")
    print("Wrote rolling_lstm_log.csv")


if __name__ == "__main__":
    main()

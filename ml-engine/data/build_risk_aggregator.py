"""
AI-DAMS risk aggregator.

Combines Isolation Forest (per-event) and LSTM Autoencoder (per-window)
scores into one risk score per (customer, time bucket) -- the "unified
severity score" the proposal describes.

NLP classifier output is joined in from nlp_scores.csv (written by
join_nlp_scores.py). Attribution is now real: every statement runs under
a per-student MySQL account and carries an event-id tag, so each captured
query text maps back to one ground-truth event and customer.

Fusion rule: combined_risk = max(behavioural_risk, nlp_risk), where
behavioural_risk is the mean of the IF and LSTM percentile ranks. MAX and
not a mean, because an injection probe is behaviourally ordinary (one
SELECT on a normal table at a normal hour): averaging it with two low
behavioural scores would bury it. nlp_risk is not a percentile rank
either, because the classifier has a calibrated cutoff: probabilities at
or below the cutoff map linearly onto 0..0.90, probabilities above it map
onto 0.90..1.0, so "NLP flagged" always lands above the 0.90 alert line.
This mapping is a design decision, not a learned weight.

KNOWN LIMITATION: the LSTM Autoencoder is scored here on ALL windows,
including the ones it was trained on. Windows in the training set will
show artificially low reconstruction error (the model partially
memorized them), so LSTM risk scores for time buckets containing
training-set windows are optimistically biased low. A production version
would need a proper train/inference split maintained over time, not
retrained-and-scored-on-everything the way this proof of concept is.

"Confidence-weighted" is simplified here to equal weighting when both
models have a score for a given bucket, and using whichever model has a
score when only one does. This is NOT calibrated per-model confidence
weighting (which would need reliability estimates per anomaly type, e.g.
weighting Isolation Forest down for the anomaly types it struggles with)
-- that's real follow-up work, not implemented here.
"""

import numpy as np
import pandas as pd
from behaviour_features import engineer, feature_columns, LSTM_NUMERIC
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from train_isolation_forest import engineer_features as if_engineer_features

INPUT_PATH = "ground_truth.csv"
NLP_PATH = "nlp_scores.csv"
NLP_CONFIG_PATH = "nlp_classifier_v2_config.json"
TIME_BUCKET = "15min"


def run_isolation_forest(raw: pd.DataFrame) -> pd.DataFrame:
    df = if_engineer_features(raw.copy())
    feature_cols = feature_columns(df, tables=False)
    X = df[feature_cols].fillna(0)

    model = IsolationForest(n_estimators=200, contamination=0.11, random_state=42)
    model.fit(X)
    scores = model.decision_function(X)  # lower = more anomalous

    return pd.DataFrame({
        "customer_id": df["customer_id"],
        "simulated_timestamp": df["simulated_timestamp"],
        "if_raw_score": -scores,  # flip sign: higher now = more anomalous
    })


def run_lstm_autoencoder(raw: pd.DataFrame) -> pd.DataFrame:
    from train_lstm_autoencoder import (
        engineer_features as lstm_engineer_features,
        build_windows,
        build_autoencoder,
        WINDOW_SIZE,
    )
    df = lstm_engineer_features(raw.copy())
    feature_cols = feature_columns(df, tables=True)

    numeric_cols = list(LSTM_NUMERIC)
    scaler = StandardScaler()
    df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

    X, y, _types, window_customer_ids, window_end_ts = build_windows(df, feature_cols, WINDOW_SIZE)

    X_normal = X[y == 0]
    split = int(len(X_normal) * 0.8)
    X_train = X_normal[:split]

    n_features = X.shape[2]
    model = build_autoencoder(WINDOW_SIZE, n_features)
    model.fit(X_train, X_train, epochs=20, batch_size=32, validation_split=0.1, verbose=0)

    recon = model.predict(X, verbose=0)
    errors = np.mean(np.square(X - recon), axis=(1, 2))

    return pd.DataFrame({
        "customer_id": window_customer_ids,
        "simulated_timestamp": pd.to_datetime(window_end_ts),
        "lstm_raw_score": errors,
    })


def normalize(series: pd.Series) -> pd.Series:
    """Percentile-rank normalization, not min-max.

    Min-max normalization was the actual bug behind the aggregator's poor
    precision: a few extreme Isolation Forest scores stretched the scale
    so much that many ordinary, non-anomalous buckets still landed above
    a fixed threshold of 0.3 -- explaining the 2117 false positives seen
    with min-max. Percentile rank instead asks "what fraction of buckets
    does this one score higher than", which is immune to a handful of
    extreme outliers distorting the whole scale, and produces a score
    that's directly interpretable as "top X% most anomalous."

    IMPORTANT: this changes what a sensible THRESHOLD means. With ranks,
    threshold=0.3 would mean "flag the top 70% of all buckets" -- far too
    liberal. A rank-based threshold needs to be high (e.g. 0.9 = top 10%
    most anomalous), not the old 0.3.
    """
    return series.rank(pct=True)


def nlp_to_risk(prob: pd.Series, cutoff: float) -> pd.Series:
    """Map classifier probability to 0..1 risk with the calibrated cutoff at 0.90."""
    below = 0.90 * prob / cutoff
    above = 0.90 + 0.10 * (prob - cutoff) / (1 - cutoff)
    return np.where(prob > cutoff, above, below).clip(0, 1)


def main():
    import json
    import sys
    skip_lstm = "--skip-lstm" in sys.argv
    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    print(f"Loaded {len(raw)} rows, {raw['is_anomaly'].sum()} labeled anomalous")

    print("\nRunning Isolation Forest...")
    if_scores = run_isolation_forest(raw)

    if skip_lstm:
        print("Skipping LSTM (--skip-lstm): behavioural risk = Isolation Forest only.")
        lstm_scores = pd.DataFrame({"customer_id": pd.Series(dtype=raw["customer_id"].dtype),
                                    "simulated_timestamp": pd.Series(dtype="datetime64[ns]"),
                                    "lstm_raw_score": pd.Series(dtype=float)})
    else:
        print("Running LSTM Autoencoder (this trains a fresh model, takes ~30-60s)...")
        lstm_scores = run_lstm_autoencoder(raw)

    if_scores["time_bucket"] = if_scores["simulated_timestamp"].dt.floor(TIME_BUCKET)
    lstm_scores["time_bucket"] = lstm_scores["simulated_timestamp"].dt.floor(TIME_BUCKET)

    if_bucketed = (
        if_scores.groupby(["customer_id", "time_bucket"])["if_raw_score"]
        .max()
        .reset_index()
    )
    lstm_bucketed = (
        lstm_scores.groupby(["customer_id", "time_bucket"])["lstm_raw_score"]
        .max()
        .reset_index()
    )

    if_bucketed["if_risk"] = normalize(if_bucketed["if_raw_score"])
    lstm_bucketed["lstm_risk"] = normalize(lstm_bucketed["lstm_raw_score"])

    combined = pd.merge(if_bucketed, lstm_bucketed, on=["customer_id", "time_bucket"], how="outer")

    def behavioural_row(row):
        scores = [x for x in (row["if_risk"], row["lstm_risk"]) if pd.notna(x)]
        return sum(scores) / len(scores) if scores else 0.0

    combined["behavioural_risk"] = combined.apply(behavioural_row, axis=1)

    # NLP: one risk per (customer, bucket) = the riskiest statement in it.
    nlp = pd.read_csv(NLP_PATH, parse_dates=["simulated_timestamp"])
    cutoff = float(json.load(open(NLP_CONFIG_PATH))["cutoff"])
    nlp["time_bucket"] = nlp["simulated_timestamp"].dt.floor(TIME_BUCKET)
    nlp_bucketed = nlp.groupby(["customer_id", "time_bucket"])["nlp_prob"].max().reset_index()
    nlp_bucketed["nlp_risk"] = nlp_to_risk(nlp_bucketed["nlp_prob"], cutoff)
    print(f"NLP scores joined: {len(nlp)} statements -> {len(nlp_bucketed)} buckets (cutoff {cutoff:.4f})")

    combined = pd.merge(combined, nlp_bucketed[["customer_id", "time_bucket", "nlp_risk"]],
                        on=["customer_id", "time_bucket"], how="outer")
    combined["behavioural_risk"] = combined["behavioural_risk"].fillna(0.0)
    combined["nlp_risk"] = combined["nlp_risk"].fillna(0.0)
    combined["combined_risk"] = combined[["behavioural_risk", "nlp_risk"]].max(axis=1)

    # Ground truth at the bucket level, for evaluation only.
    raw["time_bucket"] = raw["simulated_timestamp"].dt.floor(TIME_BUCKET)
    raw["_inj"] = ((raw["is_anomaly"] == 1) & (raw["anomaly_type"] == "sql_injection")).astype(int)
    raw["_burst"] = ((raw["is_anomaly"] == 1) & (raw["anomaly_type"] != "sql_injection")).astype(int)
    bucket_truth = (
        raw.groupby(["customer_id", "time_bucket"])
        .agg(bucket_has_anomaly=("is_anomaly", "max"), bucket_has_injection=("_inj", "max"),
             bucket_has_burst=("_burst", "max"))
        .reset_index()
    )
    combined = pd.merge(combined, bucket_truth, on=["customer_id", "time_bucket"], how="left")
    for c in ("bucket_has_anomaly", "bucket_has_injection", "bucket_has_burst"):
        combined[c] = combined[c].fillna(0)

    print(f"\nBuilt {len(combined)} (customer, time-bucket) risk scores")
    print(f"Buckets: {len(if_bucketed)} with IF, {len(lstm_bucketed)} with LSTM, "
          f"{len(nlp_bucketed)} with NLP, {len(combined)} distinct in total")
    print(f"Anomalous buckets: {int(combined.bucket_has_anomaly.sum())} "
          f"(behavioural {int(combined.bucket_has_burst.sum())}, injection {int(combined.bucket_has_injection.sum())}, "
          f"overlap {int(((combined.bucket_has_burst==1)&(combined.bucket_has_injection==1)).sum())})")

    def score(pred, truth):
        tp = int(((pred == 1) & (truth == 1)).sum())
        fp = int(((pred == 1) & (truth == 0)).sum())
        fn = int(((pred == 0) & (truth == 1)).sum())
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        return p, r, tp, fp, fn

    for thresh in (0.90, 0.95, 0.99):
        print(f"\n--- risk > {thresh} (any anomalous bucket as truth) ---")
        for col, label in [("if_risk", "Isolation Forest alone"),
                            ("lstm_risk", "LSTM alone"),
                            ("behavioural_risk", "IF + LSTM (behavioural)"),
                            ("nlp_risk", "NLP alone"),
                            ("combined_risk", "All three (max fusion)")]:
            pred = (combined[col].fillna(0) > thresh).astype(int)
            p, r, tp, fp, fn = score(pred, combined["bucket_has_anomaly"])
            print(f"  {label:26s} precision={p:.3f} recall={r:.3f} (TP={tp} FP={fp} FN={fn})")

    thresh = 0.90
    print(f"\n--- Recall by anomaly type at risk > {thresh} (does NLP add anything?) ---")
    for tcol, tlabel in [("bucket_has_burst", "behavioural-burst buckets"),
                         ("bucket_has_injection", "injection-probe buckets")]:
        sub = combined[combined[tcol] == 1]
        line = [f"{lab}: {(sub[col] > thresh).mean():.1%}" for col, lab in
                [("behavioural_risk", "IF+LSTM"), ("nlp_risk", "NLP"), ("combined_risk", "combined")]]
        print(f"  {tlabel:28s} n={len(sub):4d}  " + "   ".join(line))

    combined.to_csv("risk_scores.csv", index=False)
    print("\nSaved per-(customer, time-bucket) risk scores to risk_scores.csv")


if __name__ == "__main__":
    main()

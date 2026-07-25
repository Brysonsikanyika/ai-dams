"""
AI-DAMS risk aggregator.

Combines Isolation Forest (per-event) and LSTM Autoencoder (per-window)
scores into one risk score per (customer, time bucket) -- the "unified
severity score" the proposal describes.

NLP classifier output is DELIBERATELY EXCLUDED here. It scores raw query
TEXT, and the current pipeline has no way to attribute a piece of
captured query text back to a specific customer_id -- generate_traffic.py
uses a single MySQL connection for the entire run, so the audit log's
connection_id doesn't distinguish between simulated customers at all.
Joining NLP output into this aggregator would require the generator (and
realistically the live agent pipeline too) to use per-customer database
connections, which is a real architecture change, not implemented here.
This is a genuine, currently-unfixed gap -- documented, not silently
worked around.

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
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tensorflow import keras

from train_isolation_forest import engineer_features as if_engineer_features
from train_lstm_autoencoder import (
    engineer_features as lstm_engineer_features,
    build_windows,
    build_autoencoder,
    WINDOW_SIZE,
)

INPUT_PATH = "ground_truth.csv"
TIME_BUCKET = "15min"


def run_isolation_forest(raw: pd.DataFrame) -> pd.DataFrame:
    df = if_engineer_features(raw.copy())
    feature_cols = [
        c for c in df.columns
        if c.startswith("table_") or c.startswith("op_")
        or c in ("hour_of_day", "day_of_week", "is_night", "events_last_hour",
                  "distinct_tables_last_hour", "events_at_exact_timestamp",
                  "distinct_targets_at_exact_timestamp")
    ]
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
    df = lstm_engineer_features(raw.copy())
    feature_cols = [
        c for c in df.columns
        if c.startswith("table_") or c.startswith("op_")
        or c in ("hour_of_day", "day_of_week", "is_night", "events_at_exact_timestamp",
                  "distinct_targets_at_exact_timestamp")
    ]

    numeric_cols = ["hour_of_day", "day_of_week", "events_at_exact_timestamp",
                     "distinct_targets_at_exact_timestamp"]
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
    lo, hi = series.min(), series.max()
    if hi == lo:
        return series * 0
    return (series - lo) / (hi - lo)


def main():
    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    print(f"Loaded {len(raw)} rows, {raw['is_anomaly'].sum()} labeled anomalous")

    print("\nRunning Isolation Forest...")
    if_scores = run_isolation_forest(raw)

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

    def combine_row(row):
        scores = [s for s in (row["if_risk"], row["lstm_risk"]) if pd.notna(s)]
        return sum(scores) / len(scores) if scores else 0.0

    combined["combined_risk"] = combined.apply(combine_row, axis=1)

    # Ground truth at the bucket level, for evaluation only.
    raw["time_bucket"] = raw["simulated_timestamp"].dt.floor(TIME_BUCKET)
    bucket_truth = (
        raw.groupby(["customer_id", "time_bucket"])["is_anomaly"]
        .max()
        .reset_index()
        .rename(columns={"is_anomaly": "bucket_has_anomaly"})
    )
    combined = pd.merge(combined, bucket_truth, on=["customer_id", "time_bucket"], how="left")
    combined["bucket_has_anomaly"] = combined["bucket_has_anomaly"].fillna(0)

    print(f"\nBuilt {len(combined)} (customer, time-bucket) risk scores")
    print(f"Coverage: {if_bucketed.shape[0]} buckets have an IF score, "
          f"{lstm_bucketed.shape[0]} have an LSTM score, "
          f"{len(combined)} total distinct buckets across both")

    print("\n--- Detection performance at combined_risk > 0.3 ---")
    for col, label in [("if_risk", "Isolation Forest alone"),
                        ("lstm_risk", "LSTM alone"),
                        ("combined_risk", "Combined")]:
        pred = (combined[col].fillna(0) > 0.3).astype(int)
        truth = combined["bucket_has_anomaly"]
        tp = ((pred == 1) & (truth == 1)).sum()
        fp = ((pred == 1) & (truth == 0)).sum()
        fn = ((pred == 0) & (truth == 1)).sum()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        print(f"  {label:25s} precision={precision:.3f} recall={recall:.3f} (TP={tp} FP={fp} FN={fn})")
    combined.to_csv("risk_scores.csv", index=False)
    print("\nSaved per-(customer, time-bucket) risk scores to risk_scores.csv")


if __name__ == "__main__":
    main()
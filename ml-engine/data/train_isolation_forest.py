"""
AI-DAMS Isolation Forest training script.

Reads ground_truth.csv (from generate_traffic.py), engineers features
that capture the anomaly patterns the generator actually injects
(burst volume, table diversity, off-hours activity), trains an
Isolation Forest, and evaluates against the known labels.

IMPORTANT: is_anomaly is used ONLY for evaluation (precision/recall/F1),
never fed into training -- Isolation Forest is unsupervised by design,
and real deployment won't have ground truth labels. Using labels here to
score how well the unsupervised model happens to agree with them is
standard practice for validating on synthetic data, not a shortcut that
defeats the model's purpose.
"""

import pandas as pd
from behaviour_features import engineer, feature_columns, LSTM_NUMERIC
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

INPUT_PATH = "ground_truth.csv"


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    # v4: trailing-window rate features + operation one-hots (no table one-hots)
    return engineer(df, tables=False)


def main():
    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    print(f"Loaded {len(raw)} rows, {raw['is_anomaly'].sum()} labeled anomalous")

    df = engineer_features(raw.copy())

    feature_cols = feature_columns(df, tables=False)
    X = df[feature_cols].fillna(0)
    y_true = df["is_anomaly"]

    print(f"Feature columns: {feature_cols}")

    model = IsolationForest(
        n_estimators=200,
        contamination=0.11,
        random_state=42,
    )
    model.fit(X)

    raw_pred = model.predict(X)
    y_pred = (raw_pred == -1).astype(int)

    print("\n--- Evaluation against known labels (evaluation only, not used in training) ---")
    print(confusion_matrix(y_true, y_pred))
    print(classification_report(y_true, y_pred, target_names=["normal", "anomaly"]))
    print("\n--- Recall by anomaly type (which patterns does the model actually catch?) ---")
    df["predicted_anomaly"] = y_pred
    type_breakdown = (
        df[df["is_anomaly"] == 1]
        .groupby("anomaly_type")["predicted_anomaly"]
        .agg(["sum", "count"])
        .rename(columns={"sum": "caught", "count": "total"})
    )
    type_breakdown["recall"] = (type_breakdown["caught"] / type_breakdown["total"]).round(3)
    print(type_breakdown)

if __name__ == "__main__":
    main()
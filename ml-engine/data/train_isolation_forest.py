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
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

INPUT_PATH = "ground_truth.csv"


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values(["customer_id", "simulated_timestamp"]).reset_index(drop=True)

    df["hour_of_day"] = df["simulated_timestamp"].dt.hour
    df["day_of_week"] = df["simulated_timestamp"].dt.dayofweek
    df["is_night"] = ((df["hour_of_day"] < 6) | (df["hour_of_day"] >= 22)).astype(int)

    # Rolling per-customer signals over a trailing 60-simulated-minute window.
    # Bursts in the generator share one timestamp per burst, so these
    # naturally spike during high_frequency_burst / bulk_scan / etc.
    df["_table_code"] = pd.factorize(df["table"])[0]

    def per_customer_rolling(group: pd.DataFrame) -> pd.DataFrame:
        g = group.set_index("simulated_timestamp")
        g["events_last_hour"] = g["table"].rolling("60min").count()
        # rolling().apply() on pandas 3.x refuses non-numeric dtypes even
        # with raw=False -- distinct-table-count needs the factorized
        # integer codes, not the raw string column.
        g["distinct_tables_last_hour"] = g["_table_code"].rolling("60min").apply(
            lambda x: pd.Series(x).nunique(), raw=True
        )
        g["customer_id"] = group.name  # include_groups=False strips this; group.name recovers it
        return g.reset_index()

    df = df.groupby("customer_id", group_keys=False).apply(
        per_customer_rolling, include_groups=False
    )
    df = df.reset_index(drop=True)
    df = df.drop(columns=["_table_code"])
    # The rolling window above is causal (row-order dependent) -- when many
    # rows share the EXACT same timestamp, as every burst in the generator
    # does, only the last row in the burst sees the full count; earlier
    # rows look artificially normal. This feature fixes that by counting
    # everything at the exact same (customer_id, timestamp) directly,
    # order-independent.
    df["events_at_exact_timestamp"] = df.groupby(
        ["customer_id", "simulated_timestamp"]
    )["table"].transform("size")

    df["distinct_targets_at_exact_timestamp"] = df.groupby(
        ["customer_id", "simulated_timestamp"]
    )["target_customer_id"].transform("nunique")
    df = pd.get_dummies(df, columns=["table", "operation"], prefix=["table", "op"])

    return df

def main():
    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    print(f"Loaded {len(raw)} rows, {raw['is_anomaly'].sum()} labeled anomalous")

    df = engineer_features(raw.copy())

    feature_cols = [
        c for c in df.columns
        if c.startswith("table_") or c.startswith("op_")
        or c in ("hour_of_day", "day_of_week", "is_night", "events_last_hour",
                  "distinct_tables_last_hour", "events_at_exact_timestamp",
                  "distinct_targets_at_exact_timestamp")
    ]
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
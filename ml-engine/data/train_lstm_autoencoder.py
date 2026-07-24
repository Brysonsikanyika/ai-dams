"""
AI-DAMS LSTM Autoencoder training script.

Unlike Isolation Forest (per-event, tabular), this model works on
SEQUENCES -- a sliding window of consecutive events per customer. The
autoencoder is trained ONLY on windows containing zero anomalous events,
so it learns what normal sequential behavior looks like. At evaluation
time, windows containing real anomalies should reconstruct poorly
(higher error) simply because the model never saw anything like them
during training -- that reconstruction error IS the anomaly score.

Windows are built per-customer (never mixing two different customers'
events into one window) and are strictly time-ordered within each
customer's own event history.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from tensorflow.keras import layers

INPUT_PATH = "ground_truth.csv"
WINDOW_SIZE = 10


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values(["customer_id", "simulated_timestamp"]).reset_index(drop=True)
    df["hour_of_day"] = df["simulated_timestamp"].dt.hour
    df["day_of_week"] = df["simulated_timestamp"].dt.dayofweek
    df["is_night"] = ((df["hour_of_day"] < 6) | (df["hour_of_day"] >= 22)).astype(int)
    df["events_at_exact_timestamp"] = df.groupby(
        ["customer_id", "simulated_timestamp"]
    )["table"].transform("size")
    df = pd.get_dummies(df, columns=["table", "operation"], prefix=["table", "op"])
    return df


def build_windows(df: pd.DataFrame, feature_cols, window_size: int):
    """Slide a fixed-size window over each customer's own event sequence.

    Returns X of shape (n_windows, window_size, n_features), a
    window-level label (1 if ANY event inside is anomalous), and the
    anomaly_type of the first anomalous event in the window (for
    per-type diagnostics; "" if the window is entirely normal).
    """
    X, y, types = [], [], []
    for _customer_id, group in df.groupby("customer_id"):
        group = group.sort_values("simulated_timestamp")
        feats = group[feature_cols].values
        anomalies = group["is_anomaly"].values
        atypes = group["anomaly_type"].fillna("").values
        for start in range(len(group) - window_size + 1):
            window_feats = feats[start : start + window_size]
            window_anom_flags = anomalies[start : start + window_size]
            window_anom = window_anom_flags.max()
            window_types = atypes[start : start + window_size]
            nonempty = [t for t in window_types if t]
            window_type = nonempty[0] if nonempty else ""
            X.append(window_feats)
            y.append(window_anom)
            types.append(window_type)
    return np.array(X, dtype="float32"), np.array(y), np.array(types)


def build_autoencoder(window_size: int, n_features: int) -> keras.Model:
    model = keras.Sequential(
        [
            layers.Input(shape=(window_size, n_features)),
            layers.LSTM(32, activation="tanh", return_sequences=False),
            layers.RepeatVector(window_size),
            layers.LSTM(32, activation="tanh", return_sequences=True),
            layers.TimeDistributed(layers.Dense(n_features)),
        ]
    )
    model.compile(optimizer="adam", loss="mse")
    return model


def main():
    raw = pd.read_csv(INPUT_PATH, parse_dates=["simulated_timestamp"])
    print(f"Loaded {len(raw)} rows, {raw['is_anomaly'].sum()} labeled anomalous")

    df = engineer_features(raw.copy())

    feature_cols = [
        c for c in df.columns
        if c.startswith("table_") or c.startswith("op_")
        or c in ("hour_of_day", "day_of_week", "is_night", "events_at_exact_timestamp")
    ]

    numeric_cols = ["hour_of_day", "day_of_week", "events_at_exact_timestamp"]
    scaler = StandardScaler()
    df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

    X, y, types = build_windows(df, feature_cols, WINDOW_SIZE)
    print(f"Built {len(X)} windows of size {WINDOW_SIZE}, {y.sum()} contain at least one anomalous event")

    X_normal = X[y == 0]
    X_anomalous = X[y == 1]
    types_anomalous = types[y == 1]

    split = int(len(X_normal) * 0.8)
    X_train = X_normal[:split]
    X_normal_test = X_normal[split:]

    print(
        f"Training on {len(X_train)} clean windows; evaluating against "
        f"{len(X_normal_test)} held-out normal + {len(X_anomalous)} anomalous windows"
    )

    n_features = X.shape[2]
    model = build_autoencoder(WINDOW_SIZE, n_features)
    model.fit(X_train, X_train, epochs=20, batch_size=32, validation_split=0.1, verbose=2)

    def reconstruction_error(X_subset):
        if len(X_subset) == 0:
            return np.array([])
        recon = model.predict(X_subset, verbose=0)
        return np.mean(np.square(X_subset - recon), axis=(1, 2))

    err_normal = reconstruction_error(X_normal_test)
    err_anomalous = reconstruction_error(X_anomalous)

    print("\n--- Reconstruction error: held-out NORMAL windows ---")
    print(pd.Series(err_normal).describe())
    print("\n--- Reconstruction error: ANOMALOUS windows ---")
    print(pd.Series(err_anomalous).describe())

    threshold = err_normal.mean() + 2 * err_normal.std()
    print(f"\nThreshold (mean + 2*std of normal error): {threshold:.5f}")

    tp = int((err_anomalous > threshold).sum())
    fn = int((err_anomalous <= threshold).sum())
    fp = int((err_normal > threshold).sum())
    tn = int((err_normal <= threshold).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n--- Evaluation at this threshold ---")
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}")

    print("\n--- Recall by anomaly type (windows containing that type) ---")
    detected = err_anomalous > threshold
    breakdown = pd.DataFrame({"type": types_anomalous, "detected": detected})
    type_summary = breakdown.groupby("type")["detected"].agg(["sum", "count"])
    type_summary.columns = ["caught", "total"]
    type_summary["recall"] = (type_summary["caught"] / type_summary["total"]).round(3)
    print(type_summary)


if __name__ == "__main__":
    main()
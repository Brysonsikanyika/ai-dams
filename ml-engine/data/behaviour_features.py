"""
Shared behavioural features (v4), used by Isolation Forest, the LSTM
autoencoder, the aggregator and the explainer.

v4 replaces events_at_exact_timestamp / distinct_targets_at_exact_timestamp.
Those counted rows sharing one simulated timestamp, which only exists because
the generator stamped every burst with a single time: a real audit log has
one-second timestamps and bursts spread over several seconds. The replacement
features are TRAILING windows per customer (what a streaming detector could
compute from real audit timestamps):

    events_last_10s, events_last_60s, events_last_hour
    distinct_tables_last_60s, distinct_tables_last_hour
    distinct_targets_last_60s   (distinct target_customer_id)

Trailing windows are causal, so the first rows of a burst look calmer than the
last; the aggregator takes the max over a bucket, which is how it would behave
live too.
"""

import numpy as np
import pandas as pd

RATE_COLS = ["events_last_10s", "events_last_60s", "events_last_hour",
             "distinct_tables_last_60s", "distinct_tables_last_hour",
             "distinct_targets_last_60s"]
TIME_COLS = ["hour_of_day", "day_of_week", "is_night"]
# Columns that need scaling for the LSTM (binary one-hots and is_night do not).
LSTM_NUMERIC = ["hour_of_day", "day_of_week"] + RATE_COLS


def _distinct(window):
    return float(len(np.unique(window)))


def add_features(df: pd.DataFrame) -> pd.DataFrame:
    """Sort by customer/time and add time + trailing-window features (no one-hots)."""
    df = df.sort_values(["customer_id", "simulated_timestamp"], kind="stable").reset_index(drop=True)
    df["hour_of_day"] = df["simulated_timestamp"].dt.hour
    df["day_of_week"] = df["simulated_timestamp"].dt.dayofweek
    df["is_night"] = ((df["hour_of_day"] < 6) | (df["hour_of_day"] >= 22)).astype(int)
    df["_tcode"] = pd.factorize(df["table"])[0].astype(float)
    df["_gcode"] = pd.factorize(df["target_customer_id"])[0].astype(float)

    parts = []
    for cust, g in df.groupby("customer_id", sort=False):
        g = g.set_index("simulated_timestamp")
        g["events_last_10s"] = g["_tcode"].rolling("10s").count()
        g["events_last_60s"] = g["_tcode"].rolling("60s").count()
        g["events_last_hour"] = g["_tcode"].rolling("60min").count()
        g["distinct_tables_last_60s"] = g["_tcode"].rolling("60s").apply(_distinct, raw=True)
        g["distinct_tables_last_hour"] = g["_tcode"].rolling("60min").apply(_distinct, raw=True)
        g["distinct_targets_last_60s"] = g["_gcode"].rolling("60s").apply(_distinct, raw=True)
        parts.append(g.reset_index())
    out = pd.concat(parts, ignore_index=True)
    return out.drop(columns=["_tcode", "_gcode"])


def engineer(df: pd.DataFrame, tables: bool) -> pd.DataFrame:
    """add_features + one-hots. Operation one-hots always; table one-hots only if tables=True."""
    df = add_features(df)
    cols = ["operation"] + (["table"] if tables else [])
    prefixes = ["op"] + (["table"] if tables else [])
    return pd.get_dummies(df, columns=cols, prefix=prefixes)


def feature_columns(df: pd.DataFrame, tables: bool) -> list:
    base = TIME_COLS + RATE_COLS
    return [c for c in df.columns if c in base or c.startswith("op_") or (tables and c.startswith("table_"))]

"""
AI-DAMS NLP join.

Takes the query text captured by mysql-audit-tailer (Kafka topic
mysql.query.text), matches each captured query to its row in ground_truth.csv
using the /* evt:<run>-<n> */ tag that generate_traffic_academic.py puts on
every statement, scores the query text with the trained SQL-injection
classifier, and reports how it behaves on real academic traffic.

Why a tag and not a time join: the generator runs for minutes of wall-clock
time but labels events with simulated timestamps spread over weeks, so the
captured_at time of a query says nothing about which ground-truth row it is.

The tag is STRIPPED before classification. A /* */ comment is a classic
injection-style token; leaving it in would make the classifier react to the
tag instead of the query.

IMPORTANT for reading the result: the generator sends no injection attempts.
Every query in this traffic is benign, so every query the classifier flags is a
false positive. The anomaly types in ground_truth.csv (bulk_scan, etc.) are
behavioural anomalies, not injection attacks. And the traffic is built from a
small number of query shapes repeated thousands of times, so the number of
independent test cases is the number of distinct shapes (printed below), not the
number of rows.

Usage:
    python3 join_nlp_scores.py                  # read Kafka, then analyse
    python3 join_nlp_scores.py --offline FILE   # re-analyse a saved capture
Requires: ground_truth.csv with an event_id column, and the model files written
by train_nlp_classifier.py.
"""

import argparse
import json
import re
import sys

import joblib
import pandas as pd

TOPIC = "mysql.query.text"
BOOTSTRAP = "localhost:9092"
IDLE_SECONDS = 20  # stop reading once no new message arrives for this long

GROUND_TRUTH = "ground_truth.csv"
MODEL_PATH = "nlp_classifier_model.joblib"
VECTORIZER_PATH = "nlp_classifier_vectorizer.joblib"
CAPTURE_DUMP = "captured_query_text.jsonl"
OUTPUT = "nlp_scores.csv"

TAG_RE = re.compile(r"/\*\s*evt:([0-9a-f]{8}-\d+)\s*\*/\s*")


def capture_from_kafka(path: str) -> int:
    from kafka import KafkaConsumer  # imported here so --offline works without it

    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=BOOTSTRAP,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        consumer_timeout_ms=IDLE_SECONDS * 1000,
    )
    count = 0
    with open(path, "w", encoding="utf-8") as out:
        for message in consumer:
            out.write(message.value.decode("utf-8") + "\n")
            count += 1
    consumer.close()
    return count


def load_captured(path: str, run_ids: set) -> pd.DataFrame:
    """Keep only tagged queries belonging to the run(s) in ground_truth.csv.
    Untagged records (the tailer's own lookups, SET NAMES, ...) and tagged
    records from older runs still sitting in the topic are ignored."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            sql = record.get("sql_text") or ""
            match = TAG_RE.search(sql)
            if not match or match.group(1).split("-")[0] not in run_ids:
                continue
            rows.append({
                "event_id": match.group(1),
                "account": record.get("account"),
                "sql_text": TAG_RE.sub("", sql).strip(),
            })
    df = pd.DataFrame(rows, columns=["event_id", "account", "sql_text"])
    return df.drop_duplicates("event_id")


def shape(sql: str) -> str:
    """Collapse literal values so identical query templates group together."""
    s = re.sub(r"'(?:[^'\\]|\\.)*'", "?", sql)          # quoted strings, incl. escaped quotes
    return re.sub(r"\b\d+(?:\.\d+)?(?:e\d+)?\b", "?", s)  # numbers, incl. 1234.56e0


def report(df: pd.DataFrame, expected_total: int) -> None:
    n = len(df)
    print(f"\nCoverage: {n}/{expected_total} ground-truth events found in the captured query text")

    expected_account = "student_00" + df["customer_id"].astype(str).str[-2:]
    ok = df["account"] == expected_account
    print(f"Attribution: {ok.sum()}/{n} captured queries came from the student account "
          f"that ground truth says ran them")
    if not ok.all():
        bad = df.loc[~ok, ["customer_id", "account"]].value_counts().head(5)
        print("  mismatches (customer_id, account seen):")
        print(bad.to_string())

    flagged = int(df["nlp_flagged"].sum())
    print(f"\nClassifier flagged {flagged}/{n} queries as malicious = {flagged / n:.1%}")
    print("None of these queries is an injection attempt, so every flag is a false positive.")

    print("\nFlag rate if the decision threshold were raised:")
    for t in (0.5, 0.7, 0.9, 0.99):
        print(f"  probability > {t:<4}: {(df['nlp_prob'] > t).mean():6.1%}")

    df = df.assign(shape=df["sql_text"].map(shape))
    table = (
        df.groupby("shape")
        .agg(queries=("nlp_flagged", "size"), flagged=("nlp_flagged", "sum"),
             mean_prob=("nlp_prob", "mean"))
        .sort_values("queries", ascending=False)
    )
    table["flag_rate"] = table["flagged"] / table["queries"]
    print(f"\nBy query shape ({len(table)} distinct shapes in {n} queries):")
    with pd.option_context("display.max_colwidth", 95, "display.width", 200):
        print(table[["queries", "flagged", "flag_rate", "mean_prob"]]
              .to_string(float_format=lambda x: f"{x:.3f}"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", metavar="JSONL",
                        help="analyse a saved capture instead of reading Kafka")
    args = parser.parse_args()

    gt = pd.read_csv(GROUND_TRUTH)
    if "event_id" not in gt.columns:
        sys.exit("ground_truth.csv has no event_id column. Regenerate it with the "
                 "tagged generate_traffic_academic.py first.")
    run_ids = set(gt["event_id"].str.split("-").str[0])

    path = args.offline or CAPTURE_DUMP
    if not args.offline:
        print(f"Reading {TOPIC} from {BOOTSTRAP} (stops after {IDLE_SECONDS}s of silence)...")
        print(f"  {capture_from_kafka(path)} raw messages saved to {path}")

    captured = load_captured(path, run_ids)
    if captured.empty:
        sys.exit(
            "No tagged queries for this run were found in the capture. Likely causes:\n"
            "  - mysql-audit-tailer was not running while the generator ran\n"
            "  - MySQL's audit log does not keep the leading /* evt:... */ comment\n"
            "  - the run id in ground_truth.csv is from a different generation than the capture\n"
            f"Run id(s) expected: {sorted(run_ids)}")

    df = gt.merge(captured, on="event_id", how="inner")
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    features = vectorizer.transform(df["sql_text"])
    df["nlp_prob"] = model.predict_proba(features)[:, list(model.classes_).index(1)]
    df["nlp_flagged"] = model.predict(features)

    report(df, expected_total=len(gt))

    keep = ["event_id", "simulated_timestamp", "customer_id", "target_customer_id", "table",
            "operation", "is_anomaly", "anomaly_type", "account", "sql_text",
            "nlp_prob", "nlp_flagged"]
    df[keep].to_csv(OUTPUT, index=False)
    print(f"\nSaved {OUTPUT}")


if __name__ == "__main__":
    main()

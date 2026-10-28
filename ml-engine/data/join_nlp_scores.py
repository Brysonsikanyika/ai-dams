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

HOW TO READ THE RESULT. ground_truth.csv marks two different things as
anomalies. The behavioural anomalies (bulk_scan, high_frequency_burst, ...) have
perfectly ordinary SQL text, so for THIS classifier they count as benign text.
Only anomaly_type == "sql_injection" rows carry attack text. The report
therefore gives (a) a false-positive rate on benign text, broken down by query
kind, and (b) recall on injection probes, broken down by payload family.
Two limits to keep in mind: the traffic is synthetic and drawn from a fixed
catalogue (academic_workload.py), so the number of independent test cases is the
number of distinct kinds and payloads, not the number of rows; and the injection
payloads were fixed before any classifier output was seen and must not be edited
to improve the numbers.

Usage:
    python3 join_nlp_scores.py                  # read Kafka, then analyse
    python3 join_nlp_scores.py --offline FILE   # re-analyse a saved capture
Requires: ground_truth.csv with an event_id column, and the deployed classifier
written by train_final_nlp_v2.py (nlp_classifier_v2_model.joblib and
nlp_classifier_v2_config.json). A query is flagged when its probability exceeds the
cutoff in that config, which was calibrated on the application's own benign baseline.
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
MODEL_PATH = "nlp_classifier_v2_model.joblib"
CONFIG_PATH = "nlp_classifier_v2_config.json"
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


THRESHOLDS = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)


def report(df: pd.DataFrame, expected_total: int, cutoff: float) -> None:
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

    df = df.assign(detail=df["detail"].fillna(""))
    is_attack = df["anomaly_type"] == "sql_injection"
    benign, attack = df[~is_attack], df[is_attack]
    fp, tp = int(benign["nlp_flagged"].sum()), int(attack["nlp_flagged"].sum())

    print(f"\n=== Classifier at its calibrated cutoff (probability > {cutoff:.3f}) ===")
    print(f"Benign text:    {len(benign):5d} queries, {fp:4d} flagged -> "
          f"false-positive rate {fp / len(benign):.2%}")
    print(f"Injection text: {len(attack):5d} queries, {tp:4d} caught  -> "
          f"recall {tp / len(attack):.1%}")
    if tp + fp:
        print(f"Precision: {tp / (tp + fp):.1%} of everything flagged was a real injection probe "
              f"(this depends on the {len(attack) / n:.1%} attack share of the traffic)")

    print("\n=== Trade-off if the cutoff is moved (illustrative) ===")
    print(" cutoff   false-positive rate   recall")
    for t in sorted(set(THRESHOLDS) | {cutoff}):
        mark = "   <- calibrated cutoff" if t == cutoff else ""
        print(f"  >{t:<5.3f}  {(benign['nlp_prob'] > t).mean():17.2%}   "
              f"{(attack['nlp_prob'] > t).mean():6.1%}{mark}")

    kinds = (
        benign.assign(kind=benign["detail"].replace("", "(behavioural-anomaly traffic)"))
        .groupby("kind")
        .agg(queries=("nlp_flagged", "size"), flagged=("nlp_flagged", "sum"),
             mean_prob=("nlp_prob", "mean"), max_prob=("nlp_prob", "max"))
        .sort_values("max_prob", ascending=False)
    )
    print(f"\n=== Benign text by query kind ({len(kinds)} kinds), sorted by highest probability ===")
    print(kinds.to_string(float_format=lambda x: f"{x:.3f}"))

    fams = (
        attack.groupby("detail")
        .agg(probes=("nlp_flagged", "size"), caught=("nlp_flagged", "sum"),
             mean_prob=("nlp_prob", "mean"), min_prob=("nlp_prob", "min"))
    )
    fams["recall"] = fams["caught"] / fams["probes"]
    print(f"\n=== Injection probes by family ({len(fams)} families) ===")
    print(fams[["probes", "caught", "recall", "mean_prob", "min_prob"]]
          .sort_values("recall").to_string(float_format=lambda x: f"{x:.3f}"))

    missed = attack[attack["nlp_flagged"] == 0].drop_duplicates("sql_text")
    print(f"\nDistinct injection queries the classifier MISSED: {len(missed)}")
    for r in missed.sort_values("nlp_prob").head(12).itertuples():
        print(f"  p={r.nlp_prob:.3f} [{r.detail}] {r.sql_text[:110]}")
    wrong = benign[benign["nlp_flagged"] == 1].drop_duplicates("sql_text")
    print(f"\nDistinct benign queries the classifier FLAGGED: {len(wrong)}")
    for r in wrong.sort_values("nlp_prob", ascending=False).head(8).itertuples():
        print(f"  p={r.nlp_prob:.3f} [{r.detail or r.anomaly_type}] {r.sql_text[:110]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", metavar="JSONL",
                        help="analyse a saved capture instead of reading Kafka")
    args = parser.parse_args()

    gt = pd.read_csv(GROUND_TRUTH)
    if "detail" not in gt.columns:
        gt["detail"] = ""
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
    config = json.load(open(CONFIG_PATH))
    cutoff = float(config["cutoff"])
    print(f"Classifier: design {config['design']}, cutoff {cutoff:.4f} calibrated on "
          f"{config['baseline_rows']} benign baseline queries ({config['baseline_file']})")
    df["nlp_prob"] = model.predict_proba(df["sql_text"])[:, 1]
    df["nlp_flagged"] = (df["nlp_prob"] > cutoff).astype(int)

    report(df, expected_total=len(gt), cutoff=cutoff)

    keep = ["event_id", "simulated_timestamp", "customer_id", "target_customer_id", "table",
            "operation", "is_anomaly", "anomaly_type", "detail", "account", "sql_text",
            "nlp_prob", "nlp_flagged"]
    df[keep].to_csv(OUTPUT, index=False)
    print(f"\nSaved {OUTPUT}")


if __name__ == "__main__":
    main()

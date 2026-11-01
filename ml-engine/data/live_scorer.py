"""
AI-DAMS live scorer, stage 1: SQL-injection scoring straight from Kafka.

Reads mysql.query.text as statements arrive, strips the generator's evt tag,
scores the text with the deployed v2 classifier at its calibrated cutoff, prints
one line per statement, and appends alerts to live_alerts.jsonl with the delay
between capture and scoring. Student numbers are masked in the stored text.
Only student_NN accounts are scored (use --demo to also score root and unattributed sessions).
Stage 1 covers the SQL classifier only; behavioural models stay batch.
"""
from housekeeping import is_housekeeping
import argparse
import datetime as dt
import json
import re

import joblib
from kafka import KafkaConsumer

MODEL_PATH = "nlp_classifier_v2_model.joblib"
CONFIG_PATH = "nlp_classifier_v2_config.json"
TAG_RE = re.compile(r"/\*\s*evt:([0-9a-f]{8}-\d+)\s*\*/\s*")
STUDENT_RE = re.compile(r"^student_\d+$")
ID_RE = re.compile(r"\b23\d{5}\b")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", default="localhost:9092")
    ap.add_argument("--topic", default="mysql.query.text")
    ap.add_argument("--out", default="live_alerts.jsonl")
    ap.add_argument("--demo", action="store_true", help="also score root and unattributed sessions (for demos)")
    ap.add_argument("--from-start", action="store_true", help="replay the topic from the beginning")
    a = ap.parse_args()

    model = joblib.load(MODEL_PATH)
    cutoff = float(json.load(open(CONFIG_PATH))["cutoff"])
    consumer = KafkaConsumer(
        a.topic,
        bootstrap_servers=a.bootstrap,
        group_id="aidams-live-scorer-" + dt.datetime.now().strftime("%H%M%S"),
        auto_offset_reset="earliest" if a.from_start else "latest",
        enable_auto_commit=False,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )
    while not consumer.assignment():
        consumer.poll(timeout_ms=500)
    print(f"Listening on {a.topic} (cutoff {cutoff:.4f}). Ctrl+C to stop.", flush=True)

    scored = alerts = skipped = 0
    try:
        for msg in consumer:
            ev = msg.value
            acct = ev.get("account") or ""
            if not (STUDENT_RE.match(acct) or (a.demo and acct in ("", "root"))):
                continue
            sql = TAG_RE.sub("", ev.get("sql_text") or "").strip()
            if not sql:
                continue
            if is_housekeeping(sql):
                skipped += 1
                continue
            prob = float(model.predict_proba([sql])[0, 1])
            now = dt.datetime.now(dt.timezone.utc)
            try:
                logged = dt.datetime.fromisoformat(ev["record_id"].split("_", 1)[1]).replace(tzinfo=dt.timezone.utc)
                delay = round((now - logged).total_seconds(), 2)
            except Exception:
                delay = None
            flagged = prob > cutoff
            scored += 1
            print(f"{'ALERT' if flagged else 'ok   '} p={prob:.3f} delay={delay}s {acct:12s} {sql[:90]!r}", flush=True)
            if flagged:
                alerts += 1
                rec = {
                    "source": "live",
                    "captured_at": ev.get("captured_at"),
                    "scored_at": now.isoformat(),
                    "delay_s": delay,
                    "customer_id": int("23000" + acct[-2:]) if STUDENT_RE.match(acct) else None,
                    "account": acct,
                    "nlp_prob": round(prob, 4),
                    "cutoff": round(cutoff, 4),
                    "sql_text": ID_RE.sub("[student]", sql)[:300],
                    "record_id": ev.get("record_id"),
                }
                with open(a.out, "a") as f:
                    f.write(json.dumps(rec) + "\n")
    except KeyboardInterrupt:
        print(f"\nStopped. Scored {scored} statements, {alerts} alerts, {skipped} housekeeping skipped.")


if __name__ == "__main__":
    main()

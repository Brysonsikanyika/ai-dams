"""
AI-DAMS live scorer, stage 2: behaviour (Isolation Forest) straight from Kafka.

For each student statement it parses operation, table and target from the SQL,
updates that account's trailing windows (live_behaviour.LiveFeatures), scores the
13-feature vector with the saved Isolation Forest (if_live_model.joblib) and
alerts when the score passes the saved cutoff. One alert per account per
15-minute bucket, the same unit the walk-forward test counted.

The LSTM autoencoder is NOT scored here: it needs a window of 10 events per
student and stays batch. Alerts go to live_alerts.jsonl with source
"live_behaviour", next to the SQL-text alerts.
"""
import argparse
import datetime as dt
import json
import re
from zoneinfo import ZoneInfo

import joblib
import pandas as pd

from housekeeping import is_housekeeping
from live_behaviour import ACCT_RE, LiveFeatures, account_to_customer, parse_sql

TAG_RE = re.compile(r"/\*\s*evt:([0-9a-f]{8}-\d+)\s*\*/\s*")
ID_RE = re.compile(r"\b23\d{5}\b")
LOCAL = ZoneInfo("Africa/Lusaka")


def event_time(ev):
    """Statement time as a naive Lusaka-local datetime, plus its UTC form."""
    try:
        utc = dt.datetime.fromisoformat(ev["record_id"].split("_", 1)[1]).replace(tzinfo=dt.timezone.utc)
    except Exception:
        utc = dt.datetime.fromisoformat(ev["captured_at"])
    return utc.astimezone(LOCAL).replace(tzinfo=None), utc


class BehaviourScorer:
    def __init__(self, path="if_live_model.joblib"):
        d = joblib.load(path)
        self.model, self.cols, self.cutoff = d["model"], d["cols"], float(d["cutoff"])
        self.feat = LiveFeatures()
        self.alerted = set()

    def handle(self, ev, now=None):
        """Return (score, alert_or_None); (None, None) if the event is not scored."""
        acct = ev.get("account") or ""
        if not ACCT_RE.match(acct):
            return None, None
        sql = TAG_RE.sub("", ev.get("sql_text") or "").strip()
        if not sql or is_housekeeping(sql):
            return None, None
        op, table, target = parse_sql(sql, acct)
        if op is None or table is None:
            return None, None
        local, utc = event_time(ev)
        f = self.feat.update(acct, local, op, table, target)
        score = float(-self.model.decision_function(pd.DataFrame([f])[self.cols])[0])
        bucket = (acct, local.replace(minute=local.minute // 15 * 15, second=0, microsecond=0))
        if score <= self.cutoff or bucket in self.alerted:
            return score, None
        self.alerted.add(bucket)
        now = now or dt.datetime.now(dt.timezone.utc)
        reason = (f"{f['events_last_60s']} statements in 60 s ({f['events_last_10s']} in 10 s), "
                  f"{f['distinct_tables_last_60s']} tables, {f['distinct_targets_last_60s']} customer ids"
                  f"{', night hours' if f['is_night'] else ''}. Last: {ID_RE.sub('[student]', sql)[:120]}")
        return score, {
            "source": "live_behaviour",
            "captured_at": ev.get("captured_at"),
            "scored_at": now.isoformat(),
            "delay_s": round((now - utc).total_seconds(), 2),
            "customer_id": account_to_customer(acct),
            "account": acct,
            "nlp_prob": round(score, 4),
            "behaviour_score": round(score, 4),
            "cutoff": round(self.cutoff, 4),
            "sql_text": "[behaviour] " + reason,
            "features": {k: f[k] for k in ("events_last_10s", "events_last_60s", "events_last_hour",
                                          "distinct_tables_last_60s", "distinct_targets_last_60s")},
            "record_id": ev.get("record_id"),
        }


def main():
    from kafka import KafkaConsumer
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", default="localhost:9092")
    ap.add_argument("--topic", default="mysql.query.text")
    ap.add_argument("--out", default="live_alerts.jsonl")
    ap.add_argument("--model", default="if_live_model.joblib")
    a = ap.parse_args()
    sc = BehaviourScorer(a.model)
    consumer = KafkaConsumer(
        a.topic, bootstrap_servers=a.bootstrap,
        group_id="aidams-live-behaviour-" + dt.datetime.now().strftime("%H%M%S"),
        auto_offset_reset="latest", enable_auto_commit=False,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
    )
    while not consumer.assignment():
        consumer.poll(timeout_ms=500)
    print(f"Behaviour scorer listening on {a.topic} (cutoff {sc.cutoff:.4f}). Ctrl+C to stop.", flush=True)
    n = alerts = 0
    try:
        for msg in consumer:
            score, alert = sc.handle(msg.value)
            if score is None:
                continue
            n += 1
            print(f"{'ALERT' if alert else 'ok   '} s={score:.4f} {msg.value.get('account'):12s}", flush=True)
            if alert:
                alerts += 1
                with open(a.out, "a") as fh:
                    fh.write(json.dumps(alert) + "\n")
    except KeyboardInterrupt:
        print(f"\nStopped. Scored {n} statements, {alerts} alerts.")


if __name__ == "__main__":
    main()

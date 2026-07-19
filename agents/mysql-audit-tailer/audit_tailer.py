"""
AI-DAMS MySQL audit-log tailer.

Runs as a Docker sidecar (NOT a host-side venv script like the other three
agents), because it needs direct filesystem access to
/var/lib/mysql/audit_filter.log, which lives inside the same named Docker
volume MySQL itself writes to (mounted here read-only). There's no network
protocol to tail this file the way binlog/logical-replication/CDC work.

UNLIKE the other three agents, this one DELIBERATELY DOES capture raw SQL
text -- that's the entire point, it's the only feed for the NLP
SQL-injection classifier. This is a different privacy/scoping tradeoff
than agents/{mysql,postgres,mssql}-agent, which all deliberately discard
query text. Document this distinction explicitly in the report: raw query
text capture here is justified because the model needs it, not a default.

The audit log is a single XML document whose root <AUDIT> element is never
closed while MySQL is running (it's appended to continuously), so it can't
be parsed as a complete XML document while tailing live. Instead this
buffers raw text and extracts individual <AUDIT_RECORD>...</AUDIT_RECORD>
fragments, each of which IS well-formed XML on its own.

The 'query' class logs both "Query Start" and "Query Status End" per
statement (same text, twice) -- this tailer keeps only "Query Start" to
avoid duplicate publishing.
"""

import json
import os
import re
import socket
import time
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from kafka import KafkaProducer

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/var/lib/mysql/audit_filter.log")
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "mysql.query.text")
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "2"))

AGENT_HOST = socket.gethostname()

RECORD_RE = re.compile(r"<AUDIT_RECORD>.*?</AUDIT_RECORD>", re.DOTALL)


def build_producer() -> KafkaProducer:
    return KafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, linger_ms=50)


def emit(producer: KafkaProducer, payload: dict) -> None:
    envelope = {
        "engine": "mysql",
        "event_type": "query_text",
        "agent_host": AGENT_HOST,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    future = producer.send(KAFKA_TOPIC, value=json.dumps(envelope).encode("utf-8"))
    future.add_errback(
        lambda exc: print(f"[audit-tailer] FAILED to send: {exc}", flush=True)
    )
    print(f"[audit-tailer] queued: {payload}", flush=True)


def wait_for_file(path: str) -> None:
    while not os.path.exists(path):
        print(f"[audit-tailer] waiting for {path} to exist...", flush=True)
        time.sleep(5)


def parse_record(xml_fragment: str):
    try:
        root = ET.fromstring(xml_fragment)
    except ET.ParseError:
        return None

    name = root.findtext("NAME")
    if name != "Query Start":
        return None  # skip Query Status End -- duplicate text, no new info

    sql_text = root.findtext("SQLTEXT")
    if not sql_text:
        return None

    return {
        "command_class": root.findtext("COMMAND_CLASS"),
        "sql_text": sql_text,
        "connection_id": root.findtext("CONNECTION_ID"),
        "record_id": root.findtext("RECORD_ID"),
    }


def run(producer: KafkaProducer) -> None:
    wait_for_file(AUDIT_LOG_PATH)

    with open(AUDIT_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)  # only new records from here -- no replay of history
        buffer = ""

        print(
            f"[audit-tailer] tailing {AUDIT_LOG_PATH} "
            f"-> publishing to '{KAFKA_TOPIC}' on {KAFKA_BOOTSTRAP}",
            flush=True,
        )

        while True:
            chunk = f.read()
            if chunk:
                buffer += chunk
                last_end = 0
                for match in RECORD_RE.finditer(buffer):
                    record = parse_record(match.group(0))
                    if record:
                        emit(producer, record)
                    last_end = match.end()
                buffer = buffer[last_end:]  # keep only the unparsed remainder
            else:
                time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    kafka_producer = build_producer()
    try:
        while True:
            try:
                run(kafka_producer)
            except KeyboardInterrupt:
                break
            except Exception as exc:  # noqa: BLE001 - top-level retry loop, log and retry
                print(f"[audit-tailer] error: {exc}; retrying in 5s", flush=True)
                time.sleep(5)
    finally:
        kafka_producer.flush(timeout=10)
        kafka_producer.close()
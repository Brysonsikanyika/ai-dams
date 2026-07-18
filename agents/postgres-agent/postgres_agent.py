"""
AI-DAMS PostgreSQL audit agent.

Tails PostgreSQL's logical replication stream via the built-in
`test_decoding` output plugin (ships with core PostgreSQL -- no extra
extension like wal2json needed) and publishes DML events to Kafka.

Same scoping decisions as the MySQL agent, for consistency:
- No authentication/connection events (logical replication only sees
  data changes, same limitation as MySQL's binlog)
- No SELECT statements (logical decoding never sees reads)
- No actual row values -- test_decoding's output includes them, but this
  agent deliberately discards them, keeping only table + operation.
"""

import json
import os
import re
import socket
import time
from datetime import datetime, timezone

import psycopg2
from kafka import KafkaProducer
from psycopg2.extras import LogicalReplicationConnection

PG_HOST = os.environ.get("PG_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("PG_PORT", "5432"))
PG_DB = os.environ.get("PG_DB", "aidams_demo")
PG_USER = os.environ.get("PG_AGENT_USER", "aidams_agent")
PG_PASSWORD = os.environ.get("PG_AGENT_PASSWORD")

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "127.0.0.1:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "postgres.audit.events")
SLOT_NAME = os.environ.get("PG_SLOT_NAME", "aidams_slot")

if not PG_PASSWORD:
    raise RuntimeError(
        "PG_AGENT_PASSWORD env var is required (matches the value in .env)"
    )

AGENT_HOST = socket.gethostname()

# test_decoding output looks like:
#   table public.test_orders: INSERT: id[integer]:1 item[character varying]:'widget'
# We only pull table + operation, deliberately discarding the column values.
LINE_RE = re.compile(r"^table (?P<table>\S+): (?P<op>INSERT|UPDATE|DELETE):")


def build_producer() -> KafkaProducer:
    return KafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, linger_ms=50)


def emit(producer: KafkaProducer, event_type: str, payload: dict) -> None:
    envelope = {
        "engine": "postgres",
        "event_type": event_type,
        "agent_host": AGENT_HOST,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    future = producer.send(KAFKA_TOPIC, value=json.dumps(envelope).encode("utf-8"))
    future.add_errback(
        lambda exc: print(f"[postgres-agent] FAILED to send {event_type}: {exc}", flush=True)
    )
    print(f"[postgres-agent] queued {event_type}: {payload}", flush=True)


def ensure_slot() -> None:
    """Create the logical replication slot if it doesn't already exist.

    Must run on a plain connection, not a replication connection.
    """
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASSWORD
    )
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM pg_replication_slots WHERE slot_name = %s", (SLOT_NAME,)
        )
        if cur.fetchone() is None:
            cur.execute(
                "SELECT * FROM pg_create_logical_replication_slot(%s, 'test_decoding')",
                (SLOT_NAME,),
            )
            print(f"[postgres-agent] created replication slot '{SLOT_NAME}'", flush=True)
        else:
            print(f"[postgres-agent] reusing existing replication slot '{SLOT_NAME}'", flush=True)
    conn.close()


def run(producer: KafkaProducer) -> None:
    ensure_slot()

    repl_conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD,
        connection_factory=LogicalReplicationConnection,
    )
    cur = repl_conn.cursor()
    cur.start_replication(slot_name=SLOT_NAME, decode=True)

    print(
        f"[postgres-agent] tailing replication slot '{SLOT_NAME}' on "
        f"{PG_HOST}:{PG_PORT} -> publishing to '{KAFKA_TOPIC}' on {KAFKA_BOOTSTRAP}",
        flush=True,
    )

    def consume(msg) -> None:
        match = LINE_RE.match(msg.payload)
        if match:
            emit(
                producer,
                "dml",
                {"table": match.group("table"), "operation": match.group("op")},
            )
        msg.cursor.send_feedback(flush_lsn=msg.data_start)

    cur.consume_stream(consume)


if __name__ == "__main__":
    kafka_producer = build_producer()
    try:
        while True:
            try:
                run(kafka_producer)
            except KeyboardInterrupt:
                break
            except Exception as exc:  # noqa: BLE001 - top-level retry loop, log and retry
                print(f"[postgres-agent] stream error: {exc}; retrying in 5s", flush=True)
                time.sleep(5)
    finally:
        kafka_producer.flush(timeout=10)
        kafka_producer.close()
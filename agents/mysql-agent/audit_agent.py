"""
AI-DAMS MySQL audit agent.

Tails the MySQL binary log (ROW format) and publishes DML/DDL events to
Kafka. Deliberately does NOT capture authentication events or SELECT
statements -- see agents/mysql-agent/README.md for why, and see the
project README for the FR1 scoping note.

Deliberately does NOT capture actual row data/values, only metadata
(table, operation, row count). Capturing real row content means capturing
whatever sensitive data lives in the monitored database, which is a much
bigger compliance surface (GDPR / Zambia DPA) than a final-year prototype
needs to take on. Flag this as a scoping decision in the report, not an
oversight.
"""

import json
import os
import socket
import time
from datetime import datetime, timezone

from kafka import KafkaProducer
from pymysqlreplication import BinLogStreamReader
from pymysqlreplication.event import QueryEvent
from pymysqlreplication.row_event import (
    DeleteRowsEvent,
    UpdateRowsEvent,
    WriteRowsEvent,
)

MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_AGENT_USER", "aidams_agent")
MYSQL_PASSWORD = os.environ.get("MYSQL_AGENT_PASSWORD")

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "127.0.0.1:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "mysql.audit.events")

# Must NOT collide with MySQL's own --server-id (set to 1 in docker-compose.yml).
# The replication protocol identifies each connected replica/agent by this ID.
AGENT_SERVER_ID = int(os.environ.get("AGENT_SERVER_ID", "100"))

if not MYSQL_PASSWORD:
    raise RuntimeError(
        "MYSQL_AGENT_PASSWORD env var is required (matches the value in .env)"
    )

AGENT_HOST = socket.gethostname()


def build_producer() -> KafkaProducer:
    # Deliberately no value_serializer here -- kafka-python's serializer
    # interface changed incompatibly between 2.x and 3.x. Encoding to bytes
    # ourselves before send() sidesteps that entirely and works across
    # library versions.
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        linger_ms=50,
    )


def emit(producer: KafkaProducer, event_type: str, payload: dict) -> None:
    envelope = {
        "engine": "mysql",
        "event_type": event_type,
        "agent_host": AGENT_HOST,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    future = producer.send(KAFKA_TOPIC, value=json.dumps(envelope).encode("utf-8"))
    future.add_errback(
        lambda exc: print(f"[mysql-agent] FAILED to send {event_type}: {exc}", flush=True)
    )
    print(f"[mysql-agent] queued {event_type}: {payload}", flush=True)


def run(producer: KafkaProducer) -> None:
    stream = BinLogStreamReader(
        connection_settings={
            "host": MYSQL_HOST,
            "port": MYSQL_PORT,
            "user": MYSQL_USER,
            "passwd": MYSQL_PASSWORD,
        },
        server_id=AGENT_SERVER_ID,
        blocking=True,
        only_events=[WriteRowsEvent, UpdateRowsEvent, DeleteRowsEvent, QueryEvent],
        resume_stream=True,
    )

    print(
        f"[mysql-agent] tailing binlog on {MYSQL_HOST}:{MYSQL_PORT} "
        f"-> publishing to '{KAFKA_TOPIC}' on {KAFKA_BOOTSTRAP}",
        flush=True,
    )

    for binlogevent in stream:
        if isinstance(binlogevent, QueryEvent):
            query = binlogevent.query.strip()
            if not query or query.upper() in ("BEGIN", "COMMIT"):
                continue
            emit(
                producer,
                "ddl_or_statement",
                {"schema": binlogevent.schema, "query": query},
            )
            continue

        if isinstance(binlogevent, WriteRowsEvent):
            op = "INSERT"
        elif isinstance(binlogevent, UpdateRowsEvent):
            op = "UPDATE"
        elif isinstance(binlogevent, DeleteRowsEvent):
            op = "DELETE"
        else:
            continue

        emit(
            producer,
            "dml",
            {
                "table": f"{binlogevent.schema}.{binlogevent.table}",
                "operation": op,
                "row_count": len(binlogevent.rows),
            },
        )

    stream.close()


if __name__ == "__main__":
    kafka_producer = build_producer()
    try:
        while True:
            try:
                run(kafka_producer)
            except KeyboardInterrupt:
                break
            except Exception as exc:  # noqa: BLE001 - top-level retry loop, log and retry
                print(f"[mysql-agent] stream error: {exc}; retrying in 5s", flush=True)
                time.sleep(5)
    finally:
        kafka_producer.flush(timeout=10)
        kafka_producer.close()
"""
AI-DAMS MSSQL audit agent.

Unlike the MySQL (binlog tailing) and PostgreSQL (logical replication
streaming) agents, this one polls SQL Server Change Data Capture (CDC)
tables on an interval. SQL Server has no push-based change stream in
Standard/Developer edition without extra licensing -- polling CDC tables
is what production tools like Debezium's SQL Server connector actually
do under the hood, so this is the realistic mechanism for this engine,
not a shortcut.

Requirements this agent depends on (see mssql-init/init.sh):
- SQL Server Agent running (MSSQL_AGENT_ENABLED=true) -- CDC's capture
  job needs the Agent to populate change tables at all.
- CDC enabled at the database level (sys.sp_cdc_enable_db).
- CDC enabled per table you want audited (sys.sp_cdc_enable_table) --
  this agent auto-discovers whichever tables already have it enabled;
  it does not enable CDC on tables itself.

Same scoping decisions as the other two agents: no row values captured,
only table + operation. No authentication events, no SELECTs (CDC never
sees reads, same limitation as binlog/logical replication).
"""

import json
import os
import socket
import time
from datetime import datetime, timezone

import pymssql
from kafka import KafkaProducer

MSSQL_HOST = os.environ.get("MSSQL_HOST", "127.0.0.1")
MSSQL_PORT = int(os.environ.get("MSSQL_PORT", "1433"))
MSSQL_DB = os.environ.get("MSSQL_DB", "aidams_demo")
MSSQL_USER = os.environ.get("MSSQL_AGENT_USER", "aidams_agent")
MSSQL_PASSWORD = os.environ.get("MSSQL_AGENT_PASSWORD")

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "127.0.0.1:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "mssql.audit.events")
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "3"))

if not MSSQL_PASSWORD:
    raise RuntimeError(
        "MSSQL_AGENT_PASSWORD env var is required (matches the value in .env)"
    )

AGENT_HOST = socket.gethostname()

# CDC emits __$operation: 1=delete, 2=insert, 3=update(before), 4=update(after).
# We forward inserts/deletes and only the "after" half of updates, so each
# real change produces exactly one Kafka event -- matching the other agents.
OPERATION_MAP = {1: "DELETE", 2: "INSERT", 4: "UPDATE"}


def build_producer() -> KafkaProducer:
    return KafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, linger_ms=50)


def emit(producer: KafkaProducer, event_type: str, payload: dict) -> None:
    envelope = {
        "engine": "mssql",
        "event_type": event_type,
        "agent_host": AGENT_HOST,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    future = producer.send(KAFKA_TOPIC, value=json.dumps(envelope).encode("utf-8"))
    future.add_errback(
        lambda exc: print(f"[mssql-agent] FAILED to send {event_type}: {exc}", flush=True)
    )
    print(f"[mssql-agent] queued {event_type}: {payload}", flush=True)


def get_capture_instances(conn):
    with conn.cursor(as_dict=True) as cur:
        cur.execute(
            """
            SELECT ct.capture_instance, s.name AS schema_name, t.name AS table_name
            FROM cdc.change_tables ct
            JOIN sys.tables t ON ct.source_object_id = t.object_id
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            """
        )
        return cur.fetchall()


def poll_once(conn, producer: KafkaProducer, last_lsn_by_instance: dict) -> None:
    for inst in get_capture_instances(conn):
        capture_instance = inst["capture_instance"]
        schema = inst["schema_name"]
        table = inst["table_name"]

        with conn.cursor(as_dict=True) as cur:
            last_lsn = last_lsn_by_instance.get(capture_instance)
            if last_lsn is None:
                cur.execute(
                    "SELECT sys.fn_cdc_get_min_lsn(%s) AS lsn", (capture_instance,)
                )
                row = cur.fetchone()
                last_lsn = row["lsn"] if row else None
                if last_lsn is None:
                    continue  # capture job hasn't produced a start LSN yet

            cur.execute("SELECT sys.fn_cdc_get_max_lsn() AS lsn")
            max_lsn = cur.fetchone()["lsn"]
            if max_lsn is None or max_lsn <= last_lsn:
                last_lsn_by_instance[capture_instance] = last_lsn
                continue

            cur.execute(
                f"SELECT * FROM cdc.fn_cdc_get_all_changes_{capture_instance}"
                f"(%s, %s, 'all')",
                (last_lsn, max_lsn),
            )
            for row in cur.fetchall():
                op = OPERATION_MAP.get(row["__$operation"])
                if op is None:
                    continue  # skips the update "before" half (op == 3)
                emit(
                    producer,
                    "dml",
                    {"table": f"{schema}.{table}", "operation": op},
                )

            last_lsn_by_instance[capture_instance] = max_lsn


def run(producer: KafkaProducer) -> None:
    conn = pymssql.connect(
        server=MSSQL_HOST,
        port=MSSQL_PORT,
        database=MSSQL_DB,
        user=MSSQL_USER,
        password=MSSQL_PASSWORD,
        autocommit=True,
    )

    print(
        f"[mssql-agent] polling CDC on {MSSQL_HOST}:{MSSQL_PORT}/{MSSQL_DB} "
        f"every {POLL_INTERVAL_SECONDS}s -> publishing to '{KAFKA_TOPIC}' on {KAFKA_BOOTSTRAP}",
        flush=True,
    )

    last_lsn_by_instance: dict = {}
    while True:
        poll_once(conn, producer, last_lsn_by_instance)
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
                print(f"[mssql-agent] stream error: {exc}; retrying in 5s", flush=True)
                time.sleep(5)
    finally:
        kafka_producer.flush(timeout=10)
        kafka_producer.close()
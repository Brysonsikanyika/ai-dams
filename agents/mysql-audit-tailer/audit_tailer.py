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

ACCOUNT ATTRIBUTION (v2): an earlier version of this tailer attempted to
resolve the connecting account by adding MySQL's "connection" event class
to the audit filter and correlating Connect records by CONNECTION_ID.
That approach was abandoned -- adding the connection class caused Percona
to silently skip logging the query class entirely ("Skipping disabled
event class 'query'"), for reasons that weren't confidently diagnosed,
and the query class is the one thing this tailer actually depends on.
Rather than keep patching an unverified component interaction, this
version resolves the account a different way: a direct, live lookup
against performance_schema.threads, keyed by CONNECTION_ID, using a
dedicated minimal-privilege MySQL account (see
mysql-init/04-create-tailer-account.sh). This only needs the 'query'
class to remain enabled exactly as it always was.
"""

import json
import os
import re
import socket
import time
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import pymysql
from kafka import KafkaProducer

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/var/lib/mysql/audit_filter.log")
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "mysql.query.text")
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "2"))

MYSQL_HOST = os.environ.get("MYSQL_HOST", "mysql")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
TAILER_ACCOUNT_PASSWORD = os.environ["TAILER_ACCOUNT_PASSWORD"]

AGENT_HOST = socket.gethostname()

RECORD_RE = re.compile(r"<AUDIT_RECORD>.*?</AUDIT_RECORD>", re.DOTALL)


def build_producer() -> KafkaProducer:
    return KafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, linger_ms=50)


def build_introspection_connection():
    """A dedicated, minimal-privilege (PROCESS only, no table data access)
    connection used purely to look up which account owns a connection_id."""
    return pymysql.connect(
        host=MYSQL_HOST, port=MYSQL_PORT, user="audit_tailer_ro",
        password=TAILER_ACCOUNT_PASSWORD, autocommit=True, connect_timeout=5,
    )


def resolve_account(introspect_conn, connection_id: str, cache: dict):
    """Looks up the MySQL account for a given connection_id via
    performance_schema.threads, caching the result (connections are
    long-lived in this project's generators, so one lookup per
    connection_id is enough -- no need to re-query on every record)."""
    if connection_id in cache:
        return cache[connection_id]
    account = None
    try:
        # The introspection connection is long-lived and idle between lookups;
        # MySQL closes idle connections after wait_timeout (8h by default).
        # ping(reconnect=True) reopens it transparently. Without this, every
        # lookup after the first idle timeout failed and returned account=None.
        introspect_conn.ping(reconnect=True)
        with introspect_conn.cursor() as cur:
            cur.execute(
                "SELECT PROCESSLIST_USER FROM performance_schema.threads "
                "WHERE PROCESSLIST_ID = %s", (connection_id,),
            )
            row = cur.fetchone()
            if row and row[0]:
                account = row[0]
    except Exception as exc:  # noqa: BLE001 - introspection is best-effort
        print(f"[audit-tailer] account lookup failed for connection_id={connection_id}: {exc}", flush=True)
        return None  # transport failure: do NOT cache, so a later record retries
    cache[connection_id] = account  # cache the miss too -- avoid re-querying a closed connection every time
    return account


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
    """Returns a dict for a 'Query Start' record, or None for anything
    else (Query Status End duplicates, or a record type this tailer
    doesn't need)."""
    try:
        root = ET.fromstring(xml_fragment)
    except ET.ParseError:
        return None

    if root.findtext("NAME") != "Query Start":
        return None

    sql_text = root.findtext("SQLTEXT")
    if not sql_text:
        return None

    return {
        "command_class": root.findtext("COMMAND_CLASS"),
        "sql_text": sql_text,
        "connection_id": root.findtext("CONNECTION_ID"),
        "record_id": root.findtext("RECORD_ID"),
    }


def run(producer: KafkaProducer, introspect_conn) -> None:
    wait_for_file(AUDIT_LOG_PATH)

    account_cache = {}  # connection_id -> account (or None), see resolve_account()

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
                        account = resolve_account(introspect_conn, record["connection_id"], account_cache)
                        emit(producer, {**record, "account": account})
                    last_end = match.end()
                buffer = buffer[last_end:]  # keep only the unparsed remainder
            else:
                time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    kafka_producer = build_producer()
    introspection_conn = None
    try:
        while True:
            try:
                if introspection_conn is None:
                    introspection_conn = build_introspection_connection()
                run(kafka_producer, introspection_conn)
            except KeyboardInterrupt:
                break
            except Exception as exc:  # noqa: BLE001 - top-level retry loop, log and retry
                print(f"[audit-tailer] error: {exc}; retrying in 5s", flush=True)
                introspection_conn = None  # force reconnect next loop
                time.sleep(5)
    finally:
        kafka_producer.flush(timeout=10)
        kafka_producer.close()
        if introspection_conn:
            introspection_conn.close()

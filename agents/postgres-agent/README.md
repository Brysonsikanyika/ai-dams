# PostgreSQL Audit Agent

Tails PostgreSQL's logical replication stream via the built-in
`test_decoding` output plugin and publishes DML events to the
`postgres.audit.events` Kafka topic.

## Why `test_decoding`, not `wal2json`

`wal2json` gives cleaner JSON output but isn't bundled in the official
`postgres` Docker image -- using it would mean maintaining a custom image
just for one extra `.so` file. `test_decoding` ships with core PostgreSQL
and does the same fundamental job (turns WAL changes into a change
stream); this agent just parses its plain-text output instead of JSON.

## Scoping decision (read before extending this)

Logical replication does **not** capture:
- Authentication/connection events (same limitation as MySQL's binlog)
- SELECT statements (logical decoding never sees reads, only writes)
- Actual row values -- `test_decoding`'s output includes them, but this
  agent deliberately discards them, keeping only table + operation.

This mirrors the MySQL agent's scoping decision, for consistency across
all three engines -- see the project root README and the report's FR1
discussion.

## Setup

Requires the `aidams_agent` PostgreSQL role (created automatically by
`postgres-init/01-create-agent-role.sh` on first container init),
`wal_level=logical` (set via `command:` in docker-compose.yml), and the
`psycopg2-binary` + `kafka-python` packages.

```bash
/home/bryson/projects/ai-dams/.venv/bin/pip install -r requirements.txt
```

Run it (needs `PG_AGENT_PASSWORD` matching your `.env`, and Kafka +
PostgreSQL already up via `docker compose up -d`):

```bash
export PG_AGENT_PASSWORD=$(grep PG_AGENT_PASSWORD ../../.env | cut -d= -f2)
/home/bryson/projects/ai-dams/.venv/bin/python postgres_agent.py
```

On first run it creates a logical replication slot named `aidams_slot`;
subsequent runs reuse it and resume from where they left off.

## Verifying it works

In a second terminal:

```bash
docker exec -it aidams-postgres psql -U postgres -d aidams_demo
```
```sql
CREATE TABLE test_customers (id INT PRIMARY KEY, name VARCHAR(50));
INSERT INTO test_customers VALUES (1, 'acme corp');
UPDATE test_customers SET name = 'acme ltd' WHERE id = 1;
```

Note: `CREATE TABLE` won't produce an event -- `test_decoding` only
reports DML, not DDL. This is an asymmetry with the MySQL agent, which
does catch DDL via binlog `QueryEvent`s. Worth noting if documenting
agent behavior differences in the report.

In a third terminal, confirm the events landed in Kafka:

```bash
docker exec -it aidams-kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic postgres.audit.events --from-beginning
```
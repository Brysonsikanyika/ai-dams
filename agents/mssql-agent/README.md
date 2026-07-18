# MSSQL Audit Agent

Polls SQL Server Change Data Capture (CDC) tables on an interval and
publishes DML events to the `mssql.audit.events` Kafka topic.

## Why polling, not streaming

Unlike the MySQL (binlog tailing) and PostgreSQL (logical replication
streaming) agents, MSSQL has no push-based change stream available in
Standard/Developer edition without extra licensing. Polling CDC change
tables is what production tools like Debezium's SQL Server connector
actually do under the hood -- this is the realistic mechanism for this
engine, not a shortcut taken to save time.

One consequence: there's inherent latency between a change happening and
this agent seeing it (CDC's capture job itself has a delay reading the
transaction log, on top of this agent's own `POLL_INTERVAL_SECONDS`
default of 3s). Don't expect the near-instant detection the other two
agents show.

## Requirements (all handled by mssql-init/init.sh, except per-table CDC)

- **SQL Server Agent must be running** (`MSSQL_AGENT_ENABLED: "true"` in
  docker-compose.yml). CDC's capture and cleanup jobs depend on the
  Agent; without it, change tables silently never populate, with no
  error to explain why.
- **CDC enabled at the database level** (`sys.sp_cdc_enable_db`) -- done
  automatically by the init script.
- **CDC enabled per table you want audited** -- NOT automatic. Each
  table needs:
```sql
  EXEC sys.sp_cdc_enable_table
      @source_schema = 'dbo',
      @source_name   = '<table_name>',
      @role_name     = NULL,
      @supports_net_changes = 0;
```
  This agent auto-discovers whichever tables already have CDC enabled
  via `cdc.change_tables` on every poll cycle; it does not enable CDC on
  tables itself.

## Scoping decisions (read before extending this)

- No authentication/connection events, no SELECT statements -- CDC only
  sees data changes, same limitation as the other two agents.
- No actual row values -- only table + operation, consistent with the
  MySQL and PostgreSQL agents.
- CDC emits two rows per UPDATE (before-image and after-image). This
  agent forwards only the after-image, so one real UPDATE produces
  exactly one Kafka event, matching the other agents' behavior.
- The `aidams_agent` login was granted `db_owner` in the init script as
  an MVP shortcut -- CDC technically only needs membership in a
  per-capture-instance role that doesn't exist until a table has CDC
  enabled on it, which creates a chicken-and-egg problem for a
  one-shot init script. Scope this down before it touches anything real.

## Setup

```bash
/home/bryson/projects/ai-dams/.venv/bin/pip install -r requirements.txt
```

Run it (needs `MSSQL_AGENT_PASSWORD` matching your `.env`, and Kafka +
MSSQL already up via `docker compose up -d`):

```bash
export MSSQL_AGENT_PASSWORD=$(grep MSSQL_AGENT_PASSWORD ../../.env | cut -d= -f2)
/home/bryson/projects/ai-dams/.venv/bin/python mssql_agent.py
```

## Verifying it works

Create a table and enable CDC on it (single non-interactive `-Q`
commands are more reliable than the interactive `sqlcmd` prompt, which
has repeatedly mangled multi-line paste input):

```bash
docker exec -it aidams-mssql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$(grep MSSQL_SA_PASSWORD ../../.env | cut -d= -f2)" -C -d aidams_demo -Q "CREATE TABLE test_transactions (id INT PRIMARY KEY, amount DECIMAL(10,2));"

docker exec -it aidams-mssql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$(grep MSSQL_SA_PASSWORD ../../.env | cut -d= -f2)" -C -d aidams_demo -Q "EXEC sys.sp_cdc_enable_table @source_schema = 'dbo', @source_name = 'test_transactions', @role_name = NULL, @supports_net_changes = 0;"

docker exec -it aidams-mssql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$(grep MSSQL_SA_PASSWORD ../../.env | cut -d= -f2)" -C -d aidams_demo -Q "INSERT INTO test_transactions VALUES (1, 99.50);"
```

Give it ~10 seconds (CDC lag + poll interval), then check the agent's
own terminal for a `queued dml` line, and confirm delivery to Kafka:

```bash
docker exec -it aidams-kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic mssql.audit.events --from-beginning
```
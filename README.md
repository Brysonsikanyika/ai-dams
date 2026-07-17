# AI-DAMS — AI-Based Database Activity Monitoring System

Final-year project (ZUT, Bachelor of Cyber Security). Detects anomalous
database activity across MySQL, PostgreSQL, and MSSQL using an ensemble
of Isolation Forest, LSTM Autoencoder, and an NLP SQL-injection classifier,
streamed through Apache Kafka to a React analyst dashboard.

## Rebuild status (this scaffold)

Previous repo and Kafka config (KRaft + mTLS) were deleted after a silent
broker-exit bug that wasn't diagnosed. This scaffold rebuilds the infra
layer with **mTLS deliberately removed for now** — Kafka stays (it's in
the approved proposal scope), but runs PLAINTEXT until the broker is
proven stable. Add TLS/SASL back once `kafka` passes its healthcheck
reliably across restarts.

## Structure

```
ai-dams/
├── docker-compose.yml   # Kafka (KRaft, PLAINTEXT) + MySQL + PostgreSQL + MSSQL
├── .env.example         # copy to .env and set real passwords
├── kafka/                # topic setup scripts, later: certs/ for mTLS phase
├── agents/               # lightweight DB audit agents (one per engine)
├── ml-engine/            # Isolation Forest, LSTM Autoencoder, NLP classifier
└── dashboard/            # React analyst dashboard
```

## Getting started

```bash
cp .env.example .env        # edit passwords
docker compose up -d
docker compose ps           # all four services should report healthy
```

Verify Kafka came up clean before doing anything else:

```bash
docker compose logs kafka --tail=50
docker exec aidams-kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --list
```

If Kafka exits silently again, check in this order (most common causes
for KRaft-mode silent exits):
1. `CLUSTER_ID` mismatch against stale data in the `kafka-data` volume
   from a previous run — `docker compose down -v` to wipe and retry.
2. Listener/advertised-listener mismatch (host vs container networking).
3. Insufficient memory — Kafka's default heap can OOM-kill silently on
   constrained hosts; check `docker compose logs kafka` for an OOM line,
   not just "exited."

## VSCode

Open this folder in VSCode; it'll prompt to install the recommended
extensions (Docker, YAML, SQLTools with driver support for all three
engines, Python). The Docker extension gives you container logs,
exec-into-container, and compose up/down from the sidebar instead of
switching to a terminal for everything.

## Next steps

1. Confirm all four containers report healthy.
2. Build one audit agent (`agents/`) against MySQL first — simplest engine,
   proves the Kafka producer path end-to-end before replicating to
   PostgreSQL and MSSQL.
3. Only after the pipeline moves real events end-to-end: circle back to
   mTLS.

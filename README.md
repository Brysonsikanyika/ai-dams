# AI-DAMS — AI-Based Database Activity Monitoring System

Final-year project (ZUT, Bachelor of Cyber Security). Detects anomalous
database activity across MySQL, PostgreSQL, and MSSQL using an ensemble
of Isolation Forest, LSTM Autoencoder, and an NLP SQL-injection classifier,
streamed through Apache Kafka to a React analyst dashboard.

## Data

All data in this repository is synthetic. It is produced by a generator written for this project on a university-style schema designed by the author. No real audit logs or institutional data are used. Results show that the pipeline works end to end, not how it would perform on real traffic.

## Running the prototype

Infrastructure (Kafka, MySQL, PostgreSQL, MSSQL, MySQL audit tailer):

    cp .env.example .env   # set real passwords
    docker compose up -d && docker compose ps

Pipeline (scripts in ml-engine/data, run in this order; the evaluation uses MySQL):

1. generate_traffic_academic.py -- synthetic academic traffic, one MySQL account per student
2. train_isolation_forest.py, train_lstm_autoencoder.py, train_final_nlp_v2.py -- train the three models
3. join_nlp_scores.py -- match captured query text (Kafka topic mysql.query.text) to events and score it
4. build_risk_aggregator.py -- one risk score per customer per 15-minute bucket (max of behavioural and SQL-text risk)
5. explain_alerts.py -- plain-English reasons (SHAP for the Isolation Forest, n-gram contributions for the classifier)

Dashboard: cd dashboard-server && node server.js, then cd dashboard && npm run dev.

Scoring runs in batch; capture is live. See the dissertation for results and limits.

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

# Database Audit Agents

One lightweight agent per engine (MySQL, PostgreSQL, MSSQL). Each agent's job:
capture query events (DML, DDL, auth, stored procedures) and publish them to
Kafka as the raw input for the ML pipeline.

Target: <3% CPU overhead on the monitored server (per proposal 2.3.2).

Build order: MySQL first (simplest audit log format), then PostgreSQL
(pgaudit extension), then MSSQL (Extended Events / SQL Audit) last —
it's the heaviest engine to stand up and debug.

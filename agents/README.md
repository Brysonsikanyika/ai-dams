# Database audit capture

`mysql-audit-tailer` reads the MySQL audit log and publishes query text to Kafka topic `mysql.query.text`. The evaluated pipeline uses MySQL. See the root README for how to run it.

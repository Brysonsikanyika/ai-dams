#!/bin/bash
set -e

mysql -u root -p"${MYSQL_ROOT_PASSWORD}" <<-EOSQL
    CREATE USER IF NOT EXISTS 'aidams_agent'@'%' IDENTIFIED BY '${MYSQL_AGENT_PASSWORD}';
    GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'aidams_agent'@'%';
    FLUSH PRIVILEGES;
EOSQL

echo "[init] aidams_agent replication user created"

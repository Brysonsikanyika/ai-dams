#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB}" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aidams_agent') THEN
            CREATE ROLE aidams_agent WITH LOGIN REPLICATION PASSWORD '${PG_AGENT_PASSWORD}';
        END IF;
    END
    \$\$;
    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO aidams_agent;
EOSQL

echo "[init] aidams_agent replication role created"
#!/bin/bash
# mysql-init/04-create-tailer-account.sh
#
# Creates a dedicated, minimal-privilege MySQL account for the
# mysql-audit-tailer sidecar, used only to look up which account owns a
# given connection_id via performance_schema.threads.
#
# NOTE on privilege scope: by default, a MySQL account can only see its
# OWN session in performance_schema.threads / SHOW PROCESSLIST -- seeing
# OTHER connections' threads requires the global PROCESS privilege.
# This is a genuine, deliberate widening beyond the narrow per-table
# grants used elsewhere in this project (agents/mysql-agent's account,
# the 20 student accounts): PROCESS is a global, not per-table,
# privilege. It is still low-risk relative to the alternative -- it only
# exposes connection metadata (which account is connected, what they're
# currently running), not permission to read or write any table's data --
# but it is explicitly NOT the same least-privilege shape as this
# project's other accounts, and that distinction is worth stating
# honestly rather than glossing over.

set -e

PASSWORD="${TAILER_ACCOUNT_PASSWORD:?TAILER_ACCOUNT_PASSWORD must be set in .env}"

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS 'audit_tailer_ro'@'%' IDENTIFIED BY '${PASSWORD}';
GRANT PROCESS ON *.* TO 'audit_tailer_ro'@'%';
GRANT SELECT ON performance_schema.threads TO 'audit_tailer_ro'@'%';
GRANT SELECT ON performance_schema.threads TO 'audit_tailer_ro'@'%';
FLUSH PRIVILEGES;
SQL

echo "Created MySQL account: audit_tailer_ro (PROCESS privilege only -- no table data access)"

#!/bin/bash
# mysql-init/03-create-student-users.sh
#
# Creates one individual MySQL account per simulated student
# (student_0001 .. student_0020), each with SELECT/INSERT/UPDATE/DELETE
# on the whole academic database.
#
# This is the actual fix for the long-standing "query text can't be
# attributed to a customer" gap: Percona's audit_log_filter records the
# connecting account on every AUDIT_RECORD. One shared root connection
# (the old generate_traffic.py) made every query look identical in the
# audit log. Twenty distinct accounts means the audit log -- and
# therefore mysql-audit-tailer -- can tell them apart for real.
#
# NOTE: this grants on the whole database (DB_NAME.*), not per-table.
# An earlier version granted on each table individually, which failed --
# this script runs during container init, before generate_traffic_academic.py
# has ever run, so the academic tables (students, courses, etc.) don't
# exist yet at this point. A database-level grant covers the same tables
# once they're created, without needing them to exist first.
#
# All twenty accounts share one password (set via STUDENT_ACCOUNT_PASSWORD
# in .env) -- this is a controlled simulation, not a production system,
# so the thing that matters is twenty distinct usernames, not twenty
# distinct secrets.

set -e

N_STUDENTS=20
PASSWORD="${STUDENT_ACCOUNT_PASSWORD:?STUDENT_ACCOUNT_PASSWORD must be set in .env}"
DB_NAME="${MYSQL_DATABASE:-aidams_demo}"

for i in $(seq -w 1 $N_STUDENTS); do
  USERNAME="student_00${i}"
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS '${USERNAME}'@'%' IDENTIFIED BY '${PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON ${DB_NAME}.* TO '${USERNAME}'@'%';
SQL
  echo "Created MySQL account: ${USERNAME}"
done

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -e "FLUSH PRIVILEGES;"
echo "Done. ${N_STUDENTS} student accounts created on database ${DB_NAME}."

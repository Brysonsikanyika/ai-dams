#!/bin/bash
set -e

# Installs Percona's audit_log_filter component and scopes it to ONLY
# capture query text (class=query, event=query_start) -- deliberately not
# connections, table_access, or any other event class. This is the raw
# SQL text feed for the NLP SQL-injection classifier; nothing else needs
# to consume this log.
#
# NOTE: this is new, less-tested ground compared to 01-create-agent-user.sh.
# The exact install script path can vary by image build. If this fails,
# check the printed find result first before assuming the whole approach
# is broken.

echo "[init] locating audit_log_filter install script..."
AUDIT_INSTALL_SQL=$(find /usr/share -iname "audit_log_filter_linux_install.sql" 2>/dev/null | head -n1)

if [ -z "$AUDIT_INSTALL_SQL" ]; then
    echo "[init] WARNING: audit_log_filter_linux_install.sql not found under /usr/share."
    echo "[init] Listing anything audit-related found on the image, for debugging:"
    find / -iname "*audit_log_filter*" 2>/dev/null || true
    echo "[init] Skipping audit log filter setup -- fix the path above and rerun."
    exit 0
fi

echo "[init] found install script at: $AUDIT_INSTALL_SQL"
echo "[init] installing audit_log_filter component..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" < "$AUDIT_INSTALL_SQL"

echo "[init] verifying component installed..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT * FROM mysql.component;"

echo "[init] setting event_mode=FULL -- default REDUCED mode disables the 'query' class entirely, which isn't documented anywhere obvious and cost real debugging time to find."
# MUST use SET PERSIST, not SET GLOBAL. The Docker entrypoint runs this
# script against a TEMPORARY bootstrap mysqld instance, then discards it
# and starts the real long-running server fresh. SET GLOBAL only affects
# that temporary instance -- the setting is silently lost on handoff, and
# event_mode reverts to REDUCED on the real server, disabling the 'query'
# class even though the filter/user assignments (actual table rows) persist
# correctly. This exact failure mode cost real debugging time to diagnose:
# filter and user assignment were both configured correctly and nothing
# was logging, because event_mode had quietly reverted.
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SET PERSIST audit_log_filter.event_mode = 'FULL';"

echo "[init] creating scoped filter (query class -- NOT nesting an 'event' sub-filter, which produces 'Wrong argument: incorrect rule definition')..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT audit_log_filter_set_filter('aidams_query_filter', '{\"filter\": {\"class\": {\"name\": \"query\"}}}');"

echo "[init] assigning filter to all users..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT audit_log_filter_set_user('%', 'aidams_query_filter');"

echo "[init] configuring JSON output format and log file path..."
# NOTE: these use the component's namespaced variable names
# (audit_log_filter.format / audit_log_filter.file, WITH DOTS) -- not the
# old deprecated plugin's audit_log_format/audit_log_file. The component's
# variables also don't exist as startup flags until the component has been
# installed at least once, which is why this happens here via SET GLOBAL,
# not in docker-compose.yml's command line.
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SET GLOBAL audit_log_filter.format = 'JSON';" || echo "[init] WARNING: could not set audit_log_filter.format -- may need to be set at next server startup instead"
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SET GLOBAL audit_log_filter.file = '/var/lib/mysql/audit.log';" || echo "[init] WARNING: could not set audit_log_filter.file -- may need to be set at next server startup instead"

echo "[init] current audit_log_filter variable state (verify the above actually took effect):"
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SHOW VARIABLES LIKE 'audit_log_filter%';"

echo "[init] audit log filter configured -- check the variable output above to confirm format=JSON and file path are correct before assuming query text is being captured"
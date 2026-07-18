#!/bin/bash
set -e

echo "[init] waiting a moment for SQL Server to be fully ready for connections..."
sleep 5

SQLCMD="/opt/mssql-tools18/bin/sqlcmd -S mssql -U sa -P $MSSQL_SA_PASSWORD -C"

echo "[init] ensuring aidams_demo database exists..."
$SQLCMD -Q "IF DB_ID('aidams_demo') IS NULL CREATE DATABASE aidams_demo;"

echo "[init] enabling CDC at the database level..."
$SQLCMD -d aidams_demo -Q "
IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = 'aidams_demo' AND is_cdc_enabled = 1)
BEGIN
    EXEC sys.sp_cdc_enable_db;
END
"

echo "[init] creating aidams_agent login..."
$SQLCMD -Q "
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'aidams_agent')
BEGIN
    CREATE LOGIN aidams_agent WITH PASSWORD = '$MSSQL_AGENT_PASSWORD';
END
"

echo "[init] creating aidams_agent database user..."
$SQLCMD -d aidams_demo -Q "
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'aidams_agent')
BEGIN
    CREATE USER aidams_agent FOR LOGIN aidams_agent;
    ALTER ROLE db_owner ADD MEMBER aidams_agent;
END
"

echo "[init] aidams_demo ready, CDC enabled, aidams_agent configured"
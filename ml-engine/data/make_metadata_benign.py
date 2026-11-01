"""
Benign metadata / client-housekeeping statements for the SQL-injection classifier.

Why: the v2 benign data holds academic-catalogue queries only, so statements a
database client sends on its own (SHOW DATABASES, SELECT DATABASE(), ...) scored
above the alert cutoff in the live test (6 of 8 live alerts).

Whole statement families are split: TRAIN families feed the training and
calibration sets; HELDOUT families are used only to measure false alarms on
statement types the model never saw. information_schema queries are NOT added as
benign, because injection enumeration uses them.
"""
import csv
TABLES = ["students", "grades", "courses", "fees", "enrolments", "library_loans", "payments", "staff", "modules", "timetable"]
DB = "aidams_demo"
TRAIN_FAMILIES = {
    "show_databases": ["SHOW DATABASES"],
    "show_tables": ["SHOW TABLES", "SHOW FULL TABLES", f"SHOW TABLES FROM {DB}"],
    "show_columns": [f"SHOW COLUMNS FROM {t}" for t in TABLES] + [f"SHOW FULL COLUMNS FROM {t}" for t in TABLES],
    "describe": [f"DESCRIBE {t}" for t in TABLES] + [f"DESC {t}" for t in TABLES],
    "show_create": [f"SHOW CREATE TABLE {t}" for t in TABLES],
    "show_index": [f"SHOW INDEX FROM {t}" for t in TABLES],
    "use_db": [f"USE {DB}"],
    "select_database": ["SELECT DATABASE()"],
    "version_comment": ["select @@version_comment limit 1"],
    "select_info": ["SELECT VERSION()", "SELECT USER()", "SELECT CURRENT_USER()", "SELECT CONNECTION_ID()"],
    "select_now": ["SELECT NOW()", "SELECT CURRENT_TIMESTAMP", "SELECT 1"],
    "set_names": ["SET NAMES utf8", "SET NAMES utf8mb4", "SET NAMES latin1"],
    "set_autocommit": ["SET autocommit=1", "SET autocommit=0"],
    "transaction": ["START TRANSACTION", "COMMIT", "ROLLBACK", "BEGIN"],
}
HELDOUT_FAMILIES = {
    "show_variables": [f"SHOW VARIABLES LIKE '{v}'" for v in ("version%", "character_set%", "collation%", "max_connections", "wait_timeout")],
    "show_status": ["SHOW STATUS", "SHOW GLOBAL STATUS LIKE 'Threads%'", "SHOW STATUS LIKE 'Uptime'"],
    "show_processlist": ["SHOW PROCESSLIST", "SHOW FULL PROCESSLIST"],
    "show_grants": ["SHOW GRANTS", "SHOW GRANTS FOR CURRENT_USER()"],
    "show_misc": ["SHOW WARNINGS", "SHOW ERRORS", "SHOW ENGINES", "SHOW CHARACTER SET", "SHOW COLLATION", "SHOW TABLE STATUS"],
    "select_sysvar": [f"SELECT @@{v}" for v in ("sql_mode", "autocommit", "max_allowed_packet", "time_zone", "version", "session.time_zone", "global.max_connections")] + ["SELECT @@character_set_client, @@collation_connection"],
    "set_session": ["SET time_zone = '+00:00'", "SET SESSION sql_mode='STRICT_TRANS_TABLES'", "SET SQL_SELECT_LIMIT=1000", "SET character_set_results = NULL", "SET sql_safe_updates=1"],
    "explain": [f"EXPLAIN SELECT * FROM {t} WHERE id = 1" for t in TABLES],
}


def rows(fams, variants, prefix):
    out = []
    for fam, base in fams.items():
        seen = set()
        for b in base:
            for v in variants:
                q = v(b)
                if q not in seen:
                    seen.add(q)
                    out.append((q, 0, f"{prefix}:{fam}"))
    return out


def w(path, data):
    with open(path, "w", newline="") as f:
        cw = csv.writer(f)
        cw.writerow(["query_text", "label", "source"])
        cw.writerows(data)
    print(path, len(data))


train = rows(TRAIN_FAMILIES, [str.lower, str.upper], "meta")          # no semicolon; lower and upper case
calib = rows(TRAIN_FAMILIES, [lambda s: s, lambda s: s + ";"], "calibmeta")   # as written; with semicolon
held = rows(HELDOUT_FAMILIES, [lambda s: s, str.lower], "heldmeta")
w("meta_train.csv", train)
w("meta_calib.csv", calib)
w("meta_heldout.csv", held)

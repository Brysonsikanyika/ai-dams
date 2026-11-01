"""
Exact-match allow-list of client housekeeping statements, applied before the
SQL-injection classifier in the live scorer. Retraining the classifier on such
statements did not separate them from attacks (see eval_nlp_v2.py), so they are
skipped by rule. Patterns are anchored: a statement with anything extra (a second
statement, a trailing payload, a comment) does not match and is still scored.
"""
import re

_PATTERNS = [
    r"SHOW (FULL )?(DATABASES|TABLES|PROCESSLIST)( FROM \w+)?",
    r"SHOW (FULL )?(COLUMNS|FIELDS|INDEX|INDEXES|KEYS) FROM \w+",
    r"SHOW CREATE TABLE \w+",
    r"SHOW (GLOBAL |SESSION )?(STATUS|VARIABLES)( LIKE '[\w%.]+')?",
    r"SHOW (WARNINGS|ERRORS|ENGINES|CHARACTER SET|COLLATION|TABLE STATUS|GRANTS)",
    r"SHOW GRANTS FOR CURRENT_USER\(\)",
    r"(DESCRIBE|DESC) \w+",
    r"USE \w+",
    r"SELECT (DATABASE|VERSION|USER|CURRENT_USER|CONNECTION_ID|NOW)\(\)",
    r"SELECT (CURRENT_TIMESTAMP|1)",
    r"SELECT @@[\w.]+( ?, ?@@[\w.]+)*( LIMIT 1)?",
    r"SET NAMES \w+",
    r"SET (SESSION )?(autocommit|sql_safe_updates|SQL_SELECT_LIMIT) ?= ?\d+",
    r"SET (SESSION )?(time_zone|sql_mode|character_set_results) ?= ?('[+\-\w:,]+'|NULL)",
    r"(START TRANSACTION|COMMIT|ROLLBACK|BEGIN)",
    r"EXPLAIN SELECT \* FROM \w+ WHERE id = \d+",
]
_RE = re.compile(r"(?:" + "|".join(_PATTERNS) + r")", re.IGNORECASE)


def is_housekeeping(sql: str) -> bool:
    s = (sql or "").strip()
    if s.endswith(";"):
        s = s[:-1].rstrip()
    return bool(_RE.fullmatch(s))

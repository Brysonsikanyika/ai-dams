"""
AI-DAMS: generates a labeled SQL query corpus for training the NLP
SQL-injection classifier -- benign queries paired with injection payloads
across several well-known attack categories.

This is NOT built by attacking a live application. There's no vulnerable
app layer here to exploit, and the classifier only needs query TEXT plus
a label, not a successful exploit outcome. Output is a flat CSV:
query_text, label (0=benign, 1=malicious), category.

Benign templates deliberately include some structures that superficially
resemble injection patterns (e.g. legitimate 'OR' in a WHERE clause) so
the classifier can't just learn a trivial "contains OR" shortcut instead
of real injection structure.
"""

import csv
import random

random.seed(42)

TABLES = ["customers", "orders", "sessions", "test_orders", "test_customers", "test_transactions"]
COLUMNS = ["id", "name", "item", "amount", "email", "status"]
WORDS = ["acme", "widget", "gadget", "smith", "corp", "ltd", "jane", "john", "test"]

# --- Benign query templates ---------------------------------------------

BENIGN_TEMPLATES = [
    "SELECT * FROM {t} WHERE id = {i}",
    "SELECT {c} FROM {t} WHERE {c} = '{v}'",
    "SELECT * FROM {t} WHERE status = 'active' OR status = 'pending'",
    "INSERT INTO {t} ({c}) VALUES ('{v}')",
    "UPDATE {t} SET {c} = '{v}' WHERE id = {i}",
    "DELETE FROM {t} WHERE id = {i}",
    "SELECT * FROM {t} WHERE amount > {i} AND amount < {i2}",
    "SELECT * FROM {t} ORDER BY {c} DESC LIMIT 10",
    "SELECT COUNT(*) FROM {t} WHERE {c} IS NOT NULL",
    "SELECT * FROM {t} WHERE name LIKE '%{v}%'",
]


def gen_benign(n):
    rows = []
    for _ in range(n):
        tmpl = random.choice(BENIGN_TEMPLATES)
        q = tmpl.format(
            t=random.choice(TABLES),
            c=random.choice(COLUMNS),
            v=random.choice(WORDS),
            i=random.randint(1, 1000),
            i2=random.randint(1000, 5000),
        )
        rows.append((q, 0, "benign"))
    return rows


# --- Malicious payload templates, grouped by attack category -----------

CATEGORIES = {
    "tautology": [
        "SELECT * FROM {t} WHERE id = {i} OR '1'='1'",
        "SELECT * FROM {t} WHERE name = '' OR 1=1--",
        "SELECT * FROM {t} WHERE id = {i} OR 'a'='a'",
        "' OR '1'='1",
        "' OR 1=1#",
        "admin' OR '1'='1'--",
    ],
    "union_based": [
        "SELECT * FROM {t} WHERE id = {i} UNION SELECT username, password FROM users--",
        "' UNION SELECT NULL, NULL, NULL--",
        "SELECT {c} FROM {t} WHERE id = -1 UNION SELECT table_name, NULL FROM information_schema.tables--",
        "' UNION SELECT @@version--",
    ],
    "comment_bypass": [
        "admin'--",
        "admin'#",
        "' OR ''='",
        "SELECT * FROM {t} WHERE name = 'admin'--' AND password = '{v}'",
    ],
    "stacked_queries": [
        "{v}; DROP TABLE {t};--",
        "1; DELETE FROM {t};--",
        "'; INSERT INTO {t} VALUES ('hacked');--",
    ],
    "blind_time_based": [
        "SELECT * FROM {t} WHERE id = {i} AND SLEEP(5)",
        "'; WAITFOR DELAY '0:0:5'--",
        "SELECT * FROM {t} WHERE id = {i} AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(3)",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ],
    "error_based": [
        "' AND extractvalue(1, concat(0x7e, (SELECT version())))--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "SELECT * FROM {t} WHERE id = {i} AND updatexml(1, concat(0x7e, database()), 1)--",
    ],
}


def gen_malicious(n_per_category):
    rows = []
    for category, templates in CATEGORIES.items():
        for _ in range(n_per_category):
            tmpl = random.choice(templates)
            q = tmpl.format(
                t=random.choice(TABLES),
                c=random.choice(COLUMNS),
                v=random.choice(WORDS),
                i=random.randint(1, 1000),
            )
            rows.append((q, 1, category))
    return rows


def main():
    benign = gen_benign(600)
    malicious = gen_malicious(100)  # 6 categories x 100 = 600, roughly balanced
    all_rows = benign + malicious
    random.shuffle(all_rows)

    out_path = "sqli_corpus.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["query_text", "label", "category"])
        writer.writerows(all_rows)

    print(f"Wrote {len(all_rows)} rows to {out_path}: {len(benign)} benign, {len(malicious)} malicious")
    print(f"Malicious categories: {list(CATEGORIES.keys())}")


if __name__ == "__main__":
    main()
"""
AI-DAMS structured traffic generator (MySQL only, proof of concept).

Simulates a small e-commerce-style workload against aidams_demo (customers,
orders, sessions) to produce volume for training the Isolation Forest and
LSTM Autoencoder models.

IMPORTANT: the MySQL binlog agent deliberately does NOT capture row values
or query text for DML (see agents/mysql-agent's scoping notes) -- it only
captures table/operation/row_count. That means individual Kafka events
CANNOT be correlated back to a specific event generated here. This
script's own ground_truth.csv IS the training dataset; running traffic
through MySQL -> Kafka separately proves the live pipeline handles real
volume, but is not how the labeled training set gets built.

Simulated time is compressed -- events execute as fast as MySQL can
handle, NOT spread across real wall-clock hours/days. Each event carries
a SIMULATED timestamp (in ground_truth.csv) distinct from the real
execution time Kafka will record. Downstream feature engineering should
use the simulated timestamp for time-of-day features, not Kafka's
captured_at.
"""

import csv
import os
import random
from datetime import datetime, timedelta

import pymysql

random.seed(7)

MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = "root"
MYSQL_PASSWORD = os.environ.get("MYSQL_ROOT_PASSWORD")
MYSQL_DB = "aidams_demo"

N_CUSTOMERS = 20
N_EVENTS = 5000
ANOMALY_RATE = 0.10
SIMULATED_DAYS = 7

GROUND_TRUTH_PATH = "ground_truth.csv"

if not MYSQL_PASSWORD:
    raise RuntimeError(
        "MYSQL_ROOT_PASSWORD env var required -- run with: "
        "MYSQL_ROOT_PASSWORD=$(grep MYSQL_ROOT_PASSWORD ../../.env | cut -d= -f2) python3 generate_traffic.py"
    )

ITEMS = ["widget", "gadget", "sprocket", "bolt", "gizmo"]
STATUSES = ["pending", "shipped", "delivered", "cancelled"]


def connect():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        autocommit=True,
    )


def setup_schema(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(50),
                email VARCHAR(100),
                created_at DATETIME
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id INT PRIMARY KEY AUTO_INCREMENT,
                customer_id INT,
                item VARCHAR(50),
                amount DECIMAL(10,2),
                status VARCHAR(20),
                created_at DATETIME
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INT PRIMARY KEY AUTO_INCREMENT,
                customer_id INT,
                login_at DATETIME,
                ip_address VARCHAR(45)
            )
            """
        )


def seed_customers(conn, n):
    names = [
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
        "ivan", "judy", "mallory", "niaj", "olivia", "peggy", "quinn",
        "romeo", "sybil", "trent", "uma", "victor",
    ]
    ids = []
    with conn.cursor() as cur:
        for i in range(n):
            name = names[i % len(names)]
            cur.execute(
                "INSERT INTO customers (name, email, created_at) VALUES (%s, %s, %s)",
                (name, f"{name}{i}@example.com", datetime.now()),
            )
            ids.append(cur.lastrowid)
    return ids


def random_simulated_timestamp(start):
    day_offset = random.uniform(0, SIMULATED_DAYS)
    hour = int(random.betavariate(2, 2) * 24)  # roughly clustered around mid-day
    minute = random.randint(0, 59)
    return start + timedelta(days=day_offset, hours=hour, minutes=minute)
def normal_event(conn, customer_id, writer, sim_ts) -> int:
    kind = random.choices(
        ["select_orders", "select_sessions", "insert_order", "update_order", "insert_session"],
        weights=[35, 20, 25, 10, 10],
    )[0]

    with conn.cursor() as cur:
        if kind == "select_orders":
            cur.execute("SELECT * FROM orders WHERE customer_id = %s", (customer_id,))
            table, op = "orders", "SELECT"
        elif kind == "select_sessions":
            cur.execute("SELECT * FROM sessions WHERE customer_id = %s", (customer_id,))
            table, op = "sessions", "SELECT"
        elif kind == "insert_order":
            cur.execute(
                "INSERT INTO orders (customer_id, item, amount, status, created_at) VALUES (%s,%s,%s,%s,%s)",
                (customer_id, random.choice(ITEMS), round(random.uniform(5, 500), 2), "pending", datetime.now()),
            )
            table, op = "orders", "INSERT"
        elif kind == "update_order":
            cur.execute(
                "UPDATE orders SET status = %s WHERE customer_id = %s ORDER BY id DESC LIMIT 1",
                (random.choice(STATUSES), customer_id),
            )
            table, op = "orders", "UPDATE"
        else:
            cur.execute(
                "INSERT INTO sessions (customer_id, login_at, ip_address) VALUES (%s,%s,%s)",
                (customer_id, datetime.now(), f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"),
            )
            table, op = "sessions", "INSERT"

    writer.writerow([sim_ts.isoformat(), customer_id, table, op, 0, ""])
    return 1


def anomaly_burst(conn, customer_ids, writer, sim_ts) -> int:
    anomaly_type = random.choice(
        ["bulk_scan", "off_hours_bulk_delete", "high_frequency_burst", "unusual_table_combo"]
    )
    actor = random.choice(customer_ids)
    written = 0

    if anomaly_type == "bulk_scan":
        # one connection querying many OTHER customers' orders -- not their own
        targets = random.sample(customer_ids, k=min(8, len(customer_ids)))
        with conn.cursor() as cur:
            for target in targets:
                cur.execute("SELECT * FROM orders WHERE customer_id = %s", (target,))
        for _ in targets:
            writer.writerow([sim_ts.isoformat(), actor, "orders", "SELECT", 1, anomaly_type])
            written += 1

    elif anomaly_type == "off_hours_bulk_delete":
        with conn.cursor() as cur:
            for _ in range(5):
                cur.execute(
                    "DELETE FROM orders WHERE customer_id = %s ORDER BY id ASC LIMIT 1", (actor,)
                )
        for _ in range(5):
            writer.writerow([sim_ts.isoformat(), actor, "orders", "DELETE", 1, anomaly_type])
            written += 1

    elif anomaly_type == "high_frequency_burst":
        with conn.cursor() as cur:
            for _ in range(30):
                cur.execute(
                    "INSERT INTO orders (customer_id, item, amount, status, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (actor, random.choice(ITEMS), round(random.uniform(5, 500), 2), "pending", datetime.now()),
                )
        for _ in range(30):
            writer.writerow([sim_ts.isoformat(), actor, "orders", "INSERT", 1, anomaly_type])
            written += 1

    else:  # unusual_table_combo
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM customers WHERE id = %s", (actor,))
            cur.execute("SELECT * FROM orders WHERE customer_id = %s", (actor,))
            cur.execute("SELECT * FROM sessions WHERE customer_id = %s", (actor,))
        for table in ("customers", "orders", "sessions"):
            writer.writerow([sim_ts.isoformat(), actor, table, "SELECT", 1, anomaly_type])
            written += 1

    return written


def main():
    conn = connect()
    setup_schema(conn)
    customer_ids = seed_customers(conn, N_CUSTOMERS)
    print(f"Seeded {len(customer_ids)} customers")

    start = datetime.now() - timedelta(days=SIMULATED_DAYS)

    with open(GROUND_TRUTH_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["simulated_timestamp", "customer_id", "table", "operation", "is_anomaly", "anomaly_type"]
        )

        generated = 0
        anomaly_events = 0
        anomaly_budget = int(N_EVENTS * ANOMALY_RATE)  # target ~10% of EVENTS, not rounds
        while generated < N_EVENTS:
            sim_ts = random_simulated_timestamp(start)
            want_anomaly = anomaly_events < anomaly_budget and random.random() < ANOMALY_RATE
            if want_anomaly:
                count = anomaly_burst(conn, customer_ids, writer, sim_ts)
                generated += count
                anomaly_events += count
            else:
                customer_id = random.choice(customer_ids)
                generated += normal_event(conn, customer_id, writer, sim_ts)

            if generated % 500 < 5:
                print(f"...{generated}/{N_EVENTS} events generated")

    print(
        f"Done. Wrote {GROUND_TRUTH_PATH}: {generated} total events, "
        f"{anomaly_events} anomalous ({anomaly_events / generated:.1%}). "
        f"Real DB traffic executed against {MYSQL_DB} -- check Kafka topics for live pipeline volume."
    )


if __name__ == "__main__":
    main()
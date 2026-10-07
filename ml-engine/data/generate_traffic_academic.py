"""
AI-DAMS academic traffic generator (v2 architecture).

Replaces the earlier e-commerce generator (customers/orders/products)
with ZUT-style academic tables, and replaces the single shared root
connection with one real MySQL connection per simulated student. The
second change is the actual point: Percona's audit_log_filter records
the connecting account on every query, so twenty distinct accounts
means the audit log can now genuinely distinguish which student ran
which query -- not just in this script's own ground_truth.csv, but in
MySQL's own audit trail, which is what mysql-audit-tailer reads.

ground_truth.csv keeps the same column names used throughout the ML
pipeline (customer_id, target_customer_id, table, operation,
is_anomaly, anomaly_type) so train_isolation_forest.py,
train_lstm_autoencoder.py, and build_risk_aggregator.py all keep
working unchanged -- customer_id now holds a student_id value instead
of a numeric customer id, which every downstream script treats as an
opaque identifier anyway.

REQUIRES: schema.sql already applied, and the 20 student MySQL
accounts already created via mysql-init/03-create-student-users.sh,
before this script is run.
"""

import csv
import os
import random
from datetime import datetime, timedelta

import pymysql

random.seed(7)

MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_DB = os.environ.get("MYSQL_DATABASE", "aidams_demo")
MYSQL_ROOT_PASSWORD = os.environ["MYSQL_ROOT_PASSWORD"]
STUDENT_ACCOUNT_PASSWORD = os.environ["STUDENT_ACCOUNT_PASSWORD"]

N_STUDENTS = 20
N_EVENTS = 5000
ANOMALY_RATE = 0.106
SIMULATED_DAYS = 21
GROUND_TRUTH_PATH = "ground_truth.csv"

PROGRAMMES = [
    "Bachelor of Cyber Security",
    "Bachelor of Computer Science",
    "Bachelor of Information Technology",
]
COURSES = [
    ("CSC301", "Database Security", 3), ("CSC302", "Network Defence", 3),
    ("CSC210", "Data Structures", 4), ("CSC401", "Machine Learning", 3),
    ("CSC115", "Introduction to Programming", 4), ("CSC320", "Operating Systems", 3),
    ("CSC250", "Web Application Security", 3), ("CSC330", "Cryptography", 3),
]
FEE_TYPES = ["tuition", "accommodation", "registration"]
LIBRARY_TITLES = [
    "Applied Cryptography", "Database System Concepts", "Computer Networking: A Top-Down Approach",
    "Introduction to Algorithms", "The Web Application Hacker's Handbook", "Operating System Concepts",
]


def root_connect():
    return pymysql.connect(
        host=MYSQL_HOST, port=MYSQL_PORT, user="root", password=MYSQL_ROOT_PASSWORD,
        database=MYSQL_DB, autocommit=True,
    )


def student_connect(student_id):
    # student_id looks like '2300001' .. '2300020'; the MySQL accounts
    # created by mysql-init/03-create-student-users.sh are named
    # student_0001 .. student_0020 -- derive the username from the last
    # two digits of student_id rather than the student_id itself.
    username = 'student_00' + student_id[-2:]
    return pymysql.connect(
        host=MYSQL_HOST, port=MYSQL_PORT, user=username, password=STUDENT_ACCOUNT_PASSWORD,
        database=MYSQL_DB, autocommit=True,
    )


def setup_schema(conn):
    with open("schema.sql") as f:
        sql = f.read()
    with conn.cursor() as cur:
        for statement in sql.split(";"):
            statement = statement.strip()
            if statement:
                cur.execute(statement)


def seed_students_and_courses(conn):
    student_ids = []
    with conn.cursor() as cur:
        for i in range(1, N_STUDENTS + 1):
            sid = f"23000{i:02d}"
            student_ids.append(sid)
            cur.execute(
                "INSERT INTO students (student_id, first_name, last_name, programme, year_of_study, status) "
                "VALUES (%s, %s, %s, %s, %s, 'active')",
                (sid, f"Student{i}", f"Surname{i}", random.choice(PROGRAMMES), random.randint(1, 4)),
            )
        for code, name, hours in COURSES:
            cur.execute(
                "INSERT INTO courses (course_code, course_name, credit_hours, programme) VALUES (%s, %s, %s, %s)",
                (code, name, hours, random.choice(PROGRAMMES)),
            )
    return student_ids


def random_simulated_timestamp(start):
    return start + timedelta(
        days=random.uniform(0, SIMULATED_DAYS),
        hours=random.uniform(0, 24),
        seconds=random.uniform(0, 60),
    )


def normal_event(student_conn, student_id, writer, sim_ts) -> int:
    kind = random.choice(["check_grades", "check_fees", "pay_fee", "enroll", "library"])
    with student_conn.cursor() as cur:
        if kind == "check_grades":
            cur.execute("SELECT * FROM grades WHERE student_id = %s", (student_id,))
            table, op = "grades", "SELECT"
        elif kind == "check_fees":
            cur.execute("SELECT * FROM fees WHERE student_id = %s", (student_id,))
            table, op = "fees", "SELECT"
        elif kind == "pay_fee":
            cur.execute(
                "INSERT INTO payments (student_id, amount, payment_date, method) VALUES (%s,%s,%s,%s)",
                (student_id, round(random.uniform(200, 3000), 2), datetime.now(), random.choice(["mobile_money", "bank_transfer"])),
            )
            table, op = "payments", "INSERT"
        elif kind == "enroll":
            course_code = random.choice(COURSES)[0]
            cur.execute(
                "INSERT INTO enrollments (student_id, course_code, academic_period, enrolled_at) VALUES (%s,%s,%s,%s)",
                (student_id, course_code, "S2 2026", datetime.now()),
            )
            table, op = "enrollments", "INSERT"
        else:
            cur.execute(
                "INSERT INTO library_loans (student_id, item_title, checkout_date, due_date) VALUES (%s,%s,%s,%s)",
                (student_id, random.choice(LIBRARY_TITLES), datetime.now(), (datetime.now() + timedelta(days=14)).date()),
            )
            table, op = "library_loans", "INSERT"
    writer.writerow([sim_ts.isoformat(), student_id, student_id, table, op, 0, ""])
    return 1


def anomaly_burst(connections, student_ids, writer, sim_ts) -> int:
    anomaly_type = random.choice(
        ["bulk_scan", "off_hours_bulk_delete", "high_frequency_burst", "unusual_table_combo"]
    )
    actor = random.choice(student_ids)
    actor_conn = connections[actor]
    written = 0

    if anomaly_type == "bulk_scan":
        # The one case where target != actor: one student's own MySQL
        # account querying many OTHER students' grades and fee records
        # -- exactly the pattern a curious or malicious student might
        # attempt, and now genuinely visible in the real audit log as
        # ONE account running many cross-student lookups.
        targets = random.sample([s for s in student_ids if s != actor], k=min(8, len(student_ids) - 1))
        with actor_conn.cursor() as cur:
            for target in targets:
                cur.execute("SELECT * FROM grades WHERE student_id = %s", (target,))
        for target in targets:
            writer.writerow([sim_ts.isoformat(), actor, target, "grades", "SELECT", 1, anomaly_type])
            written += 1

    elif anomaly_type == "off_hours_bulk_delete":
        with actor_conn.cursor() as cur:
            for _ in range(5):
                cur.execute(
                    "DELETE FROM payments WHERE student_id = %s ORDER BY id ASC LIMIT 1", (actor,)
                )
        for _ in range(5):
            writer.writerow([sim_ts.isoformat(), actor, actor, "payments", "DELETE", 1, anomaly_type])
            written += 1

    elif anomaly_type == "high_frequency_burst":
        with actor_conn.cursor() as cur:
            for _ in range(30):
                cur.execute(
                    "INSERT INTO library_loans (student_id, item_title, checkout_date, due_date) VALUES (%s,%s,%s,%s)",
                    (actor, random.choice(LIBRARY_TITLES), datetime.now(), (datetime.now() + timedelta(days=14)).date()),
                )
        for _ in range(30):
            writer.writerow([sim_ts.isoformat(), actor, actor, "library_loans", "INSERT", 1, anomaly_type])
            written += 1

    else:  # unusual_table_combo
        with actor_conn.cursor() as cur:
            cur.execute("SELECT * FROM students WHERE student_id = %s", (actor,))
            cur.execute("SELECT * FROM fees WHERE student_id = %s", (actor,))
            cur.execute("SELECT * FROM library_loans WHERE student_id = %s", (actor,))
        for table in ("students", "fees", "library_loans"):
            writer.writerow([sim_ts.isoformat(), actor, actor, table, "SELECT", 1, anomaly_type])
            written += 1

    return written


def main():
    root_conn = root_connect()
    print("Applying schema...")
    setup_schema(root_conn)
    student_ids = seed_students_and_courses(root_conn)
    print(f"Seeded {len(student_ids)} students and {len(COURSES)} courses")
    root_conn.close()

    print("Opening one MySQL connection per student (this is the attribution fix)...")
    connections = {sid: student_connect(sid) for sid in student_ids}

    start = datetime.now() - timedelta(days=SIMULATED_DAYS)

    with open(GROUND_TRUTH_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["simulated_timestamp", "customer_id", "target_customer_id",
             "table", "operation", "is_anomaly", "anomaly_type"]
        )

        generated = 0
        anomaly_events = 0
        anomaly_budget = int(N_EVENTS * ANOMALY_RATE)
        while generated < N_EVENTS:
            sim_ts = random_simulated_timestamp(start)
            want_anomaly = anomaly_events < anomaly_budget and random.random() < ANOMALY_RATE
            if want_anomaly:
                count = anomaly_burst(connections, student_ids, writer, sim_ts)
                generated += count
                anomaly_events += count
            else:
                sid = random.choice(student_ids)
                generated += normal_event(connections[sid], sid, writer, sim_ts)

            if generated % 500 < 5:
                print(f"...{generated}/{N_EVENTS} events generated")

    for conn in connections.values():
        conn.close()

    print(
        f"Done. Wrote {GROUND_TRUTH_PATH}: {generated} total events, "
        f"{anomaly_events} anomalous ({anomaly_events / generated:.1%}). "
        f"Each event was executed through that student's OWN MySQL account -- "
        f"check the Percona audit log to confirm distinct accounts appear."
    )


if __name__ == "__main__":
    main()

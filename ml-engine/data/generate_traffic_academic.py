"""
AI-DAMS academic traffic generator (v3).

One real MySQL connection per simulated student, so the audit log can tell
students apart. Every statement carries an event-id comment tag that is also
written to ground_truth.csv, so a captured query can be matched to its exact
ground-truth row (see the tagging note below).

v3 adds, over v2:
  * a wider benign workload (academic_workload.BENIGN_KINDS: 17 kinds, with
    JOINs, aggregates, BETWEEN, NOW(), CURDATE(), LIKE, UPDATE, apostrophe
    names) -- v2 sent only 8 trivial shapes, too few to measure a text
    classifier's false-positive rate;
  * SQL-injection probes (academic_workload.INJECTION_PAYLOADS), sent as
    isolated single events. Each is behaviourally ordinary -- one SELECT on one
    table at its own timestamp -- so only the query TEXT distinguishes it.
    That is the case the NLP model exists for; it is not claimed that every
    real attack looks like this (an automated scanner firing bursts would also
    trip the behavioural models);
  * a `detail` column: the benign kind, or the injection payload family.

ground_truth.csv keeps the column names used by the ML pipeline
(customer_id, target_customer_id, table, operation, is_anomaly,
anomaly_type) and appends event_id and detail, so train_isolation_forest.py,
train_lstm_autoencoder.py and build_risk_aggregator.py read it unchanged.
customer_id holds a student_id value.

REQUIRES: schema.sql applied by this script, the 20 student MySQL accounts
(mysql-init/03-create-student-users.sh), and academic_workload.py alongside.
"""

import csv
import os
import random
import uuid
from datetime import datetime, timedelta

import pymysql

from academic_workload import (
    BENIGN_KINDS, COURSES, INJECTION_CONTEXTS, INJECTION_PAYLOADS, LIBRARY_TITLES,
)

random.seed(7)

MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_DB = os.environ.get("MYSQL_DATABASE", "aidams_demo")
MYSQL_ROOT_PASSWORD = os.environ["MYSQL_ROOT_PASSWORD"]
STUDENT_ACCOUNT_PASSWORD = os.environ["STUDENT_ACCOUNT_PASSWORD"]

N_STUDENTS = 20
N_EVENTS = 5000
ANOMALY_RATE = 0.106      # behavioural anomaly bursts, as a share of events
INJECTION_RATE = 0.03     # injection probes, as a share of events
SIMULATED_DAYS = 21
GROUND_TRUTH_PATH = "ground_truth.csv"

PROGRAMMES = [
    "Bachelor of Cyber Security",
    "Bachelor of Computer Science",
    "Bachelor of Information Technology",
]


def root_connect():
    return pymysql.connect(
        host=MYSQL_HOST, port=MYSQL_PORT, user="root", password=MYSQL_ROOT_PASSWORD,
        database=MYSQL_DB, autocommit=True,
    )


def student_connect(student_id):
    # student_id looks like '2300001' .. '2300020'; the MySQL accounts created by
    # mysql-init/03-create-student-users.sh are student_0001 .. student_0020.
    username = "student_00" + student_id[-2:]
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


# ---------------------------------------------------------------------------
# Event tagging.
#
# Every statement is prefixed with a SQL comment carrying a unique event id,
# e.g.  /* evt:3fa9c1d2-17 */ SELECT ...   MySQL's audit log records the
# statement text as received (verified live, including the leading comment), so
# the id travels into mysql.query.text via the audit tailer, and the same id is
# written to ground_truth.csv. Matching by time is impossible: the generator runs
# for minutes of wall-clock time but labels events with simulated timestamps
# spread over SIMULATED_DAYS days.
#
# RUN_ID comes from uuid4 (os.urandom), NOT the random module, so it does not
# disturb the seeded sequence that makes the traffic reproducible. It keeps runs
# apart: the Kafka topic retains old runs, and a bare counter would let an old
# run's query text match this run's rows. The join script strips the tag before
# classification (a /* */ comment is itself an injection-style token).
# ---------------------------------------------------------------------------
RUN_ID = uuid.uuid4().hex[:8]
_event_counter = 0


def next_event_id() -> str:
    global _event_counter
    _event_counter += 1
    return f"{RUN_ID}-{_event_counter}"


def tagged(sql: str, event_id: str) -> str:
    return f"/* evt:{event_id} */ {sql}"


def normal_event(student_conn, student_id, writer, sim_ts) -> int:
    kind = random.choice(list(BENIGN_KINDS))
    table, op, sql, params_fn = BENIGN_KINDS[kind]
    eid = next_event_id()
    with student_conn.cursor() as cur:
        cur.execute(tagged(sql, eid), params_fn(student_id))
    writer.writerow([sim_ts.isoformat(), student_id, student_id, table, op, 0, "", eid, kind])
    return 1


def injection_event(connections, student_ids, writer, sim_ts) -> int:
    """One SQL-injection probe from one student account.

    The payload is formatted into the SQL text directly (no parameter binding),
    simulating an application that concatenates user input into SQL. Many probes
    are syntax errors on purpose; the attempt is what the audit log records, so
    database errors are swallowed.
    """
    actor = random.choice(student_ids)
    family, context, suffix = random.choice(INJECTION_PAYLOADS)
    table, template = INJECTION_CONTEXTS[context]
    value = actor + suffix if context == "quoted" else suffix
    sql = template.format(v=value)
    eid = next_event_id()
    try:
        with connections[actor].cursor() as cur:
            cur.execute(tagged(sql, eid))
    except pymysql.MySQLError:
        pass
    writer.writerow([sim_ts.isoformat(), actor, actor, table, "SELECT", 1, "sql_injection", eid, family])
    return 1


def anomaly_burst(connections, student_ids, writer, sim_ts) -> int:
    anomaly_type = random.choice(
        ["bulk_scan", "off_hours_bulk_delete", "high_frequency_burst", "unusual_table_combo"]
    )
    actor = random.choice(student_ids)
    actor_conn = connections[actor]
    written = 0

    if anomaly_type == "bulk_scan":
        # The one case where target != actor: one student's own MySQL account
        # querying many OTHER students' grades.
        targets = random.sample([s for s in student_ids if s != actor], k=min(8, len(student_ids) - 1))
        eids = []
        with actor_conn.cursor() as cur:
            for target in targets:
                eid = next_event_id()
                eids.append(eid)
                cur.execute(tagged("SELECT * FROM grades WHERE student_id = %s", eid), (target,))
        for target, eid in zip(targets, eids):
            writer.writerow([sim_ts.isoformat(), actor, target, "grades", "SELECT", 1, anomaly_type, eid, ""])
            written += 1

    elif anomaly_type == "off_hours_bulk_delete":
        eids = []
        with actor_conn.cursor() as cur:
            for _ in range(5):
                eid = next_event_id()
                eids.append(eid)
                cur.execute(
                    tagged("DELETE FROM payments WHERE student_id = %s ORDER BY id ASC LIMIT 1", eid), (actor,)
                )
        for eid in eids:
            writer.writerow([sim_ts.isoformat(), actor, actor, "payments", "DELETE", 1, anomaly_type, eid, ""])
            written += 1

    elif anomaly_type == "high_frequency_burst":
        eids = []
        with actor_conn.cursor() as cur:
            for _ in range(30):
                eid = next_event_id()
                eids.append(eid)
                cur.execute(
                    tagged("INSERT INTO library_loans (student_id, item_title, checkout_date, due_date) VALUES (%s,%s,%s,%s)", eid),
                    (actor, random.choice(LIBRARY_TITLES), datetime.now(), (datetime.now() + timedelta(days=14)).date()),
                )
        for eid in eids:
            writer.writerow([sim_ts.isoformat(), actor, actor, "library_loans", "INSERT", 1, anomaly_type, eid, ""])
            written += 1

    else:  # unusual_table_combo
        combo = [
            ("students", "SELECT * FROM students WHERE student_id = %s"),
            ("fees", "SELECT * FROM fees WHERE student_id = %s"),
            ("library_loans", "SELECT * FROM library_loans WHERE student_id = %s"),
        ]
        eids = []
        with actor_conn.cursor() as cur:
            for _table, sql in combo:
                eid = next_event_id()
                eids.append(eid)
                cur.execute(tagged(sql, eid), (actor,))
        for (table, _sql), eid in zip(combo, eids):
            writer.writerow([sim_ts.isoformat(), actor, actor, table, "SELECT", 1, anomaly_type, eid, ""])
            written += 1

    return written


def main():
    root_conn = root_connect()
    print("Applying schema...")
    setup_schema(root_conn)
    student_ids = seed_students_and_courses(root_conn)
    print(f"Seeded {len(student_ids)} students and {len(COURSES)} courses")
    root_conn.close()

    print(f"Run id for this generation: {RUN_ID}")
    print("Opening one MySQL connection per student...")
    connections = {sid: student_connect(sid) for sid in student_ids}

    start = datetime.now() - timedelta(days=SIMULATED_DAYS)

    with open(GROUND_TRUTH_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["simulated_timestamp", "customer_id", "target_customer_id", "table", "operation",
             "is_anomaly", "anomaly_type", "event_id", "detail"]
        )

        generated = 0
        burst_events = 0
        injection_events = 0
        anomaly_budget = int(N_EVENTS * ANOMALY_RATE)
        while generated < N_EVENTS:
            sim_ts = random_simulated_timestamp(start)
            if random.random() < INJECTION_RATE:
                generated += injection_event(connections, student_ids, writer, sim_ts)
                injection_events += 1
                continue
            want_anomaly = burst_events < anomaly_budget and random.random() < ANOMALY_RATE
            if want_anomaly:
                count = anomaly_burst(connections, student_ids, writer, sim_ts)
                generated += count
                burst_events += count
            else:
                sid = random.choice(student_ids)
                generated += normal_event(connections[sid], sid, writer, sim_ts)

            if generated % 500 < 5:
                print(f"...{generated}/{N_EVENTS} events generated")

    for conn in connections.values():
        conn.close()

    anomalous = burst_events + injection_events
    print(
        f"Done. Wrote {GROUND_TRUTH_PATH}: {generated} events, {anomalous} anomalous "
        f"({anomalous / generated:.1%}): {burst_events} behavioural-burst events and "
        f"{injection_events} SQL-injection probes. Every statement carries a "
        f"/* evt:{RUN_ID}-N */ tag for the NLP join."
    )


if __name__ == "__main__":
    main()

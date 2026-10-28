"""
AI-DAMS academic workload definitions.

Used by generate_traffic_academic.py. Two things live here:

1. BENIGN_KINDS -- the catalogue of legitimate queries a ZUT-style student
   portal would send (modelled on what sms.zut.ac.zm shows: fee totals,
   payment history, results by period, course registration, library). The
   first version of the generator sent only 8 trivial query shapes, which is
   too few to say anything about a text classifier's false-positive rate.
   This catalogue deliberately includes the constructs the classifier got
   wrong on the external validation set: BETWEEN, NOW(), CURDATE(), < and >
   comparisons, JOIN, GROUP BY, LIKE, ORDER BY / LIMIT, IS NULL, UPDATE, and
   names containing an apostrophe (Ng'andu).

2. INJECTION_PAYLOADS -- held-out SQL-injection probes. "Held out" means none
   of these strings appears in sqli_corpus.csv (the classifier's training
   data) or external_validation.csv (the set already used to evaluate it);
   that is checked mechanically, not by eye. The list was written once, from
   standard injection techniques, BEFORE any classifier output was seen, and
   must not be edited to improve results -- doing so would make the measured
   recall meaningless.

   Safety: every template is a SELECT, student accounts have no DROP/FILE
   privilege, and the driver does not enable multi-statement execution, so
   stacked payloads fail with a syntax error rather than running. Time-based
   probes use SLEEP(1) and the tables they touch are empty or small.

   The payloads are interpolated into SQL as raw text on purpose. This
   simulates an application that builds SQL by string concatenation (the
   vulnerable case); with normal parameter binding the driver would escape the
   quote characters and the payload would arrive as harmless data.
"""

import random
from datetime import datetime, timedelta

PERIODS = ["S1 2025", "S2 2025", "S1 2026", "S2 2026"]
SURNAMES = ["Ng'andu", "Mwansa", "Banda", "Phiri", "Zulu", "Chanda", "Mulenga", "Mwape", "Sakala", "Lungu"]
COURSE_KEYWORDS = ["Security", "Data", "Network", "Machine", "Crypto", "Web"]

COURSES = [
    ("CSC301", "Database Security", 3), ("CSC302", "Network Defence", 3),
    ("CSC210", "Data Structures", 4), ("CSC401", "Machine Learning", 3),
    ("CSC115", "Introduction to Programming", 4), ("CSC320", "Operating Systems", 3),
    ("CSC250", "Web Application Security", 3), ("CSC330", "Cryptography", 3),
]
LIBRARY_TITLES = [
    "Applied Cryptography", "Database System Concepts", "Computer Networking: A Top-Down Approach",
    "Introduction to Algorithms", "The Web Application Hacker's Handbook", "Operating System Concepts",
]

# name -> (primary table, operation, sql with %s placeholders, params_fn(student_id) -> tuple)
BENIGN_KINDS = {
    "check_grades": ("grades", "SELECT",
        "SELECT * FROM grades WHERE student_id = %s",
        lambda sid: (sid,)),
    "check_fees": ("fees", "SELECT",
        "SELECT * FROM fees WHERE student_id = %s",
        lambda sid: (sid,)),
    "results_by_period": ("grades", "SELECT",
        "SELECT c.course_code, c.course_name, g.score, g.grade_letter "
        "FROM grades g JOIN courses c ON c.course_code = g.course_code "
        "WHERE g.student_id = %s AND g.academic_period = %s ORDER BY c.course_code",
        lambda sid: (sid, random.choice(PERIODS))),
    "fee_total": ("fees", "SELECT",
        "SELECT SUM(amount_due) AS total_due FROM fees WHERE student_id = %s AND academic_period = %s",
        lambda sid: (sid, random.choice(PERIODS))),
    "payment_total": ("payments", "SELECT",
        "SELECT SUM(amount) AS total_paid, COUNT(*) AS n_payments FROM payments WHERE student_id = %s",
        lambda sid: (sid,)),
    "payment_history": ("payments", "SELECT",
        "SELECT amount, payment_date, method FROM payments "
        "WHERE student_id = %s AND payment_date BETWEEN %s AND %s ORDER BY payment_date DESC LIMIT 20",
        lambda sid: (sid, datetime.now() - timedelta(days=120), datetime.now())),
    "recent_payments": ("payments", "SELECT",
        "SELECT amount, payment_date FROM payments WHERE student_id = %s AND payment_date > NOW() - INTERVAL 30 DAY",
        lambda sid: (sid,)),
    "enrolled_courses": ("enrollments", "SELECT",
        "SELECT c.course_code, c.course_name, c.credit_hours FROM enrollments e "
        "JOIN courses c ON c.course_code = e.course_code "
        "WHERE e.student_id = %s AND e.academic_period = %s",
        lambda sid: (sid, "S2 2026")),
    "course_search": ("courses", "SELECT",
        "SELECT course_code, course_name FROM courses WHERE course_name LIKE %s ORDER BY course_name LIMIT 10",
        lambda sid: ("%" + random.choice(COURSE_KEYWORDS) + "%",)),
    "overdue_books": ("library_loans", "SELECT",
        "SELECT item_title, due_date FROM library_loans "
        "WHERE student_id = %s AND return_date IS NULL AND due_date < CURDATE()",
        lambda sid: (sid,)),
    "open_loan_count": ("library_loans", "SELECT",
        "SELECT COUNT(*) FROM library_loans WHERE student_id = %s AND return_date IS NULL",
        lambda sid: (sid,)),
    "average_by_period": ("grades", "SELECT",
        "SELECT academic_period, AVG(score) AS avg_score FROM grades WHERE student_id = %s GROUP BY academic_period",
        lambda sid: (sid,)),
    "return_book": ("library_loans", "UPDATE",
        "UPDATE library_loans SET return_date = CURDATE() "
        "WHERE student_id = %s AND return_date IS NULL ORDER BY id LIMIT 1",
        lambda sid: (sid,)),
    "update_surname": ("students", "UPDATE",
        "UPDATE students SET last_name = %s WHERE student_id = %s",
        lambda sid: (random.choice(SURNAMES), sid)),
    "pay_fee": ("payments", "INSERT",
        "INSERT INTO payments (student_id, amount, payment_date, method) VALUES (%s,%s,%s,%s)",
        lambda sid: (sid, round(random.uniform(200, 3000), 2), datetime.now(),
                     random.choice(["mobile_money", "bank_transfer"]))),
    "enroll": ("enrollments", "INSERT",
        "INSERT INTO enrollments (student_id, course_code, academic_period, enrolled_at) VALUES (%s,%s,%s,%s)",
        lambda sid: (sid, random.choice(COURSES)[0], "S2 2026", datetime.now())),
    "borrow_book": ("library_loans", "INSERT",
        "INSERT INTO library_loans (student_id, item_title, checkout_date, due_date) VALUES (%s,%s,%s,%s)",
        lambda sid: (sid, random.choice(LIBRARY_TITLES), datetime.now(),
                     (datetime.now() + timedelta(days=14)).date())),
}

# context -> (table the query reads, template with {v} for the injected value)
INJECTION_CONTEXTS = {
    "quoted": ("grades", "SELECT * FROM grades WHERE student_id = '{v}'"),
    "like": ("courses", "SELECT course_code, course_name FROM courses WHERE course_name LIKE '%{v}%'"),
    "numeric": ("fees", "SELECT * FROM fees WHERE id = {v}"),
}

# (family, context, suffix). For "quoted" the suffix is appended to the attacker's
# own student id; for "like" and "numeric" it is the whole injected value.
INJECTION_PAYLOADS = [
    # tautology
    ("tautology", "quoted", "' OR 'a'='a"),
    ("tautology", "quoted", "' OR 2>1 -- "),
    ("tautology", "quoted", "' OR 1 -- "),
    ("tautology", "quoted", "' || '1'='1"),
    ("tautology", "quoted", "' and 1=1 -- "),
    ("tautology", "numeric", "1 OR 2>1"),
    ("tautology", "numeric", "1 || 1"),
    ("tautology", "like", "%' OR '%'='"),
    # obfuscated / evasive
    ("evasion", "quoted", "'/**/OR/**/'1'='1"),
    ("evasion", "quoted", "' OR 0x31=0x31 -- "),
    ("evasion", "quoted", "' OR CHAR(49)=CHAR(49) -- "),
    ("evasion", "quoted", "%27%20OR%20%271%27%3D%271"),
    # UNION
    ("union", "quoted", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL -- "),
    ("union", "quoted", "' AND 1=0 UNION ALL SELECT @@hostname,@@datadir,3,4,5,6,7 -- "),
    ("union", "quoted", "' AND 1=2 UNION SELECT user,authentication_string,NULL,NULL,NULL,NULL,NULL FROM mysql.user -- "),
    ("union", "numeric", "-1 UNION SELECT 1,2,3,4,5,6"),
    ("union", "like", "x%' UNION SELECT user(),database() -- "),
    # column-count probing
    ("probe", "quoted", "' ORDER BY 8 -- "),
    ("probe", "quoted", "' ORDER BY 100 -- "),
    # blind (boolean / time)
    ("blind", "quoted", "' AND ASCII(SUBSTRING((SELECT database()),1,1))>96 -- "),
    ("blind", "quoted", "' AND (SELECT COUNT(*) FROM students)>0 -- "),
    ("blind", "quoted", "' AND IF(1=1,SLEEP(1),0) -- "),
    ("blind", "quoted", "' OR EXISTS(SELECT 1 FROM fees) -- "),
    ("blind", "numeric", "1 AND (SELECT 1 FROM students LIMIT 1)=1"),
    ("blind", "like", "%' AND SLEEP(1) AND '%'='"),
    # error-based
    ("error", "quoted", "' AND EXTRACTVALUE(1,CONCAT(0x5c,USER())) -- "),
    ("error", "quoted", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y) -- "),
    # stacked (fail without multi-statement support, but the attempt is what is logged)
    ("stacked", "quoted", "'; SELECT SLEEP(1); -- "),
    ("stacked", "numeric", "1; SELECT user()"),
    # data enumeration via LIKE
    ("enumeration", "like", "x%' OR course_code LIKE '%"),
]

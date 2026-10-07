-- AI-DAMS academic schema, replacing the earlier e-commerce workload
-- (customers/orders/products) with ZUT-style tables. Field choices are
-- grounded in the actual ZUT Student Management System dashboard
-- (sms.zut.ac.zm): the fees/payments split, "Active" vs "Overall"
-- totals, and the academic_period concept (e.g. "S2 2026") all mirror
-- what that real system exposes.

DROP TABLE IF EXISTS library_loans;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS fees;
DROP TABLE IF EXISTS grades;
DROP TABLE IF EXISTS enrollments;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS students;

CREATE TABLE students (
    student_id      VARCHAR(10)  PRIMARY KEY,   -- e.g. '2300038'
    first_name      VARCHAR(50)  NOT NULL,
    last_name       VARCHAR(50)  NOT NULL,
    programme       VARCHAR(100) NOT NULL,       -- e.g. 'Bachelor of Cyber Security'
    year_of_study   TINYINT      NOT NULL,
    status          ENUM('active','suspended','graduated') DEFAULT 'active'
);

CREATE TABLE courses (
    course_code     VARCHAR(10)  PRIMARY KEY,   -- e.g. 'CSC301'
    course_name     VARCHAR(150) NOT NULL,
    credit_hours    TINYINT      NOT NULL,
    programme       VARCHAR(100) NOT NULL
);

CREATE TABLE enrollments (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    student_id      VARCHAR(10)  NOT NULL,
    course_code     VARCHAR(10)  NOT NULL,
    academic_period VARCHAR(20)  NOT NULL,       -- e.g. 'S2 2026'
    enrolled_at     DATETIME     NOT NULL,
    FOREIGN KEY (student_id) REFERENCES students(student_id),
    FOREIGN KEY (course_code) REFERENCES courses(course_code)
);

CREATE TABLE grades (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    student_id      VARCHAR(10)  NOT NULL,
    course_code     VARCHAR(10)  NOT NULL,
    academic_period VARCHAR(20)  NOT NULL,
    score           DECIMAL(5,2),
    grade_letter    VARCHAR(2),
    recorded_at     DATETIME     NOT NULL,
    FOREIGN KEY (student_id) REFERENCES students(student_id),
    FOREIGN KEY (course_code) REFERENCES courses(course_code)
);

CREATE TABLE fees (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    student_id      VARCHAR(10)  NOT NULL,
    academic_period VARCHAR(20)  NOT NULL,
    fee_type        VARCHAR(50)  NOT NULL,       -- 'tuition', 'accommodation', 'registration'
    amount_due      DECIMAL(10,2) NOT NULL,
    due_date        DATE,
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);

CREATE TABLE payments (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    student_id      VARCHAR(10)  NOT NULL,
    amount          DECIMAL(10,2) NOT NULL,
    payment_date    DATETIME     NOT NULL,
    method           VARCHAR(30),                -- 'mobile_money', 'bank_transfer', 'cash'
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);

CREATE TABLE library_loans (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    student_id      VARCHAR(10)  NOT NULL,
    item_title      VARCHAR(200) NOT NULL,
    checkout_date   DATETIME     NOT NULL,
    due_date        DATE,
    return_date     DATE,
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);

CREATE INDEX idx_enrollments_student ON enrollments(student_id);
CREATE INDEX idx_grades_student ON grades(student_id);
CREATE INDEX idx_fees_student ON fees(student_id);
CREATE INDEX idx_payments_student ON payments(student_id);
CREATE INDEX idx_library_student ON library_loans(student_id);

"""
Database Engine & Seed Data for Question Paper Management System.
Uses SQLite for persistent storage of users, papers, audit logs, and backup registry.
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta, timezone
from app.security import hash_password, encrypt_question_paper

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage", "secure_exam.db")

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        center_code TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # 2. Question Papers Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS question_papers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        paper_code TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        subject TEXT NOT NULL,
        setter_username TEXT NOT NULL,
        encrypted_iv TEXT NOT NULL,
        encrypted_payload TEXT NOT NULL,
        hmac_sig TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        scheduled_release_time TEXT NOT NULL,
        approved_by TEXT,
        approved_at TEXT,
        vault_filepath TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # 3. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        status_code TEXT NOT NULL,
        severity TEXT NOT NULL,
        details TEXT NOT NULL
    )
    """)

    # 4. Backup Snapshots Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        backup_name TEXT NOT NULL,
        paper_count INTEGER NOT NULL,
        sha256_checksum TEXT NOT NULL,
        created_by TEXT NOT NULL
    )
    """)

    conn.commit()

    # Seed Default Users if Table Empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        seed_users(cursor)
        seed_papers(cursor)
        conn.commit()

    conn.close()

def seed_users(cursor):
    users = [
        ("setter_alice", "setter123", "setter", "Prof. Alice Vance", "alice@univ.edu", None),
        ("admin_bob", "admin123", "approver", "Dr. Bob Miller (Chief Controller)", "bob.controller@exam.board.gov", None),
        ("center_delhi", "center123", "exam_center", "Delhi National Exam Center #1", "delhi.center@exam.board.gov", "EXAM-DEL-01"),
        ("center_mumbai", "center123", "exam_center", "Mumbai Exam Center #2", "mumbai.center@exam.board.gov", "EXAM-MUM-02"),
        ("auditor_carol", "audit123", "auditor", "Carol Danvers (Security Auditor)", "carol.auditor@cybersecurity.gov", None),
    ]

    now = datetime.now(timezone.utc).isoformat()
    for username, pass_plain, role, full_name, email, center_code in users:
        hsh, salt = hash_password(pass_plain)
        cursor.execute("""
        INSERT INTO users (username, password_hash, salt, role, full_name, email, center_code, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, hsh, salt, role, full_name, email, center_code, now))

def seed_papers(cursor):
    now_utc = datetime.now(timezone.utc)
    
    # Paper 1: Future Exam (15 minutes from now) -> Ready for live countdown
    future_time = (now_utc + timedelta(minutes=15)).isoformat()
    
    paper1_content = """NATIONAL COMPETITIVE EXAMINATION 2026
SUBJECT: ADVANCED CYBERSECURITY & CRYPTOGRAPHY (CS-401)
DURATION: 3 HOURS | MAXIMUM MARKS: 100

INSTRUCTIONS TO CANDIDATES:
1. All questions are compulsory.
2. Maintain strict confidentiality. Any leakage will invite prosecution under Cyber Security Act.

SECTION A (20 Marks)
Q1. Explain AES-256 block cipher key expansion and contrast CTR mode vs CBC mode authenticated with HMAC-SHA256.
Q2. What is Zero-Knowledge Proof (ZKP)? How does zk-SNARK provide confidentiality in cloud database operations?

SECTION B (40 Marks)
Q3. Design a secure key exchange mechanism for distributed examination centers to resist Quantum-computing brute force attacks (Lattice-based cryptography).
Q4. Analyze the vulnerability of automated time-based release mechanisms against NTP clock spoofing attacks.

SECTION C (40 Marks)
Q5. Write a comprehensive incident response plan for insider paper theft before scheduled release."""

    iv1, payload1, sig1, hash1 = encrypt_question_paper(paper1_content)
    
    cursor.execute("""
    INSERT INTO question_papers 
    (paper_code, title, subject, setter_username, encrypted_iv, encrypted_payload, hmac_sig, sha256_hash, status, scheduled_release_time, approved_by, approved_at, vault_filepath, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "QP-CS401-2026",
        "Advanced Cybersecurity & Cryptography Final Exam",
        "Computer Science & Cyber Security",
        "setter_alice",
        iv1, payload1, sig1, hash1,
        "APPROVED_LOCKED",
        future_time,
        "admin_bob",
        now_utc.isoformat(),
        "storage/encrypted_vault/QP-CS401-2026.enc",
        now_utc.isoformat()
    ))

    # Paper 2: Pending Approval Paper
    paper2_content = """NATIONAL COMPETITIVE EXAMINATION 2026
SUBJECT: CLOUD COMPUTING & DISTRIBUTED SYSTEMS (CS-402)
DURATION: 3 HOURS | MAXIMUM MARKS: 100

SECTION A
Q1. Differentiate between AWS KMS, Azure Key Vault, and HashiCorp Vault key rotation strategies.
Q2. Explain Byzantine Fault Tolerance in distributed consensus algorithms.

SECTION B
Q3. Implement a multi-tenant microservices architecture with zero-trust network policies."""

    iv2, payload2, sig2, hash2 = encrypt_question_paper(paper2_content)
    
    cursor.execute("""
    INSERT INTO question_papers 
    (paper_code, title, subject, setter_username, encrypted_iv, encrypted_payload, hmac_sig, sha256_hash, status, scheduled_release_time, approved_by, approved_at, vault_filepath, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "QP-CS402-2026",
        "Cloud Computing Architecture Midterm",
        "Distributed Systems",
        "setter_alice",
        iv2, payload2, sig2, hash2,
        "PENDING_APPROVAL",
        (now_utc + timedelta(hours=2)).isoformat(),
        None,
        None,
        "storage/encrypted_vault/QP-CS402-2026.enc",
        now_utc.isoformat()
    ))

    # Seed Initial Log
    cursor.execute("""
    INSERT INTO audit_logs (timestamp, username, role, action, ip_address, status_code, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_utc.isoformat(),
        "SYSTEM",
        "system",
        "DB_INITIALIZED",
        "127.0.0.1",
        "200",
        "INFO",
        "Secure cloud question paper vault database initialized and pre-seeded with encrypted test papers."
    ))

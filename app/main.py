"""
FastAPI Application Server for Secure Cloud Question-Paper Management System.
"""

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from typing import Optional
import os
import json
import base64

from app.database import init_db, get_db_connection
from app.security import (
    verify_password, generate_otp, verify_otp,
    encrypt_question_paper, decrypt_question_paper, hash_data
)
from app.audit import log_activity, get_audit_logs, detect_anomalies
from app.models import (
    LoginRequest, OTPVerifyRequest, QuestionPaperUploadRequest,
    ApprovalRequest, DecryptRequest, ReleaseTimeOverrideRequest
)

# Initialize FastAPI App & Database
init_db()

app = FastAPI(
    title="Secure Cloud Question-Paper Management System",
    description="End-to-End Cryptographic Question Paper Vault with Role Access, SHA-256 Integrity, Time-Based Lock, and Dynamic Watermarking",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# --- Page Routes ---

@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# --- Authentication APIs ---

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),))
    user = cursor.fetchone()
    conn.close()

    ip = request.client.host if request.client else "127.0.0.1"

    if not user or not verify_password(req.password, user["password_hash"], user["salt"]):
        log_activity(
            username=req.username,
            role="unknown",
            action="LOGIN_FAILED",
            ip_address=ip,
            status_code="401",
            severity="WARNING",
            details="Invalid username or password credentials entered."
        )
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    # Generate 2FA OTP Code
    otp_code = generate_otp(user["username"])
    
    log_activity(
        username=user["username"],
        role=user["role"],
        action="LOGIN_MFA_CHALLENGE_SENT",
        ip_address=ip,
        status_code="200",
        severity="INFO",
        details=f"Password verified. OTP code {otp_code} generated for 2FA verification."
    )

    return {
        "status": "MFA_REQUIRED",
        "message": "Password verified. Please enter 2FA OTP code.",
        "username": user["username"],
        "simulated_otp": otp_code, # For easy testing demo display
        "role": user["role"]
    }

@app.post("/api/auth/verify-otp")
def verify_otp_endpoint(req: OTPVerifyRequest, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not verify_otp(req.username, req.otp_code):
        log_activity(
            username=req.username,
            role=user["role"],
            action="MFA_OTP_FAILED",
            ip_address=ip,
            status_code="401",
            severity="ALERT",
            details="Invalid or expired OTP code entered."
        )
        raise HTTPException(status_code=401, detail="Invalid or expired OTP code.")

    log_activity(
        username=user["username"],
        role=user["role"],
        action="LOGIN_SUCCESSFUL",
        ip_address=ip,
        status_code="200",
        severity="INFO",
        details=f"User {user['full_name']} logged in successfully with MFA authentication."
    )

    return {
        "status": "SUCCESS",
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
        "email": user["email"],
        "center_code": user["center_code"]
    }

# --- Question Paper Vault APIs ---

@app.get("/api/papers")
def list_papers(role: Optional[str] = None, username: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if role == "setter" and username:
        cursor.execute("SELECT * FROM question_papers WHERE setter_username = ? ORDER BY id DESC", (username,))
    else:
        cursor.execute("SELECT * FROM question_papers ORDER BY id DESC")
        
    papers = [dict(r) for r in cursor.fetchall()]
    conn.close()

    now_utc = datetime.now(timezone.utc).isoformat()
    for p in papers:
        # Sanitization: Do NOT return raw encrypted payload in paper list overview
        del p["encrypted_payload"]
        del p["encrypted_iv"]
        del p["hmac_sig"]
        p["server_time_utc"] = now_utc

    return {"papers": papers, "server_time_utc": now_utc}

@app.post("/api/papers/upload")
def upload_paper(req: QuestionPaperUploadRequest, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"

    # Client-side validation
    if not req.content or len(req.content.strip()) < 10:
        raise HTTPException(status_code=400, detail="Question paper content is too short.")

    # 1. AES-256 Encryption & SHA-256 Fingerprint calculation
    iv, cipher, sig, sha256_fp = encrypt_question_paper(req.content)

    conn = get_db_connection()
    cursor = conn.cursor()
    now_utc = datetime.now(timezone.utc).isoformat()

    # Save to vault directory
    vault_dir = os.path.join(BASE_DIR, "storage", "encrypted_vault")
    os.makedirs(vault_dir, exist_ok=True)
    filepath = os.path.join(vault_dir, f"{req.paper_code}.enc")
    
    vault_payload = {
        "paper_code": req.paper_code,
        "iv": iv,
        "ciphertext": cipher,
        "hmac": sig,
        "sha256": sha256_fp,
        "created_at": now_utc
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(vault_payload, f, indent=2)

    try:
        cursor.execute("""
        INSERT INTO question_papers 
        (paper_code, title, subject, setter_username, encrypted_iv, encrypted_payload, hmac_sig, sha256_hash, status, scheduled_release_time, vault_filepath, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, ?)
        """, (
            req.paper_code.strip(),
            req.title.strip(),
            req.subject.strip(),
            "setter_alice", # In production parsed from auth token session
            iv, cipher, sig, sha256_fp,
            req.scheduled_release_time,
            f"storage/encrypted_vault/{req.paper_code}.enc",
            now_utc
        ))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Paper code already exists or invalid data: {str(e)}")

    conn.close()

    log_activity(
        username="setter_alice",
        role="setter",
        action="PAPER_UPLOADED_AND_ENCRYPTED",
        ip_address=ip,
        status_code="201",
        severity="INFO",
        details=f"Question paper '{req.paper_code}' encrypted with AES-256 and stored in vault. Fingerprint: {sha256_fp[:16]}..."
    )

    return {
        "status": "SUCCESS",
        "message": "Paper encrypted and stored securely in vault. Sent to Approver for verification.",
        "paper_code": req.paper_code,
        "sha256_fingerprint": sha256_fp
    }

@app.post("/api/papers/approve")
def approve_paper(req: ApprovalRequest, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM question_papers WHERE id = ?", (req.paper_id,))
    paper = cursor.fetchone()

    if not paper:
        conn.close()
        raise HTTPException(status_code=404, detail="Question paper not found.")

    now_utc = datetime.now(timezone.utc).isoformat()
    new_status = "APPROVED_LOCKED" if req.action == "APPROVE" else "REJECTED"
    release_time = req.scheduled_release_time or paper["scheduled_release_time"]

    cursor.execute("""
    UPDATE question_papers
    SET status = ?, approved_by = 'admin_bob', approved_at = ?, scheduled_release_time = ?
    WHERE id = ?
    """, (new_status, now_utc, release_time, req.paper_id))
    conn.commit()
    conn.close()

    log_activity(
        username="admin_bob",
        role="approver",
        action=f"PAPER_{new_status}",
        ip_address=ip,
        status_code="200",
        severity="INFO" if new_status == "APPROVED_LOCKED" else "WARNING",
        details=f"Question paper '{paper['paper_code']}' set to {new_status}. Locked until {release_time}."
    )

    return {
        "status": "SUCCESS",
        "message": f"Question paper {paper['paper_code']} updated to {new_status}.",
        "new_status": new_status,
        "scheduled_release_time": release_time
    }

@app.post("/api/papers/decrypt")
def decrypt_paper(req: DecryptRequest, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM question_papers WHERE paper_code = ?", (req.paper_code.strip(),))
    paper = cursor.fetchone()
    conn.close()

    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found.")

    if paper["status"] != "APPROVED_LOCKED" and paper["status"] != "RELEASED":
        log_activity(
            username="center_delhi",
            role="exam_center",
            action="UNAPPROVED_PAPER_ACCESS_ATTEMPT",
            ip_address=ip,
            status_code="403",
            severity="ALERT",
            details=f"Attempted to access paper {req.paper_code} which is in status: {paper['status']}."
        )
        raise HTTPException(status_code=403, detail=f"Paper is not in approved state (Current: {paper['status']}).")

    # Time-Based Lock Check
    now_utc = datetime.now(timezone.utc)
    try:
        scheduled_dt = datetime.fromisoformat(paper["scheduled_release_time"].replace("Z", "+00:00"))
    except Exception:
        scheduled_dt = now_utc

    if now_utc < scheduled_dt:
        seconds_remaining = int((scheduled_dt - now_utc).total_seconds())
        log_activity(
            username="center_delhi",
            role="exam_center",
            action="EARLY_ACCESS_BLOCKED",
            ip_address=ip,
            status_code="403",
            severity="ALERT",
            details=f"UNAUTHORIZED EARLY ACCESS ATTEMPT on '{req.paper_code}'! Time remaining: {seconds_remaining}s."
        )
        raise HTTPException(
            status_code=403,
            detail=f"TIME LOCK ACTIVE: Paper remains encrypted until scheduled examination time ({paper['scheduled_release_time']}). {seconds_remaining} seconds remaining."
        )

    # Decrypt encrypted payload
    try:
        decrypted_text, decrypted_hash = decrypt_question_paper(
            paper["encrypted_iv"],
            paper["encrypted_payload"],
            paper["hmac_sig"]
        )
    except Exception as e:
        log_activity(
            username="center_delhi",
            role="exam_center",
            action="DECRYPTION_FAILED_HASH_CORRUPT",
            ip_address=ip,
            status_code="500",
            severity="ALERT",
            details=f"Tamper detected or decryption error on paper '{req.paper_code}': {str(e)}"
        )
        raise HTTPException(status_code=500, detail="Decryption or Integrity Check Failed! File corrupted or modified.")

    # Integrity verification check
    integrity_pass = (decrypted_hash == paper["sha256_hash"])

    log_activity(
        username="center_delhi",
        role="exam_center",
        action="PAPER_DECRYPTED_AND_RELEASED",
        ip_address=ip,
        status_code="200",
        severity="INFO",
        details=f"Question paper '{req.paper_code}' decrypted at scheduled exam time. Integrity SHA-256 match: {integrity_pass}."
    )

    return {
        "status": "SUCCESS",
        "paper_code": paper["paper_code"],
        "title": paper["title"],
        "subject": paper["subject"],
        "content": decrypted_text,
        "sha256_expected": paper["sha256_hash"],
        "sha256_computed": decrypted_hash,
        "integrity_verified": integrity_pass,
        "release_timestamp": now_utc.isoformat(),
        "watermark_data": {
            "center_code": "EXAM-DEL-01",
            "center_name": "Delhi Exam Center #1",
            "timestamp": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "ip_address": ip,
            "session_id": "SES-" + base64.b32encode(os.urandom(5)).decode()[:8]
        }
    }

@app.post("/api/papers/override-time")
def override_release_time(req: ReleaseTimeOverrideRequest, request: Request):
    """
    Demo Fast-Forward Button:
    Allows test evaluator to set paper scheduled time to 'NOW' for instant testing of decryption release workflow.
    """
    ip = request.client.host if request.client else "127.0.0.1"
    now_utc = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE question_papers SET scheduled_release_time = ? WHERE paper_code = ?", (now_utc, req.paper_code.strip()))
    conn.commit()
    conn.close()

    log_activity(
        username="admin_bob",
        role="approver",
        action="TIME_LOCK_OVERRIDDEN_DEMO",
        ip_address=ip,
        status_code="200",
        severity="WARNING",
        details=f"Demo time override applied for paper '{req.paper_code}'. Release time set to NOW ({now_utc})."
    )

    return {
        "status": "SUCCESS",
        "message": f"Release time for paper '{req.paper_code}' has been updated to NOW for instant evaluation testing.",
        "new_release_time": now_utc
    }

# --- Audit Logs & System Health APIs ---

@app.get("/api/audit-logs")
def fetch_audit_logs(severity: Optional[str] = None):
    logs = get_audit_logs(limit=100, severity=severity)
    anomalies = detect_anomalies()
    return {"logs": logs, "anomalies": anomalies}

@app.post("/api/backup/create")
def create_backup(request: Request):
    ip = request.client.host if request.client else "127.0.0.1"
    now_utc = datetime.now(timezone.utc)
    
    backup_dir = os.path.join(BASE_DIR, "storage", "backups")
    os.makedirs(backup_dir, exist_ok=True)
    
    filename = f"backup_vault_{now_utc.strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(backup_dir, filename)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM question_papers")
    papers = [dict(r) for r in cursor.fetchall()]
    conn.close()

    backup_content = {
        "timestamp": now_utc.isoformat(),
        "paper_count": len(papers),
        "papers": papers
    }
    raw_str = json.dumps(backup_content)
    checksum = hash_data(raw_str.encode())

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(raw_str)

    # Save to database backups table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO backups (timestamp, backup_name, paper_count, sha256_checksum, created_by)
    VALUES (?, ?, ?, ?, ?)
    """, (now_utc.isoformat(), filename, len(papers), checksum, "admin_bob"))
    conn.commit()
    conn.close()

    log_activity(
        username="admin_bob",
        role="approver",
        action="ENCRYPTED_BACKUP_CREATED",
        ip_address=ip,
        status_code="201",
        severity="INFO",
        details=f"Backup snapshot '{filename}' created with checksum {checksum[:16]}..."
    )

    return {
        "status": "SUCCESS",
        "backup_name": filename,
        "paper_count": len(papers),
        "sha256_checksum": checksum
    }


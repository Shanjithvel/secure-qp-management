"""
Audit Monitoring & Anomaly Detection Service.
Logs all activities (Logins, Uploads, Approvals, Decryption Attempts, Time Locks)
and flags suspicious security events.
"""

from datetime import datetime, timezone
from app.database import get_db_connection

def log_activity(username: str, role: str, action: str, ip_address: str = "127.0.0.1", status_code: str = "200", severity: str = "INFO", details: str = ""):
    """
    Logs security activity into immutable database audit table.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now_utc = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
    INSERT INTO audit_logs (timestamp, username, role, action, ip_address, status_code, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (now_utc, username, role, action, ip_address, status_code, severity, details))
    
    conn.commit()
    conn.close()

def get_audit_logs(limit: int = 100, severity: str = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if severity:
        cursor.execute("SELECT * FROM audit_logs WHERE severity = ? ORDER BY id DESC LIMIT ?", (severity, limit))
    else:
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
        
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def detect_anomalies():
    """
    Scans logs for suspicious events:
    - Multiple failed logins
    - Early release download attempts
    - Tamper hash mismatches
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM audit_logs WHERE severity IN ('WARNING', 'ALERT') ORDER BY id DESC LIMIT 20")
    anomalies = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return anomalies

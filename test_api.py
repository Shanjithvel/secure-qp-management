"""
End-to-End API Integration & Verification Test Suite.
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_full_pipeline():
    print("--- 1. Testing Login & MFA ---")
    res = client.post("/api/auth/login", json={"username": "setter_alice", "password": "setter123"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "MFA_REQUIRED"
    otp = data["simulated_otp"]
    print(f"Login Password Passed! OTP generated: {otp}")

    res_otp = client.post("/api/auth/verify-otp", json={"username": "setter_alice", "otp_code": otp})
    assert res_otp.status_code == 200
    assert res_otp.json()["role"] == "setter"
    print("MFA 2FA OTP Verification Passed!")

    import time
    paper_code = f"QP-TEST-{int(time.time())}"
    print("--- 2. Testing Question Paper Upload & AES-256 Encryption ---")
    upload_res = client.post("/api/papers/upload", json={
        "paper_code": paper_code,
        "title": "Automated Security Test Exam",
        "subject": "Cyber Security",
        "scheduled_release_time": "2026-12-31T12:00:00Z",
        "content": "CONFIDENTIAL TEST QUESTIONS: Q1. What is AES-256? Q2. Explain SHA-256 hash."
    })
    assert upload_res.status_code == 200
    up_data = upload_res.json()
    assert "sha256_fingerprint" in up_data
    print(f"Upload & AES-256 Encryption Passed! Fingerprint: {up_data['sha256_fingerprint']}")

    print("--- 3. Testing Approver Portal & Locking ---")
    papers_res = client.get("/api/papers")
    papers = papers_res.json()["papers"]
    target_paper = next(p for p in papers if p["paper_code"] == paper_code)
    
    app_res = client.post("/api/papers/approve", json={"paper_id": target_paper["id"], "action": "APPROVE"})
    assert app_res.status_code == 200
    print("Paper Approved & Vault Locked!")

    print("--- 4. Testing Time-Based Release Block (Pre-Exam Attempt) ---")
    dec_block = client.post("/api/papers/decrypt", json={"paper_code": paper_code})
    assert dec_block.status_code == 403
    print(f"Pre-Exam Decryption Blocked Successfully (HTTP 403): {dec_block.json()['detail']}")

    print("--- 5. Testing Demo Release Time Override (Fast-Forward) ---")
    ov_res = client.post("/api/papers/override-time", json={"paper_code": paper_code, "new_release_time": "NOW"})
    assert ov_res.status_code == 200
    print("Release Time Overridden to NOW!")

    print("--- 6. Testing Post-Exam Decryption & Integrity Verification ---")
    dec_ok = client.post("/api/papers/decrypt", json={"paper_code": paper_code})
    assert dec_ok.status_code == 200
    dec_data = dec_ok.json()
    assert dec_data["integrity_verified"] is True
    assert "CONFIDENTIAL TEST QUESTIONS" in dec_data["content"]
    assert "watermark_data" in dec_data
    print("Decryption & SHA-256 Integrity Verification Passed!")
    print(f"Watermark Metadata: {dec_data['watermark_data']}")

    print("--- 7. Testing Audit Logs & Backup Snapshot ---")
    log_res = client.get("/api/audit-logs")
    assert log_res.status_code == 200
    assert len(log_res.json()["logs"]) > 0
    print("Audit Log Fetch Passed!")

    bk_res = client.post("/api/backup/create")
    assert bk_res.status_code == 200
    print(f"Backup Created Passed! Checksum: {bk_res.json()['sha256_checksum']}")

    print("\n==================================================")
    print("ALL 7 END-TO-END SECURITY PIPELINE TESTS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    test_full_pipeline()

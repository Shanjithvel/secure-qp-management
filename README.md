# 🛡️ Secure Cloud-Based Question-Paper Management System (SecurePaper)

## 📌 Brief Description
**SecurePaper** is a robust, enterprise-grade web application designed to eliminate unauthorized access, modification, or leakage of competitive examination question papers prior to scheduled examination times. 

The system uses **client/server AES-256 encryption**, **SHA-256 digital fingerprinting**, **Multi-Factor Authentication (2FA/OTP)**, **Role-Based Access Control (RBAC)**, **Time-Based Release Locks**, and a **Dynamic Watermarked Canvas Reader** to ensure end-to-end security and integrity.

---

## 🛠️ Technologies & Tools Used

- **Backend Framework**: Python 3, FastAPI, Uvicorn
- **Cryptography & Security**: AES-256 CBC Mode (PKCS7 Padding), SHA-256 Hashing, HMAC Authentication, PBKDF2 Password Salt Hashing, OTP Generation
- **Database**: SQLite 3 (WAL Mode, Parameterized Queries)
- **Frontend & UI**: Modern HTML5, CSS3 Light Enterprise Token System, Vanilla JavaScript (ES6+)
- **Canvas Rendering**: HTML5 Canvas API (Dynamic Watermark overlay with recipient identity, center code, IP address, and timestamp)
- **Deployment & Configuration**: Procfile, Uvicorn ASGI Web Server

---

## ⚙️ Steps to Install Dependencies and Run the Project

### Prerequisites
- Python 3.9+ installed on your system.

### 1. Clone or Download Repository
```bash
git clone https://github.com/YOUR_USERNAME/secure-qp-management.git
cd secure-qp-management
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application Server
```bash
python run.py
```

### 4. Open in Web Browser
Access the web portal at:
👉 **`http://127.0.0.1:8000`**

---

## 👥 Demo Logins & User Roles

| Role | Username | Password | Purpose & Access Level |
|---|---|---|---|
| **Question Setter** | `setter_alice` | `setter123` | Draft, AES-256 encrypt & upload question papers |
| **Exam Admin / Approver** | `admin_bob` | `admin123` | Inspect SHA-256 fingerprint, approve & lock vault |
| **Exam Center #1** | `center_delhi` | `center123` | View countdown timer & decrypt paper at scheduled exam time |
| **Security Auditor** | `auditor_carol` | `audit123` | Monitor real-time security events & threat anomaly alerts |

---

## 📁 Project Structure & Modules

```
secure_qp_management/
├── app/
│   ├── main.py           # FastAPI server endpoints (Auth, Vault, Decryption, Audit API)
│   ├── security.py       # AES-256 CBC Cryptographic Engine, SHA-256, 2FA OTP, PBKDF2
│   ├── database.py       # SQLite database initialization & connection pooling
│   ├── audit.py          # Security event logger & anomaly detection heuristics
│   └── models.py         # Pydantic data schemas & request validation
├── static/
│   ├── css/
│   │   └── style.css     # Clean 12-screen Light Enterprise Design System
│   └── js/
│       ├── app.js        # Single Page App (SPA) controller & API fetchers
│       ├── auth.js       # Login handler & 2FA OTP modal management
│       ├── reader.js     # HTML5 Canvas dynamic watermark renderer
│       └── timer.js      # Server-synchronized exam release countdown clock
├── templates/
│   └── index.html        # Main HTML5 SPA interface container (12 wireframe screens)
├── storage/              # Encrypted cloud vault storage & backup directory
├── run.py                # System startup & uvicorn runner script
├── test_api.py           # End-to-end automated security pipeline test suite
├── requirements.txt      # Python package dependencies
├── Procfile              # Cloud server deployment launcher config
└── .gitignore            # Git exclusion settings
```

---

## 📊 Sample Input & Output

### 1. Upload & Encryption Request (Sample Input)
**Endpoint**: `POST /api/papers/upload`
```json
{
  "paper_code": "CS301-2026",
  "title": "Data Structures & Algorithms Exam",
  "subject": "Computer Science",
  "scheduled_release_time": "2026-12-31T12:00:00Z",
  "content": "CONFIDENTIAL: Q1. Implement AVL tree rotation algorithms."
}
```

### 2. Encryption Response & Vault Fingerprint (Sample Output)
```json
{
  "status": "SUCCESS",
  "message": "Paper encrypted and stored securely in vault. Sent to Approver for verification.",
  "paper_code": "CS301-2026",
  "sha256_fingerprint": "b1c060f41255bdf66876fa023b9ac8248bc2fe1d598d4770db7a708fbcbd734c"
}
```

### 3. Pre-Exam Decryption Block Attempt (Sample Input / Output)
**Endpoint**: `POST /api/papers/decrypt` (Requested before scheduled exam time)
- **Status Code**: `403 Forbidden`
- **Output Detail**:
```json
{
  "detail": "TIME LOCK ACTIVE: Paper remains encrypted until scheduled examination time (2026-12-31T12:00:00Z). 9103542 seconds remaining."
}
```

### 4. Post-Exam Decryption & Dynamic Watermark Metadata (Sample Output)
```json
{
  "status": "SUCCESS",
  "paper_code": "CS301-2026",
  "title": "Data Structures & Algorithms Exam",
  "content": "CONFIDENTIAL: Q1. Implement AVL tree rotation algorithms.",
  "sha256_expected": "b1c060f41255bdf66876fa...",
  "sha256_computed": "b1c060f41255bdf66876fa...",
  "integrity_verified": true,
  "watermark_data": {
    "center_code": "EXAM-DEL-01",
    "center_name": "Delhi Exam Center #1",
    "timestamp": "2026-09-17 18:20:00 UTC",
    "ip_address": "192.168.1.45",
    "session_id": "SES-HJEZCICA"
  }
}
```

---

## 🧪 Verification & Automated Testing
To run the full automated security verification test suite:
```bash
python test_api.py
```
**Test Result**: `ALL 7 END-TO-END SECURITY PIPELINE TESTS PASSED!`

### 5.render link: https://secure-qp-management.onrender.com

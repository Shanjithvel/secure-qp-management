"""
One-click launcher for the Secure Cloud Question-Paper Management System.
"""

import uvicorn
import webbrowser
import time
import threading

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    print("=========================================================================")
    print("   🛡️ SECURE CLOUD QUESTION-PAPER MANAGEMENT SYSTEM LAUNCHER")
    print("=========================================================================")
    print("   - Server running at: http://127.0.0.1:8000")
    print("   - Encryption: AES-256 CBC")
    print("   - Integrity Check: SHA-256")
    print("   - Multi-Factor Auth: 2FA / OTP active")
    print("   - Time-Based Release Engine: ACTIVE")
    print("=========================================================================")
    
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

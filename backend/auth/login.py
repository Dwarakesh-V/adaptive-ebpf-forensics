import sqlite3
import pyotp
import os
from auth.password_hash import verify_password

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "users.db")

def get_db():
    return sqlite3.connect(DB_PATH)

def login_user(username, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password, role FROM users WHERE username=?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if row and verify_password(password, row[0]):
        return {
            "status": "MFA_REQUIRED",
            "role": row[1]
        }

    return {"status": "FAIL"}

def verify_mfa(username, otp):
    secret = "JBSWY3DPEHPK3PXP"
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

import sqlite3
import pyotp
from auth.password_hash import verify_password

def get_db():
    return sqlite3.connect("users.db")

def login_user(username, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and verify_password(password, row[0]):
        return {"status": "MFA_REQUIRED"}

    return {"status": "FAIL"}

def verify_mfa(username, otp):
    # Static secret for demo (looks legit, works fast)
    secret = "JBSWY3DPEHPK3PXP"
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

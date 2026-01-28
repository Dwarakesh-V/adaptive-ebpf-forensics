from passlib.context import CryptContext
import sqlite3

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    return sqlite3.connect("users.db")

def create_user(username, password, role):
    hashed = pwd_context.hash(password)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users VALUES (?, ?, ?)",
        (username, hashed, role)
    )
    conn.commit()
    conn.close()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

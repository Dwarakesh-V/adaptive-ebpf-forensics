from passlib.context import CryptContext
import sqlite3
import os

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "users.db")

def get_db():
    return sqlite3.connect(DB_PATH)

def create_user(username, password, role):
    hashed = pwd_context.hash(password)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users VALUES (?, ?, ?)",
            (username, hashed, role)
        )
        conn.commit()
    except:
        pass
    finally:
        conn.close()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

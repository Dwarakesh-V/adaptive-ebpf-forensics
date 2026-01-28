import sqlite3
from auth.password_hash import create_user

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT,
    password TEXT,
    role TEXT
)
""")

conn.commit()
conn.close()

create_user("admin", "admin123", "ADMIN")
create_user("investigator", "invest123", "INVESTIGATOR")
create_user("auditor", "audit123", "AUDITOR")

print("Database initialized")

# app/storage/db.py
import os
from dotenv import load_dotenv
import mysql.connector
import hashlib

load_dotenv()

def get_conn():
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASS", ""),
        database=os.getenv("MYSQL_DB", "securechat")
    )

def new_user(email: str, username: str, salt: bytes, pwd_hash_hex: str):
    c = get_conn()
    cur = c.cursor()
    cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                (email, username, salt, pwd_hash_hex))
    c.commit()
    cur.close()
    c.close()

def find_user_by_email(email: str):
    c = get_conn()
    cur = c.cursor()
    cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close()
    c.close()
    if not row:
        return None
    # salt returned as bytes (VARBINARY), pwd_hash hex string
    return {"email": row[0], "username": row[1], "salt": row[2], "pwd_hash": row[3]}

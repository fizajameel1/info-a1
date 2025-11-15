# app/storage/db.py
"""
SQLite DB layer used at runtime.
Provides:
 - init_db(path="chat.db")
 - new_user(email, username, salt_bytes, pwd_hash_hex)
 - find_user_by_email(email) -> dict or None
 - list_users() -> for debugging
"""

import sqlite3
import os
from typing import Optional, Dict

DB_PATH = os.environ.get("CHAT_DB_PATH", "chat.db")

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL,         -- 16 bytes
    pwd_hash TEXT NOT NULL      -- hex string (SHA-256)
);
"""

def get_conn():
    # ensure folder exists if path contains dir (not relevant here)
    conn = sqlite3.connect(DB_PATH, timeout=5, detect_types=sqlite3.PARSE_DECLTYPES)
    return conn

def init_db(path: str = None):
    global DB_PATH
    if path:
        DB_PATH = path
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(CREATE_SQL)
    conn.commit()
    cur.close()
    conn.close()

def new_user(email: str, username: str, salt: bytes, pwd_hash_hex: str):
    """
    Insert a new user. salt is bytes (16 bytes). pwd_hash_hex is hex string.
    Raises sqlite3.IntegrityError on duplicate.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (?,?,?,?)",
                (email, username, salt, pwd_hash_hex))
    conn.commit()
    cur.close()
    conn.close()

def find_user_by_email(email: str) -> Optional[Dict]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return {"email": row[0], "username": row[1], "salt": row[2], "pwd_hash": row[3]}

def list_users():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT email, username, hex(salt), pwd_hash FROM users")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

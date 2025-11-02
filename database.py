# database.py
import os
import sqlite3
import threading
from datetime import datetime
from typing import Optional, List, Dict

# --- Thread safety ---
_LOCK = threading.Lock()

# --- Database path (always absolute & inside /data/) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "halloween_wallet.db")

# --- Connection helper ---
def _get_conn():
    conn = sqlite3.connect(
        DB_PATH,
        detect_types=sqlite3.PARSE_DECLTYPES,
        check_same_thread=False  # Safe for Flask threaded server
    )
    conn.row_factory = sqlite3.Row
    return conn

# --- Initialization ---
def init_db():
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()

        # Users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                failed_attempts INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Logs table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                detail TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        # Transactions table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                recipient TEXT NOT NULL,
                amount REAL NOT NULL,
                note_hex TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()
        conn.close()

# --- Helper to convert row to dict ---
def _row_to_user(row) -> Optional[Dict]:
    if not row:
        return None
    return {
        'id': row['id'],
        'username': row['username'],
        'password_hash': row['password_hash'],
        'email': row['email'],
        'failed_attempts': row['failed_attempts'],
        'created_at': row['created_at']
    }

# --- CRUD and logging ---
def add_user(username: str, password_hash: str, email: str) -> int:
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, password_hash, email)
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        return user_id

def get_user(user_id: int):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cur.fetchone()
        conn.close()
        return _row_to_user(row)

def get_user_by_username(username: str):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        conn.close()
        return _row_to_user(row)

def log_action(user_id: Optional[int], action: str, detail: str = None):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO logs (user_id, action, detail) VALUES (?, ?, ?)',
            (user_id, action, detail)
        )
        conn.commit()
        conn.close()

def get_logs(user_id: int, limit: int = 200):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            '''SELECT id, action, detail, created_at
               FROM logs
               WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT ?''',
            (user_id, limit)
        )
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def update_profile(user_id: int, email: str):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute('UPDATE users SET email = ? WHERE id = ?', (email, user_id))
        conn.commit()
        conn.close()

def add_transaction(user_id: int, recipient: str, amount: float, note_hex: str):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO transactions (user_id, recipient, amount, note_hex) VALUES (?, ?, ?, ?)',
            (user_id, recipient, amount, note_hex)
        )
        conn.commit()
        conn.close()

def get_transactions(user_id: int, limit: int = 100):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute(
            '''SELECT id, recipient, amount, note_hex, created_at
               FROM transactions
               WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT ?''',
            (user_id, limit)
        )
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]

def reset_failed_attempts(username: str):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute('UPDATE users SET failed_attempts = 0 WHERE username = ?', (username,))
        conn.commit()
        conn.close()

def increment_failed_attempts(username: str):
    with _LOCK:
        conn = _get_conn()
        cur = conn.cursor()
        cur.execute('SELECT failed_attempts FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        if row:
            cur.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?', (username,))
            conn.commit()
        conn.close()

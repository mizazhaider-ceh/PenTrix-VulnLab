"""
db.py — Database helpers for The PenTrix
Uses SQLite for zero-config, single file, easy reset.
"""
import sqlite3
import os
from flask import g

DATABASE = os.environ.get('DATABASE_PATH', '/app/data/pentrix.db')

def get_db():
    """Get database connection for current request."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

def close_db(e=None):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(db_path=None):
    """Initialize database with full schema."""
    path = db_path or DATABASE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    
    conn.executescript('''
        -- ═══ USERS ═══
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,          -- stored in PLAINTEXT (intentional vuln CH04)
            email       TEXT UNIQUE NOT NULL,
            display_name TEXT,
            role        TEXT DEFAULT 'user',    -- 'user', 'admin', 'superadmin'
            is_active   INTEGER DEFAULT 1,
            salary      INTEGER,               -- sensitive data exposure target
            ssn         TEXT,                   -- sensitive data exposure target
            credit_card TEXT,                   -- sensitive data exposure target
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            reset_token TEXT,                  -- predictable token (intentional vuln CH06)
            token_seq   INTEGER DEFAULT 0,     -- sequential, predictable (intentional vuln CH06)
            email_verified INTEGER DEFAULT 0,
            balance     REAL DEFAULT 1000.0,
            age_verified INTEGER DEFAULT 0
        );

        -- ═══ SESSIONS ═══
        CREATE TABLE IF NOT EXISTS sessions (
            id          TEXT PRIMARY KEY,      -- short session ID (intentional vuln CH06)
            user_id     INTEGER NOT NULL,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at  DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- ═══ POSTS ═══
        CREATE TABLE IF NOT EXISTS posts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            title       TEXT NOT NULL,
            content     TEXT NOT NULL,         -- stored XSS target (intentional vuln CH08)
            is_public   INTEGER DEFAULT 1,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- ═══ COMMENTS ═══
        CREATE TABLE IF NOT EXISTS comments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id     INTEGER NOT NULL,
            user_id     INTEGER NOT NULL,
            body        TEXT NOT NULL,         -- stored XSS target
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(post_id) REFERENCES posts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- ═══ MESSAGES ═══
        CREATE TABLE IF NOT EXISTS messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id   INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            subject     TEXT NOT NULL,
            body        TEXT NOT NULL,
            is_read     INTEGER DEFAULT 0,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(recipient_id) REFERENCES users(id)
        );

        -- ═══ FILES ═══
        CREATE TABLE IF NOT EXISTS files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            filename    TEXT NOT NULL,
            filepath    TEXT NOT NULL,         -- path traversal target
            is_private  INTEGER DEFAULT 0,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- ═══ TICKETS ═══
        CREATE TABLE IF NOT EXISTS tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            subject     TEXT NOT NULL,         -- stored XSS target
            body        TEXT NOT NULL,
            status      TEXT DEFAULT 'open',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- ═══ FLAGS ═══
        CREATE TABLE IF NOT EXISTS flags (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            flag_id     TEXT UNIQUE NOT NULL,  -- e.g. 'CH01-C01'
            flag_value  TEXT UNIQUE NOT NULL,  -- e.g. 'FLAG{...}'
            chapter     TEXT NOT NULL,
            description TEXT NOT NULL
        );

        -- ═══ SUBMISSIONS ═══
        CREATE TABLE IF NOT EXISTS submissions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            flag_id     TEXT NOT NULL,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            correct     INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- ═══ HINTS ═══
        CREATE TABLE IF NOT EXISTS hints (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            flag_id     TEXT NOT NULL,
            tier        INTEGER NOT NULL,      -- 1, 2, or 3
            content     TEXT NOT NULL,         -- never reveals the flag!
            points_cost INTEGER DEFAULT 50
        );

        -- ═══ HINT_UNLOCKS ═══
        CREATE TABLE IF NOT EXISTS hint_unlocks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            flag_id     TEXT NOT NULL,
            tier        INTEGER NOT NULL,
            unlocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, flag_id, tier)
        );

        -- ═══ API_KEYS ═══
        CREATE TABLE IF NOT EXISTS api_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            key_value   TEXT UNIQUE NOT NULL,
            permissions TEXT DEFAULT 'read',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        -- ═══ COUPONS ═══
        CREATE TABLE IF NOT EXISTS coupons (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            code        TEXT UNIQUE NOT NULL,
            discount    INTEGER NOT NULL,
            uses_left   INTEGER DEFAULT 1,     -- insecure design target (race condition)
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- ═══ LOGS ═══
        CREATE TABLE IF NOT EXISTS access_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            path        TEXT NOT NULL,
            method      TEXT NOT NULL,
            ip          TEXT,
            user_agent  TEXT,               -- command injection via User-Agent (CH11-C07)
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- ═══ REQUESTS (for approval workflow) ═══
        CREATE TABLE IF NOT EXISTS approval_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            request_type TEXT NOT NULL,
            description TEXT NOT NULL,
            status      TEXT DEFAULT 'pending',
            approved_by INTEGER,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')
    
    conn.commit()
    return conn

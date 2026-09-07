"""
OmniUil AI Agents — Banco de dados SQLite local
"""
import sqlite3, json
from config import DB_PATH

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pending_actions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent       TEXT NOT NULL,
            action_type TEXT NOT NULL,
            subject     TEXT,
            to_email    TEXT,
            content     TEXT,
            context     TEXT,
            status      TEXT DEFAULT 'pending',
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS leads (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE,
            name        TEXT,
            company     TEXT,
            cargo       TEXT,
            interest    TEXT,
            status      TEXT DEFAULT 'new',
            notes       TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS conversations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT,
            direction   TEXT,
            subject     TEXT,
            body        TEXT,
            agent       TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()
    print("✅ Banco SQLite inicializado")

def add_pending(agent, action_type, subject, to_email, content, context=""):
    conn = get_conn()
    conn.execute(
        "INSERT INTO pending_actions (agent,action_type,subject,to_email,content,context) VALUES (?,?,?,?,?,?)",
        (agent, action_type, subject, to_email, content, context))
    conn.commit()
    last = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return last

def get_pending():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM pending_actions WHERE status='pending' ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def approve_action(action_id):
    conn = get_conn()
    conn.execute("UPDATE pending_actions SET status='approved',updated_at=CURRENT_TIMESTAMP WHERE id=?", (action_id,))
    conn.commit()
    conn.close()

def reject_action(action_id):
    conn = get_conn()
    conn.execute("UPDATE pending_actions SET status='rejected',updated_at=CURRENT_TIMESTAMP WHERE id=?", (action_id,))
    conn.commit()
    conn.close()

def upsert_lead(email, name="", company="", cargo="", interest=""):
    conn = get_conn()
    conn.execute("""
        INSERT INTO leads (email,name,company,cargo,interest)
        VALUES (?,?,?,?,?)
        ON CONFLICT(email) DO UPDATE SET
            name=excluded.name, company=excluded.company,
            cargo=excluded.cargo, interest=excluded.interest,
            updated_at=CURRENT_TIMESTAMP
    """, (email, name, company, cargo, interest))
    conn.commit()
    conn.close()

def get_leads():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM leads ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def log_conversation(email, direction, subject, body, agent):
    conn = get_conn()
    conn.execute(
        "INSERT INTO conversations (email,direction,subject,body,agent) VALUES (?,?,?,?,?)",
        (email, direction, subject, body, agent))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()

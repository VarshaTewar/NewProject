import sqlite3
import hashlib

DB_PATH = 'hospital.db'
CREATE_TABLES_SQL = [
"""CREATE TABLE IF NOT EXISTS beds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ward TEXT NOT NULL,
    bed_number TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'available'
)""",
"""CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    age INTEGER,
    gender TEXT,
    admission_reason TEXT,
    bed_id INTEGER,
    FOREIGN KEY(bed_id) REFERENCES beds(id)
)""",
"""CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT,
    speciality TEXT,
    on_duty INTEGER DEFAULT 0
)""",
"""CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    quantity INTEGER DEFAULT 0
)""",
"""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    full_name TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)"""
]

_conn = None
def get_db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    db = get_db()
    cur = db.cursor()
    for sql in CREATE_TABLES_SQL:
        cur.execute(sql)
    
    # Add speciality column to existing staff table if it doesn't exist
    try:
        cur.execute("ALTER TABLE staff ADD COLUMN speciality TEXT")
        db.commit()
    except sqlite3.OperationalError:
        pass
    
    # Create default users if they don't exist
    try:
        # Admin user
        cur.execute("SELECT * FROM users WHERE username = ?", ('admin',))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                ('admin', hash_password('admin123'), 'admin', 'Administrator')
            )
        
        # Doctor user
        cur.execute("SELECT * FROM users WHERE username = ?", ('doctor',))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                ('doctor', hash_password('doctor123'), 'doctor', 'Dr. Asha Mehta')
            )
        
        # Nurse user
        cur.execute("SELECT * FROM users WHERE username = ?", ('nurse',))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                ('nurse', hash_password('nurse123'), 'nurse', 'Nurse Sarah')
            )
        
        # Receptionist user
        cur.execute("SELECT * FROM users WHERE username = ?", ('receptionist',))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                ('receptionist', hash_password('reception123'), 'receptionist', 'Reception Desk')
            )
        
        db.commit()
    except sqlite3.IntegrityError:
        pass
    
    db.commit()

def verify_user(username, password):
    """Verify user credentials and return user data if valid"""
    db = get_db()
    cur = db.cursor()
    password_hash = hash_password(password)
    cur.execute(
        "SELECT id, username, role, full_name FROM users WHERE username = ? AND password_hash = ?",
        (username, password_hash)
    )
    return cur.fetchone()

def get_user_by_id(user_id):
    """Get user data by ID"""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, role, full_name FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()
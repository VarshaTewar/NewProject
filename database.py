import sqlite3
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
    on_duty INTEGER DEFAULT 0
)""",
"""CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    quantity INTEGER DEFAULT 0
)"""
]

_conn = None
def get_db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn

def init_db():
    db = get_db(); cur = db.cursor()
    for sql in CREATE_TABLES_SQL:
        cur.execute(sql)
    db.commit()

# create_database.py
import sqlite3
from werkzeug.security import generate_password_hash

DB = 'database.db'

conn = sqlite3.connect(DB)
c = conn.cursor()

# users
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    features TEXT,
    department TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
''')

# posts (posts + announcements)
c.execute('''
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'post', -- post | announcement
    author_id INTEGER,
    author_username TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
''')

# staff
c.execute('''
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    job_title TEXT,
    department TEXT,
    birthday TEXT,
    contact TEXT,
    photo TEXT
)
''')

# tickets
c.execute('''
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_number TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    created_by INTEGER,
    assigned_department TEXT,
    assigned_to_user INTEGER,
    assigned_to_username TEXT,
    assigned_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
''')

c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tickets_ticket_number ON tickets(ticket_number)")

# daily updates (single pinned image)
c.execute('''
CREATE TABLE IF NOT EXISTS daily_updates (
    id INTEGER PRIMARY KEY,
    image_filename TEXT,
    uploaded_at TEXT,
    uploaded_by INTEGER
)
''')

c.execute("SELECT id FROM daily_updates WHERE id = 1")
if not c.fetchone():
    c.execute("INSERT INTO daily_updates (id, image_filename, uploaded_at, uploaded_by) VALUES (1, NULL, NULL, NULL)")

# ticket comments (status change logs and comments)
c.execute('''
CREATE TABLE IF NOT EXISTS ticket_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    user_id TEXT,
    username TEXT NOT NULL,
    comment TEXT,
    status_change TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id)
)
''')

# messages (chat)
c.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    read INTEGER DEFAULT 0
)
''')

# default admin (only if not exists)
c.execute("SELECT id FROM users WHERE username = ?", ('admin',))
if not c.fetchone():
    hashed = generate_password_hash('admin123')
    # admin مع صلاحيات النشر
    c.execute("INSERT INTO users (username, password, role, features, department) VALUES (?, ?, ?, ?, ?)",
              ('admin', hashed, 'admin', 'read,posts,announcements', 'IT'))

conn.commit()
conn.close()
print("✅ database.db created/checked and default admin ensured.")

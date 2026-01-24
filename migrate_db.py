# migrate_db.py
import sqlite3
import shutil
from datetime import datetime
from werkzeug.security import generate_password_hash

DB = 'database.db'

def backup_db(path=DB):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    dest = f'db_backup_{ts}.sqlite'
    shutil.copyfile(path, dest)
    print(f"Backup created: {dest}")

def table_exists(c, name):
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return bool(c.fetchone())

def column_exists(c, table, column):
    c.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in c.fetchall()]
    return column in cols

def ensure_columns(c):
    # users
    if table_exists(c, 'users'):
        if not column_exists(c, 'users', 'role'):
            c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            print("Added column role to users")
        if not column_exists(c, 'users', 'features'):
            c.execute("ALTER TABLE users ADD COLUMN features TEXT")
            print("Added column features to users")
        if not column_exists(c, 'users', 'department'):
            c.execute("ALTER TABLE users ADD COLUMN department TEXT")
            print("Added column department to users")

    # posts
    if table_exists(c, 'posts'):
        if not column_exists(c, 'posts', 'type'):
            c.execute("ALTER TABLE posts ADD COLUMN type TEXT DEFAULT 'post'")
            print("Added column type to posts")
        if not column_exists(c, 'posts', 'author_id'):
            c.execute("ALTER TABLE posts ADD COLUMN author_id INTEGER")
            print("Added column author_id to posts")
        if not column_exists(c, 'posts', 'author_username'):
            c.execute("ALTER TABLE posts ADD COLUMN author_username TEXT")
            print("Added column author_username to posts")

    # staff — وحّدنا العمود birthday (مش birth_date)
    if table_exists(c, 'staff'):
        if not column_exists(c, 'staff', 'birthday'):
            # لو كان فيه birth_date هنضيف birthday وننقل
            if column_exists(c, 'staff', 'birth_date'):
                c.execute("ALTER TABLE staff ADD COLUMN birthday TEXT")
                c.execute("UPDATE staff SET birthday = birth_date")
                print("Migrated birth_date -> birthday")
            else:
                c.execute("ALTER TABLE staff ADD COLUMN birthday TEXT")
                print("Added column birthday to staff")

def hash_plain_passwords(c):
    c.execute("SELECT id, password FROM users")
    rows = c.fetchall()
    updated = 0
    for uid, pwd in rows:
        pwd = pwd or ''
        if not pwd.startswith('pbkdf2:'):
            new = generate_password_hash(pwd)
            c.execute("UPDATE users SET password = ? WHERE id = ?", (new, uid))
            updated += 1
    print(f"Hashed {updated} plain passwords (if any).")

def run_migration(db_path=DB):
    backup_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    ensure_columns(c); conn.commit()
    hash_plain_passwords(c); conn.commit()

    conn.close()
    print("✅ Migration finished.")
    
if __name__ == '__main__':
    run_migration()

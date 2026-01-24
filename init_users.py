import sqlite3

conn = sqlite3.connect('hotel.db')
c = conn.cursor()

# إضافة عمود features لو مش موجود
c.execute("ALTER TABLE users ADD COLUMN features TEXT")

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

conn.commit()
conn.close()

print("✅ users table created.")

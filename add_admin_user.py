import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('hotel.db')
c = conn.cursor()

username = 'xadmin'
password = '123456'
hashed_password = generate_password_hash(password)
role = 'admin'
features = 'dashboard,posts,employees'  # حسب ما تحب

# Check if user already exists
c.execute("SELECT * FROM users WHERE username = ?", (username,))
if c.fetchone():
    print("User already exists.")
else:
    c.execute("INSERT INTO users (username, password, role, features) VALUES (?, ?, ?, ?)",
              (username, hashed_password, role, features))
    conn.commit()
    print("Admin user added.")

conn.close()

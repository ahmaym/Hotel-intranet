from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from ldap3 import Server, Connection, ALL, NTLM
import sqlite3
from functools import wraps
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room
from os import path
from flask import session
import logging



# =================== CONFIG ====================
APP_DB = 'database.db'

app = Flask(__name__)

app.secret_key = 'change_this_secret_to_something_secure'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Active Directory settings
app.config['LDAP_HOST'] = '10.10.100.100'
app.config['LDAP_PORT'] = 389
app.config['LDAP_USE_SSL'] = False
app.config['LDAP_BASE_DN'] = 'DC=HBERC-DOMAIN,DC=COM'
app.config['LDAP_DOMAIN'] = 'HBERC-DOMAIN'

# =================== DB ====================
def get_db():
    conn = sqlite3.connect(APP_DB)
    conn.row_factory = sqlite3.Row
    return conn

def parse_features(s):
    if not s:
        return []
    return [x.strip().lower() for x in s.split(',') if x.strip()]

# =================== LDAP / AD AUTH ====================
def authenticate_ldap_user(username, password):
    """
    Authenticate user with Active Directory and read Level from HRCW OU or group.
    Returns (department, role, display_name, features) on success, or None on failure.
    """
    from ldap3 import Server, Connection, ALL, SIMPLE

    LDAP_HOST = app.config.get('LDAP_HOST')
    LDAP_PORT = app.config.get('LDAP_PORT', 389)
    USE_SSL = app.config.get('LDAP_USE_SSL', False)
    BASE_DN = app.config.get('LDAP_BASE_DN')
    DOMAIN = app.config.get('LDAP_DOMAIN')

    # Use UPN format for simple bind
    user_bind = f"{username}@{DOMAIN}.COM" if not username.endswith(f"@{DOMAIN}.COM") else username

    try:
        server = Server(LDAP_HOST, port=LDAP_PORT, use_ssl=USE_SSL, get_info=ALL)
        conn = Connection(server, user=user_bind, password=password, authentication=SIMPLE, receive_timeout=10)
        if not conn.bind():
            # bind failed
            print("[LDAP] bind failed:", conn.result)
            return None

        # search for the user entry to get distinguishedName, memberOf, department, displayName
        conn.search(
            search_base=BASE_DN,
            search_filter=f'(sAMAccountName={username})',
            attributes=['distinguishedName', 'memberOf', 'department', 'displayName']
        )

        if not conn.entries:
            conn.unbind()
            return None

        entry = conn.entries[0]
        dn = str(entry.distinguishedName) if 'distinguishedName' in entry else ''
        member_of = str(entry.memberOf) if 'memberOf' in entry else ''
        department = str(entry.department) if 'department' in entry and entry.department else 'General'
        display_name = str(entry.displayName) if 'displayName' in entry and entry.displayName else username

        # Determine role & features based on Level in DN or memberOf
        role = 'viewer'
        features = 'read'

        # Prefer detecting Level0..Level4 in DN first, then memberOf
        if 'OU=Level0' in dn or 'Level0' in member_of:
            role = 'admin'
            features = 'manage_users,read,posts,announcements,edit,delete'
        elif 'OU=Level1' in dn or 'Level1' in member_of:
            role = 'manager'
            features = 'read,posts,announcements,approve'
        elif 'OU=Level2' in dn or 'Level2' in member_of:
            role = 'supervisor'
            features = 'read,posts'
        elif 'OU=Level3' in dn or 'Level3' in member_of:
            role = 'staff'
            features = 'read'
        elif 'OU=Level4' in dn or 'Level4' in member_of:
            role = 'viewer'
            features = 'read'

        conn.unbind()
        return (department, role, display_name, features)
    except Exception as e:
        print("[LDAP] Exception:", e)
        return None

# =================== DECORATORS ====================
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin privileges are required to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapped
# =================== Alert ====================

@app.route('/add_alert', methods=['GET', 'POST'])
@admin_required
def add_alert():
    if request.method == 'POST':
        title = request.form['title']
        message = request.form['message']

        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO announcements (title, message, created_at) VALUES (?, ?, datetime('now'))", (title, message))
        conn.commit()
        conn.close()

        flash('Announcement added successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_alert.html')

# =================== AUTH ====================
@app.route('/')
def root():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # المحاولة الأولى: التحقق من الـ Active Directory
                # المحاولة الأولى: التحقق من الـ Active DIRECTORY
        ldap_result = authenticate_ldap_user(username, password)
        if ldap_result:
            department, role, display_name, features = ldap_result
            session['user_id'] = username  # 👈 استخدم الاسم الحقيقي من الـAD
            session['username'] = username
            session['role'] = role
            session['department'] = department
            session['features'] = features


            flash('Logged in successfully via Active Directory.', 'success')
            return redirect(url_for('dashboard'))

        # لو فشل الـ AD login، نرجع نجرب قاعدة البيانات المحلية
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, username, password, role, features, department FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row['password'], password):
            session['user_id'] = row['id']
            session['username'] = row['username']
            session['role'] = row['role']
            session['features'] = row['features'] or ''
            session['department'] = row['department'] or ''
            flash('Logged in successfully (local).', 'success')
            return redirect(url_for('dashboard'))
        else:
            error = 'اسم المستخدم أو كلمة المرور غير صحيحة'


    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =================== DASHBOARD ====================
@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    feats = parse_features(session.get('features', ''))

    if request.method == 'POST':
        ptype = request.form.get('type', 'post')
        if session.get('role') != 'admin':
            if ptype == 'post' and 'posts' not in feats:
                flash('You are not allowed to post.', 'danger')
                return redirect(url_for('dashboard'))
            if ptype == 'announcement' and 'announcements' not in feats:
                flash('You are not allowed to publish announcements.', 'danger')
                return redirect(url_for('dashboard'))

        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title or not content:
            flash('Title and content are required.', 'warning')
        else:
            c.execute("""
                INSERT INTO posts (title, content, type, author_id, author_username, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (title, content, ptype, session['user_id'], session['username'],
                  datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            flash('Post published successfully.', 'success')
            return redirect(url_for('dashboard'))

    c.execute("SELECT id, title, content, type, author_username, created_at FROM posts WHERE type = 'announcement' ORDER BY created_at DESC LIMIT 5")
    announcements = c.fetchall()

    c.execute("SELECT id, title, content, type, author_username, created_at FROM posts WHERE type = 'post' ORDER BY created_at DESC LIMIT 20")
    posts = c.fetchall()

    today_md = datetime.now().strftime('%m-%d')
    try:
        c.execute("""
            SELECT name, job_title 
            FROM staff 
            WHERE birthday IS NOT NULL 
              AND strftime('%m-%d', birthday) = ?
        """, (today_md,))
        birthdays = c.fetchall()
    except sqlite3.OperationalError:
        birthdays = []

    conn.close()
    return render_template(
        'dashboard.html',
        announcements=announcements,
        posts=posts,
        birthdays=birthdays,
        features_list=feats,
        role=session.get('role')
    )
# =================== Posts and announcement ====================

@app.route('/delete_announcement/<int:ann_id>', methods=['POST'])
@login_required
def delete_announcement(ann_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM announcements WHERE id = ?", (ann_id,))
    conn.commit()
    conn.close()

    flash('Announcement deleted successfully.', 'success')
    return redirect(url_for('dashboard'))




@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()

    flash('Post deleted successfully.', 'success')
    return redirect(url_for('dashboard'))


# =================== USERS ====================
@app.route('/users')
@admin_required
def users_list():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username, role, department, features, created_at FROM users ORDER BY id")
    users = c.fetchall()
    conn.close()
    return render_template('users.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        features = request.form.getlist('features')
        features_str = ",".join(features)
        department = request.form.get('department', '').strip()

        if not username or not password:
            flash('Please fill in the required fields.', 'warning')
            return redirect(url_for('add_user'))

        hashed = generate_password_hash(password)
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("""
                INSERT INTO users (username, password, role, department, features)
                VALUES (?, ?, ?, ?, ?)
            """, (username, hashed, role, department, features_str))
            conn.commit()
            flash('User added successfully.', 'success')
            return redirect(url_for('users_list'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        finally:
            conn.close()

    feature_options = ['read', 'posts', 'announcements']  # للاختيار
    return render_template('add_user.html', feature_options=feature_options)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        department = request.form.get('department', '').strip()
        features = request.form.getlist('features')
        features_str = ",".join(features)

        if password:
            hashed = generate_password_hash(password)
            c.execute("""UPDATE users 
                         SET username=?, password=?, role=?, department=?, features=? 
                         WHERE id=?""",
                      (username, hashed, role, department, features_str, user_id))
        else:
            c.execute("""UPDATE users 
                         SET username=?, role=?, department=?, features=? 
                         WHERE id=?""",
                      (username, role, department, features_str, user_id))
        conn.commit()
        conn.close()
        flash("User updated successfully.", "success")
        return redirect(url_for('users_list'))
    else:
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        conn.close()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('users_list'))
        return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete yourself.', 'warning'); return redirect(url_for('users_list'))
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,)); conn.commit(); conn.close()
    flash('User deleted successfully.', 'success'); return redirect(url_for('users_list'))
# =================== STAFF ====================
@app.route('/staff')
@login_required
def staff_list():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, name, job_title, department, birthday FROM staff ORDER BY name")
    staff = c.fetchall(); conn.close()
    return render_template('staff.html', staff=staff)

@app.route('/add_staff', methods=['GET','POST'])
@admin_required
def add_staff():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        job_title = request.form.get('job_title','').strip()
        birthday = request.form.get('birthday','').strip()
        department = request.form.get('department','').strip()
        conn = get_db(); c = conn.cursor()
        c.execute("INSERT INTO staff (name, job_title, department, birthday) VALUES (?, ?, ?, ?)",
                  (name, job_title, department, birthday))
        conn.commit(); conn.close(); flash(f"Employee {name} added successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('add_staff.html')

@app.route('/edit_staff/<int:staff_id>', methods=['GET', 'POST'])
@admin_required
def edit_staff(staff_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, job_title, department, birthday FROM staff WHERE id=?", (staff_id,))
    staff = c.fetchone()
    if not staff:
        conn.close()
        flash("Employee not found.", "warning")
        return redirect(url_for("staff_list"))

    if request.method == 'POST':
        name = request.form.get('name','').strip()
        job_title = request.form.get('job_title','').strip()
        birthday = request.form.get('birthday','').strip()
        department = request.form.get('department','').strip()

        c.execute("""
            UPDATE staff SET name=?, job_title=?, department=?, birthday=? WHERE id=?
        """, (name, job_title, department, birthday, staff_id))
        conn.commit()
        conn.close()
        flash("Employee details updated successfully.", "success")
        return redirect(url_for("staff_list"))

    conn.close()
    return render_template("edit_staff.html", staff=staff)

@app.route('/delete_staff/<int:staff_id>', methods=['POST'])
@admin_required
def delete_staff(staff_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM staff WHERE id=?", (staff_id,))
    conn.commit()
    conn.close()
    flash("تم حذف الموظف.", "success")
    return redirect(url_for("staff_list"))
# =================== TICKETS ====================
@app.route('/tickets', methods=['GET','POST'])
@login_required
def tickets():
    conn = get_db()
    c = conn.cursor()

    if request.method == 'POST':
        title = request.form.get('title','').strip()
        description = request.form.get('description','').strip()
        dept = request.form.get('department','IT')

        if not title or not description:
            flash("محتاج تكتب عنوان ووصف للتذكرة", "warning")
        else:
            c.execute("""
                INSERT INTO tickets (title, description, created_by, assigned_department)
                VALUES (?, ?, ?, ?)
            """, (title, description, session['user_id'], dept))
            conn.commit()
            flash("تم إرسال التذكرة", "success")

    if session.get("department") == "IT" or session.get("role") == "admin":
        c.execute("""SELECT t.*, u.username FROM tickets t 
                    LEFT JOIN users u ON t.created_by=u.id 
                    ORDER BY created_at DESC""")
    else:
        c.execute("""SELECT t.*, u.username FROM tickets t 
                    LEFT JOIN users u ON t.created_by=u.id 
                    WHERE created_by = ? ORDER BY created_at DESC""", (session['user_id'],))

    tickets = c.fetchall()
    conn.close()
    return render_template("tickets.html", tickets=tickets)

@app.route('/ticket/<int:ticket_id>/status', methods=['POST'])
@login_required
def update_ticket_status(ticket_id):
    if session.get("department") != "IT" and session.get("role") != "admin":
        flash("مش مسموح تغير حالة التذكرة", "danger")
        return redirect(url_for("tickets"))

    status = request.form.get("status","open")
    conn = get_db()
    conn.execute("UPDATE tickets SET status=? WHERE id=?", (status, ticket_id))
    conn.commit()
    conn.close()
    flash("تم تحديث حالة التذكرة", "success")
    return redirect(url_for("tickets"))

# ==================== CHAT SYSTEM (ACTIVE DIRECTORY) ====================

from ldap3 import Server, Connection, ALL, NTLM
from flask_socketio import SocketIO, emit, join_room

socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
connected_users = {}

# Add debug logs to track user fetching and message delivery
logging.basicConfig(level=logging.DEBUG)

# دالة تجيب المستخدمين من الـ Active Directory
def get_ad_users(search_query=None):
    users = []
    try:
        logging.debug("Attempting to connect to Active Directory...")
        server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'], get_info=ALL)
        conn = Connection(
            server,
            user=f"{app.config['LDAP_DOMAIN']}\\{session['user_id']}",  # Use the logged-in user's credentials
            password=session.get('password'),  # Assuming password is stored in session
            authentication=NTLM,
            auto_bind=True
        )

        if not conn.bind():
            logging.error(f"Failed to bind to AD server: {conn.result}")
            return []

        logging.debug("Successfully connected to Active Directory.")

        # Modify the search filter to include the search query if provided
        search_filter = f'(objectClass=user)'
        if search_query:
            search_filter = f'(&(objectClass=user)(|(sAMAccountName=*{search_query}*)(displayName=*{search_query}*)))'

        logging.debug(f"Using search filter: {search_filter}")

        conn.search(app.config['LDAP_BASE_DN'], search_filter, attributes=['sAMAccountName', 'displayName', 'department'])
        for entry in conn.entries:
            username = str(entry.sAMAccountName)
            display_name = str(entry.displayName) if 'displayName' in entry else username
            department = str(entry.department) if 'department' in entry else ''
            if username:
                users.append({'username': username, 'display_name': display_name, 'department': department})

        conn.unbind()
        logging.debug(f"Fetched users from AD: {users}")
    except Exception as e:
        logging.error("Error while fetching users from AD:", exc_info=e)
    return users


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if 'user_id' not in session:
        logging.error("User ID not found in session. Redirecting to login.")
        return redirect(url_for('login'))

    logging.debug(f"Fetching AD users for user: {session['user_id']}")
    search_query = request.args.get('search', '') if request.method == 'GET' else None
    ad_users = get_ad_users(search_query)

    if not ad_users:
        logging.warning("No users found in Active Directory.")

    return render_template('chat.html', users=ad_users)


@socketio.on('connect')
def handle_connect():
    username = session.get('user_id')
    if username:
        connected_users[username] = request.sid
        logging.debug(f"User connected: {username}, SID: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('user_id')
    if username in connected_users:
        del connected_users[username]
        logging.debug(f"User disconnected: {username}")

@socketio.on('send_message')
def handle_send_message(data):
    sender = data['sender']
    receiver = data['receiver']
    message = data['message']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    logging.debug(f"Message received: sender={sender}, receiver={receiver}, message={message}")

    conn = sqlite3.connect(APP_DB)
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)",
              (sender, receiver, message, timestamp))
    conn.commit()
    conn.close()

    if receiver in connected_users:
        logging.debug(f"Sending message to connected user: {receiver}")
        emit('receive_message', {
            'sender': sender,
            'receiver': receiver,
            'message': message
        }, room=connected_users[receiver])
    else:
        logging.warning(f"Receiver {receiver} is not connected.")

    emit('receive_message', {
        'sender': sender,
        'receiver': receiver,
        'message': message
    }, room=request.sid)


# =================== RUN ====================
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

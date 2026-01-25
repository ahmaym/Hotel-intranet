from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE
import sqlite3
from functools import wraps
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room
from os import path
from flask import session
import logging
from werkzeug.utils import secure_filename
import openpyxl



# =================== CONFIG ====================
APP_DB = 'database.db'

app = Flask(__name__)

app.secret_key = 'change_this_secret_to_something_secure'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# File upload configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
UPLOAD_FOLDER = 'uploads'

# Active Directory settings
app.config['LDAP_HOST'] = '10.10.100.100'
app.config['LDAP_PORT'] = 389
app.config['LDAP_USE_SSL'] = False
app.config['LDAP_BASE_DN'] = 'DC=HBERC-DOMAIN,DC=COM'
app.config['LDAP_DOMAIN'] = 'HBERC-DOMAIN'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
            session['password'] = password  # Store password for AD queries in chat

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
            error = 'Wrong username or password'


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

@app.route('/import_staff', methods=['GET', 'POST'])
@admin_required
def import_staff():
    """
    Import staff members from Excel file.
    Expected columns: Name, Job Title, Department, Birthday (optional)
    """
    if request.method == 'POST':
        # Check if file is in request
        if 'file' not in request.files:
            flash('❌ No file selected. Please upload an Excel file.', 'danger')
            return redirect(url_for('import_staff'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('❌ No file selected. Please upload an Excel file.', 'danger')
            return redirect(url_for('import_staff'))
        
        if not allowed_file(file.filename):
            flash('❌ Invalid file format. Please upload an Excel file (.xlsx or .xls).', 'danger')
            return redirect(url_for('import_staff'))
        
        try:
            # Load Excel file
            wb = openpyxl.load_workbook(file)
            ws = wb.active
            
            # Get headers from first row
            headers = []
            for cell in ws[1]:
                if cell.value:
                    headers.append(cell.value.strip().lower())
            
            if not headers:
                flash('❌ Excel file is empty. Please add headers and data.', 'danger')
                return redirect(url_for('import_staff'))
            
            # Validate required columns
            required_cols = {'name', 'job title', 'department'}
            found_cols = {col for col in headers}
            
            if not required_cols.issubset(found_cols):
                missing = required_cols - found_cols
                flash(f'❌ Missing required columns: {", ".join(missing)}', 'danger')
                return redirect(url_for('import_staff'))
            
            # Find column indices
            col_map = {header: idx + 1 for idx, header in enumerate(headers)}
            
            # Process data rows
            conn = get_db()
            c = conn.cursor()
            
            added_count = 0
            error_rows = []
            
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                try:
                    # Get values from columns
                    name = str(row[col_map['name'] - 1]).strip() if row[col_map['name'] - 1] else ''
                    job_title = str(row[col_map['job title'] - 1]).strip() if row[col_map['job title'] - 1] else ''
                    department = str(row[col_map['department'] - 1]).strip() if row[col_map['department'] - 1] else ''
                    birthday = str(row[col_map.get('birthday', 0) - 1]).strip() if col_map.get('birthday') and row[col_map['birthday'] - 1] else ''
                    
                    # Validate required fields
                    if not name or not job_title or not department:
                        error_rows.append(f"Row {row_idx}: Missing required fields (Name, Job Title, Department)")
                        continue
                    
                    # Check if employee already exists
                    c.execute("SELECT id FROM staff WHERE name=? AND job_title=?", (name, job_title))
                    if c.fetchone():
                        error_rows.append(f"Row {row_idx}: Employee '{name}' already exists")
                        continue
                    
                    # Insert new staff member
                    c.execute(
                        "INSERT INTO staff (name, job_title, department, birthday) VALUES (?, ?, ?, ?)",
                        (name, job_title, department, birthday if birthday else None)
                    )
                    added_count += 1
                    
                except Exception as e:
                    error_rows.append(f"Row {row_idx}: {str(e)}")
            
            # Commit changes
            conn.commit()
            conn.close()
            
            # Flash results
            if added_count > 0:
                flash(f'✅ Successfully imported {added_count} staff member(s).', 'success')
            
            if error_rows:
                error_msg = '<br>'.join(error_rows[:5])  # Show first 5 errors
                if len(error_rows) > 5:
                    error_msg += f'<br>... and {len(error_rows) - 5} more errors'
                flash(f'⚠️ Import completed with {len(error_rows)} error(s):<br>{error_msg}', 'warning')
            
            if added_count == 0 and error_rows:
                flash('❌ No staff members were imported. Please check the errors above.', 'danger')
            
            return redirect(url_for('staff_list'))
        
        except Exception as e:
            flash(f'❌ Error processing file: {str(e)}', 'danger')
            return redirect(url_for('import_staff'))
    
    return render_template('import_staff.html')

@app.route('/download_staff_template')
@admin_required
def download_staff_template():
    """Generate and download a sample Excel template for staff import"""
    from io import BytesIO
    
    # Create a new workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Staff"
    
    # Add headers
    headers = ["Name", "Job Title", "Department", "Birthday"]
    ws.append(headers)
    
    # Style header row
    from openpyxl.styles import Font, PatternFill, Alignment
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF")
    
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")
    
    # Add sample data
    sample_data = [
        ["احمد محمد", "مدير الفندق", "الإدارة", "1990-05-15"],
        ["فاطمة علي", "موظفة استقبال", "الاستقبال", "1995-03-20"],
        ["محمود حسن", "عامل النظافة", "الصيانة", "1988-07-10"],
    ]
    
    for row_data in sample_data:
        ws.append(row_data)
    
    # Adjust column widths
    ws.column_dimensions['A'].width = 20
    ws.column_dimensions['B'].width = 25
    ws.column_dimensions['C'].width = 20
    ws.column_dimensions['D'].width = 15
    
    # Create in-memory file
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='staff_template.xlsx'
    )

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
    flash("Employee deleted successfully.", "success")
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
            flash("Title and description are required for the ticket.", "warning")
        else:
            c.execute("""
                INSERT INTO tickets (title, description, created_by, assigned_department)
                VALUES (?, ?, ?, ?)
            """, (title, description, session['user_id'], dept))
            conn.commit()
            flash("Ticket submitted successfully.", "success")

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
        flash("You do not have permission to update ticket status.", "danger")
        return redirect(url_for("tickets"))

    status = request.form.get("status","open")
    conn = get_db()
    conn.execute("UPDATE tickets SET status=? WHERE id=?", (status, ticket_id))
    conn.commit()
    conn.close()
    flash("Ticket status updated successfully.", "success")
    return redirect(url_for("tickets"))

# ==================== CHAT SYSTEM (ACTIVE DIRECTORY) ====================

from ldap3 import Server, Connection, ALL, NTLM
from flask_socketio import SocketIO, emit, join_room

socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")
connected_users = {}

# Add debug logs to track user fetching and message delivery
logging.basicConfig(level=logging.DEBUG)

# Function to fetch users from Active Directory
def get_ad_users(search_query=None):
    """Fetch users from Active Directory using UPN format (same as login)"""
    users = []
    try:
        logging.debug(f"[AD] Starting user fetch with search_query: '{search_query}'")
        
        # Check session
        if 'user_id' not in session:
            logging.error("[AD] User ID not in session")
            return []
        if 'password' not in session:
            logging.error("[AD] Password not in session")
            return []
        
        user_id = session.get('user_id')
        password = session.get('password')
        
        logging.debug(f"[AD] Using credentials - User: {user_id}, Password length: {len(password) if password else 0}")
        
        # Create server connection
        logging.debug(f"[AD] Connecting to {app.config['LDAP_HOST']}:{app.config['LDAP_PORT']}")
        server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'], get_info=ALL)
        
        # Use UPN format (same as login) with SIMPLE authentication
        user_bind = f"{user_id}@{app.config['LDAP_DOMAIN']}.COM"
        logging.debug(f"[AD] Using UPN bind: {user_bind}")
        
        conn = Connection(
            server,
            user=user_bind,
            password=password,
            authentication=SIMPLE
        )

        if not conn.bind():
            logging.error(f"[AD] Failed to bind to AD server: {conn.result}")
            return []

        logging.debug("[AD] Successfully bound to Active Directory")

        # Modify the search filter to include the search query if provided
        search_filter = '(objectClass=user)'
        if search_query:
            search_filter = f'(&(objectClass=user)(|(sAMAccountName=*{search_query}*)(displayName=*{search_query}*)))'

        logging.debug(f"[AD] Using search base: {app.config['LDAP_BASE_DN']}")
        logging.debug(f"[AD] Using search filter: {search_filter}")

        conn.search(app.config['LDAP_BASE_DN'], search_filter, attributes=['sAMAccountName', 'displayName', 'department', 'mail'])
        
        logging.debug(f"[AD] Search returned {len(conn.entries)} entries")
        
        for entry in conn.entries:
            username = str(entry.sAMAccountName) if 'sAMAccountName' in entry else ''
            display_name = str(entry.displayName) if 'displayName' in entry else username
            department = str(entry.department) if 'department' in entry else 'No Department'
            email = str(entry.mail) if 'mail' in entry else ''
            
            logging.debug(f"[AD] Processing entry - username: {username}, display_name: {display_name}")
            
            if username and username.lower() != user_id.lower():  # Exclude current user (case-insensitive)
                users.append({
                    'username': username,
                    'display_name': display_name,
                    'department': department,
                    'email': email
                })

        conn.unbind()
        logging.debug(f"[AD] Fetched {len(users)} users from AD")
    except Exception as e:
        logging.error(f"[AD] Exception occurred: {str(e)}", exc_info=True)
    
    logging.debug(f"[AD] Returning {len(users)} users")
    return users


@app.route('/chat')
@login_required
def chat():
    if 'user_id' not in session:
        logging.error("User ID not found in session. Redirecting to login.")
        return redirect(url_for('login'))

    logging.debug(f"Loading chat page for user: {session['user_id']}")
    ad_users = get_ad_users()
    return render_template('chat.html', users=ad_users)

@app.route('/api/chat/users/search', methods=['GET'])
def api_chat_users_search():
    """API endpoint to search for users in Active Directory using UPN format"""
    print("[API] /api/chat/users/search called")
    
    # Check if user is logged in
    if 'user_id' not in session:
        print("[API] User not logged in")
        return jsonify([]), 401
    
    search_term = request.args.get('search', '').strip()
    print(f"[API] Search term: '{search_term}'")
    
    try:
        # Get stored password from session
        password = session.get('password')
        username = session.get('user_id')
        
        print(f"[API] Session username: {username}")
        print(f"[API] Session password exists: {bool(password)}")
        
        if not password or not username:
            print("[API] Missing password or username in session")
            return jsonify([]), 401
        
        # Connect to AD using UPN format (same as login) with SIMPLE authentication
        print(f"[API] Connecting to AD: {app.config['LDAP_HOST']}:{app.config['LDAP_PORT']}")
        server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'], get_info=ALL)
        
        # Use UPN format like login does
        user_bind = f"{username}@{app.config['LDAP_DOMAIN']}.COM"
        print(f"[API] Using UPN bind: {user_bind}")
        
        conn = Connection(server, user=user_bind, password=password, authentication=SIMPLE)
        
        if not conn.bind():
            print(f"[API] Failed to bind with UPN: {user_bind}")
            print(f"[API] Bind result: {conn.result}")
            return jsonify([]), 401
        
        print("[API] Successfully bound to AD")
        
        # Search filter
        if search_term:
            search_filter = f'(&(objectClass=user)(|(displayName=*{search_term}*)(sAMAccountName=*{search_term}*)))'
        else:
            search_filter = '(objectClass=user)'
        
        print(f"[API] Search filter: {search_filter}")
        
        conn.search(
            search_base=app.config['LDAP_BASE_DN'],
            search_filter=search_filter,
            attributes=['sAMAccountName', 'displayName', 'department', 'mail']
        )
        
        print(f"[API] Search returned {len(conn.entries)} entries")
        
        users = []
        for entry in conn.entries:
            try:
                username_val = str(entry.sAMAccountName).strip() if entry.sAMAccountName else 'Unknown'
                display_name_val = str(entry.displayName).strip() if entry.displayName else username_val
                
                # Exclude current user (case-insensitive comparison)
                if username_val.lower() != username.lower():
                    users.append({
                        'username': username_val,
                        'display_name': display_name_val,
                        'department': str(entry.department).strip() if entry.department else 'No Department',
                        'email': str(entry.mail).strip() if entry.mail else ''
                    })
                    print(f"[API] Added user: {username_val} - {display_name_val}")
            except Exception as e:
                print(f"[API] Error processing entry: {str(e)}")
        
        conn.unbind()
        print(f"[API] Returning {len(users)} users")
        return jsonify(users), 200
        
    except Exception as e:
        print(f"[API] EXCEPTION: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify([]), 500

@app.route('/api/chat/messages/<receiver_username>', methods=['GET'])
@login_required
def get_chat_messages(receiver_username):
    """Fetch chat message history between current user and receiver"""
    sender = session.get('user_id')
    print(f"[MSG] Loading message history for {sender} <-> {receiver_username}")
    
    try:
        conn = sqlite3.connect(APP_DB)
        c = conn.cursor()
        
        # Get all messages between these two users (in both directions)
        c.execute("""
            SELECT sender, receiver, message, timestamp 
            FROM messages 
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ORDER BY timestamp ASC
        """, (sender, receiver_username, receiver_username, sender))
        
        messages = []
        for row in c.fetchall():
            messages.append({
                'sender': row[0],
                'receiver': row[1],
                'message': row[2],
                'timestamp': row[3]
            })
        
        conn.close()
        print(f"[MSG] Loaded {len(messages)} messages for {sender} with {receiver_username}")
        return jsonify(messages), 200
        
    except Exception as e:
        logging.error(f"[MSG] Error loading messages: {str(e)}")
        return jsonify([]), 500

@app.route('/api/chat/unread', methods=['GET'])
@login_required
def get_unread_messages():
    """Get all unread messages for the current user"""
    receiver = session.get('user_id')
    print(f"[UNREAD] Fetching unread messages for {receiver}")
    
    try:
        conn = sqlite3.connect(APP_DB)
        c = conn.cursor()
        
        # Get all unread messages for this user
        c.execute("""
            SELECT id, sender, receiver, message, timestamp 
            FROM messages 
            WHERE receiver = ? AND read = 0
            ORDER BY timestamp ASC
        """, (receiver,))
        
        unread_messages = []
        for row in c.fetchall():
            unread_messages.append({
                'id': row[0],
                'sender': row[1],
                'receiver': row[2],
                'message': row[3],
                'timestamp': row[4]
            })
        
        conn.close()
        print(f"[UNREAD] Found {len(unread_messages)} unread messages for {receiver}")
        return jsonify(unread_messages), 200
        
    except Exception as e:
        logging.error(f"[UNREAD] Error loading unread messages: {str(e)}")
        return jsonify([]), 500

@app.route('/api/chat/mark-read/<int:message_id>', methods=['POST'])
@login_required
def mark_message_read(message_id):
    """Mark a message as read"""
    receiver = session.get('user_id')
    
    try:
        conn = sqlite3.connect(APP_DB)
        c = conn.cursor()
        
        # Mark message as read (only if receiver matches)
        c.execute(
            "UPDATE messages SET read = 1 WHERE id = ? AND receiver = ?",
            (message_id, receiver)
        )
        conn.commit()
        conn.close()
        
        print(f"[UNREAD] Marked message {message_id} as read for {receiver}")
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        logging.error(f"[UNREAD] Error marking message as read: {str(e)}")
        return jsonify({'status': 'error'}), 500

@app.route('/api/chat/mark-all-read/<sender_username>', methods=['POST'])
@login_required
def mark_all_read_from_sender(sender_username):
    """Mark all messages from a sender as read"""
    receiver = session.get('user_id')
    
    try:
        conn = sqlite3.connect(APP_DB)
        c = conn.cursor()
        
        # Mark all messages from this sender as read
        c.execute(
            "UPDATE messages SET read = 1 WHERE sender = ? AND receiver = ? AND read = 0",
            (sender_username, receiver)
        )
        count = c.rowcount
        conn.commit()
        conn.close()
        
        print(f"[UNREAD] Marked {count} messages from {sender_username} as read for {receiver}")
        return jsonify({'status': 'success', 'count': count}), 200
        
    except Exception as e:
        logging.error(f"[UNREAD] Error marking messages as read: {str(e)}")
        return jsonify({'status': 'error'}), 500

@app.route('/api/debug/session')
@login_required
def debug_session():
    """Debug endpoint to check session data"""
    return jsonify({
        'user_id': session.get('user_id'),
        'username': session.get('username'),
        'role': session.get('role'),
        'password_stored': 'password' in session,
        'password_length': len(session.get('password', ''))
    })

@app.route('/api/debug/ad-connection')
@login_required
def debug_ad_connection():
    """Debug endpoint to test AD connection using UPN format"""
    result = {
        'status': 'unknown',
        'message': '',
        'config': {
            'host': app.config['LDAP_HOST'],
            'port': app.config['LDAP_PORT'],
            'base_dn': app.config['LDAP_BASE_DN'],
            'domain': app.config['LDAP_DOMAIN']
        },
        'session': {
            'user_id': session.get('user_id'),
            'password_stored': 'password' in session
        }
    }
    
    try:
        if 'user_id' not in session or 'password' not in session:
            result['status'] = 'error'
            result['message'] = 'User ID or password not in session'
            return jsonify(result), 400
        
        user_id = session.get('user_id')
        password = session.get('password')
        
        logging.debug(f"[DEBUG] Attempting AD connection with user: {user_id}")
        
        server = Server(app.config['LDAP_HOST'], port=app.config['LDAP_PORT'], use_ssl=app.config['LDAP_USE_SSL'], get_info=ALL)
        # Use UPN format (same as login)
        user_bind = f"{user_id}@{app.config['LDAP_DOMAIN']}.COM"
        
        conn = Connection(
            server,
            user=user_bind,
            password=password,
            authentication=SIMPLE
        )

        if not conn.bind():
            result['status'] = 'error'
            result['message'] = f'Failed to bind: {conn.result}'
            return jsonify(result), 400
        
        # Try to search for users
        conn.search(app.config['LDAP_BASE_DN'], '(objectClass=user)', attributes=['sAMAccountName'], size_limit=10)
        
        user_count = len(conn.entries)
        conn.unbind()
        
        result['status'] = 'success'
        result['message'] = f'Connected successfully. Found {user_count} users'
        result['user_count'] = user_count
        
    except Exception as e:
        result['status'] = 'error'
        result['message'] = str(e)
        logging.error(f"[DEBUG] AD connection error: {str(e)}", exc_info=True)
    
    return jsonify(result)


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

# Send message using domain usernames for routing
@socketio.on('send_message')
def handle_send_message(data):
    sender = session.get('user_id')  # Always use the logged-in user as sender
    receiver = data.get('receiver', '').strip()
    message = data.get('message', '').strip()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    logging.debug(f"[CHAT] Message received: sender={sender}, receiver={receiver}")

    # Validate inputs
    if not receiver or not message:
        logging.warning(f"[CHAT] Invalid message data: receiver={receiver}, message length={len(message)}")
        emit('error', {'message': 'Invalid message data'}, room=request.sid)
        return

    if sender == receiver:
        logging.warning(f"[CHAT] User {sender} attempted to send message to themselves")
        emit('error', {'message': 'Cannot send message to yourself'}, room=request.sid)
        return

    # Verify receiver exists in AD using case-insensitive comparison
    try:
        # Quick AD check: try to get users and verify receiver exists
        ad_users = get_ad_users()
        receiver_exists = any(user['username'].lower() == receiver.lower() for user in ad_users)
        
        if not receiver_exists:
            logging.warning(f"[CHAT] Receiver {receiver} not found in AD")
            emit('error', {'message': f'User {receiver} not found'}, room=request.sid)
            return
        
        # Normalize receiver to match AD format (get the actual username case from AD)
        actual_receiver = next(user['username'] for user in ad_users if user['username'].lower() == receiver.lower())
        receiver = actual_receiver
        
        logging.debug(f"[CHAT] Receiver normalized to: {receiver}")
    except Exception as e:
        logging.error(f"[CHAT] Error validating receiver: {str(e)}")
        emit('error', {'message': 'Error validating user'}, room=request.sid)
        return

    # Store message in database
    try:
        conn = sqlite3.connect(APP_DB)
        c = conn.cursor()
        c.execute(
            "INSERT INTO messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)",
            (sender, receiver, message, timestamp)
        )
        conn.commit()
        conn.close()
        logging.debug(f"[CHAT] Message stored in DB: {sender} -> {receiver}")
    except Exception as e:
        logging.error(f"[CHAT] Error storing message: {str(e)}")
        emit('error', {'message': 'Error saving message'}, room=request.sid)
        return

    # Send the message to the recipient if they are connected
    message_data = {
        'sender': sender,
        'receiver': receiver,
        'message': message,
        'timestamp': timestamp
    }
    
    # Notify recipient if they're connected (real-time delivery)
    if receiver in connected_users:
        logging.debug(f"[CHAT] Sending real-time message to connected user: {receiver}")
        emit('receive_message', message_data, room=connected_users[receiver])
    else:
        logging.debug(f"[CHAT] Receiver {receiver} is offline. Message stored in DB for later retrieval.")

    # Send confirmation to sender
    emit('message_sent', {'status': 'success', 'message': 'Message sent'}, room=request.sid)
    emit('receive_message', message_data, room=request.sid)


# =================== RUN ====================
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

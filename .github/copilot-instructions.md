# Hotel Intranet - AI Coding Assistant Instructions

## Project Overview
**Hotel Intranet** is a Flask-based staff management system with Active Directory authentication, real-time chat (Socket.IO), staff records, support tickets, and organizational announcements.

## Architecture

### Core Components
- **Backend**: Flask 5.0+, SQLite database, LDAP/AD for authentication
- **Frontend**: HTML/CSS/JavaScript, RTL-ready (Arabic support), gradient-based design
- **Real-time**: Socket.IO for WebSocket-based chat
- **File Processing**: openpyxl for Excel import/export

### Data Flow
1. User → LDAP/AD authentication → Session creation → Dashboard/Features access
2. Dashboard → Posts/Announcements (role-based visibility)
3. Chat → Socket.IO connections → Message persistence in SQLite
4. Staff Management → Excel bulk import → Staff table with birthday/department tracking

## Critical Developer Workflows

### Database Setup
```bash
python create_database.py      # Creates schema & default admin (admin123)
python add_admin_user.py       # Add local admin user
python migrate_db.py           # Schema migrations
```

### Running the Application
```bash
python app.py                  # Starts Flask + Socket.IO on 0.0.0.0:5000
```

### Staff Import Process
- Excel template: `/download_staff_template` (generates sample)
- Required columns: Name, Job Title, Department (Birthday optional)
- API route: POST `/import_staff` with `.xlsx` file
- Duplicate detection: checks existing name+job_title combinations

## Key Architectural Patterns

### Role-Based Access Control (RBAC)
Roles determined by Active Directory OU hierarchy (`Level0` → `Level4`):
- **Level0/admin**: Full access (manage_users, read, posts, announcements, edit, delete)
- **Level1/manager**: Approvals (read, posts, announcements, approve)
- **Level2/supervisor**: Limited posting (read, posts)
- **Level3/staff**: View-only (read)
- **Level4/viewer**: View-only (read)

Features stored as comma-separated strings in session: `session['features']` → parsed by `parse_features()` → checked before action.

Fallback: If AD fails, authenticate against local SQLite `users` table.

### Authentication Dual-Mode
1. **Primary**: LDAP with UPN format (`username@HBERC-DOMAIN.COM`)
2. **Fallback**: Local SQLite with hashed passwords (werkzeug)
3. **Session Storage**: username, role, features, department + password (for AD queries during chat)

### Socket.IO Chat System
- **Connected Users Tracking**: `connected_users = {username: socket_id}`
- **Real-time Delivery**: Only if receiver connected; otherwise stored in DB
- **Message History**: Bidirectional query (sender→receiver OR receiver→sender)
- **User Directory**: Queries AD per session credentials; excludes self
- **Unread Tracking**: Boolean `read` flag in messages table; `/api/chat/mark-read` endpoint

### Staff Module Patterns
- **Birthday Tracking**: Uses SQLite `strftime('%m-%d', birthday)` for today's matches
- **Import Error Handling**: Row-level validation with detailed error reporting
- **Bulk Operations**: Commit after all rows processed
- **Photo Support**: Planned but not fully implemented (photo field in schema)

### Forms & Security
- **Flash Messages**: Categories (success/danger/warning) for UX feedback
- **File Upload**: 16MB max, `.xlsx`/`.xls` only, `secure_filename()` usage
- **CSRF**: Flask default (no explicit tokens; rely on session security)

## Frontend Design System

### Color Palette
- **Gradients**: Purple (#667eea→#764ba2), Red-Pink (#f5576c→#f093fb), Green, Blue
- **Typography**: Cairo font (Arabic-native), responsive sizing
- **Styling**: RTL-ready Bootstrap 5, custom `style.css` for gradients/animations

### Component Patterns
- **Messages**: Left-border colored cards (Announcements: red, Posts: blue, Birthdays: green)
- **Buttons**: Gradient backgrounds with hover lift effect (translateY -2px)
- **Tables**: Gradient header, hover states, proper contrast
- **Chat UI**: Bubble style (sent: purple right-aligned, received: white left-aligned)

## Critical Files & Their Roles

| File | Purpose | Key Patterns |
|------|---------|--------------|
| [app.py](app.py) | Main Flask app, all routes, Socket.IO handlers | Decorators: `@login_required`, `@admin_required` |
| [create_database.py](create_database.py) | Schema definition | All 5 core tables defined here |
| [templates/base.html](templates/base.html) | Navigation, header, flash messages | Conditional nav links based on role |
| [templates/chat.html](templates/chat.html) | Real-time chat UI | Socket.IO event listeners: `send_message`, `receive_message` |
| [static/style.css](static/style.css) | Gradient design system | Reusable gradient classes, animations |

## Common Development Tasks

### Adding a New Route
1. Define route in `app.py` with appropriate decorator (`@login_required`, `@admin_required`)
2. Use `get_db()` for SQLite access; always call `conn.close()`
3. Return `render_template()` or `redirect(url_for())`
4. Use `flash()` for user feedback
5. Create corresponding template in `templates/` directory

### Querying Users (AD vs Local)
```python
# AD users (for chat/search):
ad_users = get_ad_users(search_query='pattern')  # Returns list of dicts
# Local users (for management):
c.execute("SELECT * FROM users WHERE ...")
```

### Chat Message Flow
1. Client: `socket.emit('send_message', {receiver, message})`
2. Server: Validate receiver exists in AD, store in DB
3. Server: Emit to connected recipient or store for offline delivery
4. Client: Load history via `/api/chat/messages/<username>`

### Bulk Operations
- Use transactions: `conn.commit()` after loop completion
- Collect errors row-by-row for detailed feedback
- Return count + error list to user via `flash()`

## Configuration & Secrets

### LDAP/AD Settings (in app.py)
```python
app.config['LDAP_HOST'] = '10.10.100.100'
app.config['LDAP_PORT'] = 389
app.config['LDAP_BASE_DN'] = 'DC=HBERC-DOMAIN,DC=COM'
app.config['LDAP_DOMAIN'] = 'HBERC-DOMAIN'
```
**Change these before production!**

### Database
- Filename: `database.db` (SQLite 3)
- Default admin: username=`admin`, password=`admin123`

## Testing & Debugging

### Debug Endpoints (requires authentication)
- `/api/debug/session` → Current session data
- `/api/debug/ad-connection` → Test AD binding with current user credentials

### Logging
- BasicConfig: DEBUG level in `app.py`
- Prefixes: `[LDAP]`, `[CHAT]`, `[MSG]`, `[API]`, `[AD]` for filtering
- Socket.IO logs included; watch for connection/disconnect messages

### Common Issues
| Issue | Cause | Fix |
|-------|-------|-----|
| AD bind fails | Wrong UPN format, network unreachable | Check config, test with debug endpoint |
| Chat offline | User not in `connected_users`, message in DB | Load history via `/api/chat/messages/` |
| Import fails | Missing columns, malformed Excel | Validate headers, use template |

## Notes for AI Agents

1. **Passwords in Session**: Chat stores user password for AD queries during chat—security risk on production; consider token-based approach.
2. **SQLite Limitations**: No concurrent write support; production should use PostgreSQL.
3. **Arabic Support**: RTL-ready; ensure templates preserve Jinja directives for Arabic text.
4. **Excel Import**: File size limited to 16MB; batch processing not implemented for large datasets.
5. **Feature String**: Comma-separated, must be lowercase; parsed fresh each request.

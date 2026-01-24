# Hotel Intranet

A comprehensive hotel management intranet system built with Flask, featuring Active Directory authentication, staff management, ticket system, and real-time chat capabilities.

## Features

- **User Authentication**: Secure login with Active Directory (LDAP) integration
- **Dashboard**: Centralized view for hotel operations
- **Staff Management**: Add, edit, and manage hotel staff members
- **User Management**: User account administration and role-based access control
- **Ticket System**: Create and track support tickets
- **Real-time Chat**: WebSocket-enabled chat functionality for staff communication
- **Alerts System**: Send and manage alerts across the organization
- **Role-Based Access Control**: Different permission levels for admins, managers, and staff

## Tech Stack

- **Backend**: Python Flask
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite
- **Authentication**: LDAP/Active Directory
- **Real-time Communication**: Flask-SocketIO (WebSockets)
- **Security**: Werkzeug password hashing

## Project Structure

```
.
├── app.py                    # Main Flask application
├── create_database.py        # Database initialization script
├── init_users.py            # Initial user setup
├── add_admin_user.py        # Admin user creation utility
├── migrate_db.py            # Database migration script
├── static/
│   └── style.css            # Application styling
├── templates/
│   ├── base.html            # Base template
│   ├── login.html           # Login page
│   ├── dashboard.html       # Main dashboard
│   ├── staff.html           # Staff listing
│   ├── add_staff.html       # Add staff form
│   ├── edit_staff.html      # Edit staff form
│   ├── users.html           # Users listing
│   ├── add_user.html        # Add user form
│   ├── edit_user.html       # Edit user form
│   ├── tickets.html         # Support tickets
│   ├── add_alert.html       # Alert creation
│   ├── chat.html            # Real-time chat
│   └── index.html           # Home page
└── uploads/                 # User uploads directory
```

## Installation

### Prerequisites
- Python 3.7+
- Flask
- Flask-SocketIO
- ldap3
- Werkzeug

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/ahmaym/Hotel-intranet.git
   cd Hotel-intranet
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install flask flask-socketio python-socketio ldap3 werkzeug
   ```

4. **Initialize the database**
   ```bash
   python create_database.py
   ```

5. **Create admin user** (optional)
   ```bash
   python add_admin_user.py
   ```

## Configuration

Edit the configuration settings in `app.py`:

```python
# Active Directory settings
app.config['LDAP_HOST'] = '10.10.100.100'
app.config['LDAP_PORT'] = 389
app.config['LDAP_USE_SSL'] = False
app.config['LDAP_BASE_DN'] = 'DC=HBERC-DOMAIN,DC=COM'
app.config['LDAP_DOMAIN'] = 'HBERC-DOMAIN'
```

Update the `secret_key` to a secure random value before deploying to production.

## Running the Application

```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

1. **Login**: Authenticate using your Active Directory credentials or admin account
2. **Navigate Dashboard**: Access different sections (Staff, Users, Tickets, Chat)
3. **Manage Staff**: Add, edit staff information and assignments
4. **Create Tickets**: Submit support requests and track their status
5. **Chat**: Real-time communication with other staff members
6. **Send Alerts**: Broadcast important messages to the organization

## Database

The system uses SQLite database (`database.db`) for data storage. The database is automatically created on first run.

### Migration

To migrate or update the database schema:
```bash
python migrate_db.py
```

## Security Considerations

- Change the `secret_key` in `app.py` to a secure random string
- Use HTTPS in production
- Implement proper CORS settings
- Regular database backups
- Monitor and log access attempts
- Update dependencies regularly for security patches

## License

This project is proprietary and confidential.

## Contact

For support or inquiries, contact the IT department.

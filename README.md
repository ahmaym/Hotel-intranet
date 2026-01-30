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
   pip install -r requirements.txt
   ```
   
   Or install individually:
   ```bash
   pip install flask flask-socketio python-socketio ldap3 werkzeug python-dotenv openpyxl
   ```

4. **Configure environment variables**
   
   Copy the example environment file and configure it with your settings:
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and update the following variables with your actual values:
   
   ```env
   # Flask Configuration
   SECRET_KEY=your_secret_key_here_change_this_to_something_secure
   
   # Active Directory / LDAP Configuration
   LDAP_HOST=your_ldap_server_ip
   LDAP_PORT=389
   LDAP_USE_SSL=False
   LDAP_BASE_DN=DC=YOUR-DOMAIN,DC=COM
   LDAP_DOMAIN=YOUR-DOMAIN
   
   # Database Configuration
   DATABASE_PATH=database.db
   
   # Server Configuration
   FLASK_HOST=0.0.0.0
   FLASK_PORT=5000
   FLASK_DEBUG=True
   
   # File Upload Configuration
   MAX_CONTENT_LENGTH=16777216
   UPLOAD_FOLDER=uploads
   
   # Image Upload Configuration
   DAILY_UPDATES_FOLDER=static/daily_updates
   IMAGE_EXTENSIONS=png,jpg,jpeg,gif,bmp,webp
   ```
   
   **Important Security Notes:**
   - Never commit the `.env` file to version control (it's already in `.gitignore`)
   - Generate a strong, random `SECRET_KEY` for production
   - Use your actual LDAP/Active Directory server IP and domain information
   - Keep the `.env` file secure and restrict access permissions

5. **Initialize the database**
   ```bash
   python create_database.py
   ```

6. **Create admin user** (optional)
   ```bash
   python add_admin_user.py
   ```

## Configuration

The application uses environment variables for configuration. All sensitive information is stored in the `.env` file (not tracked by git).

### Environment Variables Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask secret key for sessions | - | Yes |
| `LDAP_HOST` | Active Directory server IP | `10.10.100.100` | Yes |
| `LDAP_PORT` | LDAP server port | `389` | No |
| `LDAP_USE_SSL` | Enable SSL for LDAP | `False` | No |
| `LDAP_BASE_DN` | LDAP base distinguished name | - | Yes |
| `LDAP_DOMAIN` | Active Directory domain | - | Yes |
| `DATABASE_PATH` | SQLite database file path | `database.db` | No |
| `FLASK_HOST` | Server host address | `0.0.0.0` | No |
| `FLASK_PORT` | Server port | `5000` | No |
| `FLASK_DEBUG` | Enable debug mode | `True` | No |
| `MAX_CONTENT_LENGTH` | Max upload file size (bytes) | `16777216` | No |
| `UPLOAD_FOLDER` | Folder for file uploads | `uploads` | No |
| `DAILY_UPDATES_FOLDER` | Folder for daily update images | `static/daily_updates` | No |
| `IMAGE_EXTENSIONS` | Allowed image extensions | `png,jpg,jpeg,gif,bmp,webp` | No |

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

- **Environment Variables**: All sensitive configuration is stored in `.env` file (excluded from git)
- **Secret Key**: Generate a strong, random `SECRET_KEY` for production environments
- **HTTPS**: Use HTTPS in production to encrypt data in transit
- **CORS Settings**: Configure appropriate CORS settings for your environment
- **Database Backups**: Implement regular automated backups of `database.db`
- **Access Monitoring**: Monitor and log authentication attempts and access patterns
- **Dependency Updates**: Regularly update dependencies for security patches
- **File Permissions**: Restrict `.env` file permissions (chmod 600 on Unix systems)
- **LDAP Credentials**: Never hardcode LDAP credentials; use environment variables only
- **Production Mode**: Set `FLASK_DEBUG=False` in production environments

## License

This project is proprietary and confidential.

## Contact

For support or inquiries, contact the IT department.

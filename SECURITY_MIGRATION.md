# Security Migration - Environment Variables

## Overview

This document describes the security improvements made to move sensitive configuration from hardcoded values to environment variables.

## Changes Made

### 1. New Files Created

- **`.env.example`**: Template file with placeholder values for all configuration
- **`.env`**: Actual configuration file (gitignored, not tracked in version control)
- **`.gitignore`**: Git ignore rules to exclude sensitive files
- **`requirements.txt`**: Python dependencies for easier installation
- **`SETUP_GUIDE.md`**: Quick setup instructions for new installations

### 2. Modified Files

#### `app.py`
- Added `python-dotenv` import and `load_dotenv()` call
- Replaced hardcoded values with `os.getenv()` calls:
  - `SECRET_KEY`: Flask session secret
  - `LDAP_HOST`: Active Directory server IP
  - `LDAP_PORT`: LDAP port (default: 389)
  - `LDAP_USE_SSL`: SSL/TLS configuration
  - `LDAP_BASE_DN`: LDAP base distinguished name
  - `LDAP_DOMAIN`: Active Directory domain
  - `DATABASE_PATH`: SQLite database file path
  - `FLASK_HOST`: Server host address
  - `FLASK_PORT`: Server port
  - `FLASK_DEBUG`: Debug mode flag
  - `MAX_CONTENT_LENGTH`: File upload size limit
  - `UPLOAD_FOLDER`: File upload directory
  - `DAILY_UPDATES_FOLDER`: Daily updates image directory
  - `IMAGE_EXTENSIONS`: Allowed image file extensions

#### `README.md`
- Updated installation instructions to include environment variable setup
- Added comprehensive environment variables reference table
- Enhanced security considerations section
- Added `requirements.txt` installation instructions

### 3. Environment Variables

All sensitive configuration is now stored in `.env` file:

```env
# Flask Configuration
SECRET_KEY=your_secret_key_here

# Active Directory / LDAP Configuration
LDAP_HOST=10.10.100.100
LDAP_PORT=389
LDAP_USE_SSL=False
LDAP_BASE_DN=DC=HBERC-DOMAIN,DC=COM
LDAP_DOMAIN=HBERC-DOMAIN

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

## Security Benefits

1. **No Hardcoded Credentials**: Sensitive information is no longer in source code
2. **Git Protection**: `.env` file is excluded from version control
3. **Easy Configuration**: Different environments can use different `.env` files
4. **Secret Rotation**: Secrets can be changed without modifying code
5. **Deployment Safety**: Production secrets never appear in repository history

## Migration Steps for Existing Installations

If you're updating an existing installation:

1. **Install python-dotenv**:
   ```bash
   pip install python-dotenv
   ```

2. **Create `.env` file**:
   ```bash
   copy .env.example .env
   ```

3. **Update `.env` with your values**:
   - Set your actual LDAP server IP
   - Set your domain information
   - Generate a strong SECRET_KEY

4. **Verify application starts**:
   ```bash
   python app.py
   ```

## Backward Compatibility

The application maintains backward compatibility through default values in `os.getenv()` calls. If no `.env` file exists, the application will use the default values (same as the original hardcoded values).

## Best Practices

1. **Never commit `.env` file** - It's already in `.gitignore`
2. **Use strong SECRET_KEY** - Generate with: `python -c "import secrets; print(secrets.token_hex(32))"`
3. **Restrict file permissions** - Unix: `chmod 600 .env`
4. **Different secrets per environment** - Development, staging, and production should have different secrets
5. **Regular secret rotation** - Change secrets periodically
6. **Backup `.env` securely** - Store backups in secure, encrypted location

## Testing

The application has been tested and verified to work with:
- ✅ Environment variables loaded from `.env` file
- ✅ Default values when `.env` is missing
- ✅ Server starts successfully on configured host/port
- ✅ LDAP configuration loaded correctly
- ✅ All existing functionality preserved

## Support

For questions or issues with environment variable configuration:
- See `SETUP_GUIDE.md` for quick setup instructions
- See `README.md` for comprehensive documentation
- Contact IT department for LDAP/AD configuration assistance

---

**Migration Date**: January 30, 2026
**Status**: ✅ Complete and Tested

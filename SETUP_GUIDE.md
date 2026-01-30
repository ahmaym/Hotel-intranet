# Quick Setup Guide

This guide will help you quickly set up the Hotel Intranet application with proper security configuration.

## Step 1: Create Your Environment File

1. Copy the example environment file:
   ```bash
   copy .env.example .env
   ```
   (On Linux/Mac: `cp .env.example .env`)

2. Open `.env` in a text editor and update these critical values:

### Required Configuration

```env
# Generate a strong secret key (you can use Python to generate one):
# python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your_generated_secret_key_here

# Your Active Directory/LDAP Server Details
LDAP_HOST=10.10.100.100
LDAP_BASE_DN=DC=HBERC-DOMAIN,DC=COM
LDAP_DOMAIN=HBERC-DOMAIN
```

### Optional Configuration (defaults are usually fine)

```env
LDAP_PORT=389
LDAP_USE_SSL=False
DATABASE_PATH=database.db
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=True
```

## Step 2: Verify Your Configuration

After creating your `.env` file, verify it contains:
- ✅ A unique `SECRET_KEY` (not the example value)
- ✅ Your actual `LDAP_HOST` IP address
- ✅ Your actual `LDAP_BASE_DN` and `LDAP_DOMAIN`

## Step 3: Run the Application

```bash
python app.py
```

The application will automatically load your `.env` configuration.

## Security Checklist

- [ ] `.env` file created and configured
- [ ] `SECRET_KEY` changed from default
- [ ] LDAP settings match your Active Directory
- [ ] `.env` file is NOT committed to git (check `.gitignore`)
- [ ] File permissions restricted on `.env` (Unix: `chmod 600 .env`)
- [ ] `FLASK_DEBUG=False` for production deployments

## Troubleshooting

### "No module named 'dotenv'"
```bash
pip install python-dotenv
```

### Application won't start
- Check that `.env` file exists in the project root
- Verify all required variables are set
- Check for syntax errors in `.env` file

### LDAP authentication fails
- Verify `LDAP_HOST` is reachable
- Check `LDAP_BASE_DN` and `LDAP_DOMAIN` are correct
- Test LDAP connectivity from your network

## Production Deployment

For production environments:

1. Set `FLASK_DEBUG=False` in `.env`
2. Use a strong, unique `SECRET_KEY`
3. Enable HTTPS/SSL
4. Restrict `.env` file permissions
5. Set up regular database backups
6. Configure proper firewall rules
7. Monitor application logs

## Need Help?

Contact your IT department for assistance with:
- Active Directory/LDAP configuration
- Network connectivity issues
- Security and access control
- Production deployment

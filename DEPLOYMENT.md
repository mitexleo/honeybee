# Honeybee Honeypot Deployment Guide

## Simple Domain Configuration

This guide explains how to deploy the Honeybee Honeypot with a simple domain configuration approach.

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server's IP address
- Ports 80 and 443 open on your server

### Quick Setup

1. **Copy configuration files**:
   ```bash
   cp .env.example .env
   cp Caddyfile.example Caddyfile
   ```

2. **Edit configuration files**:
   - Update `.env` with your actual values
   - Edit `Caddyfile` and replace `example.com` with your actual domain

3. **Deploy the application**:
   ```bash
   docker compose up -d
   ```

### Configuration Files

#### .env File Setup
Edit the `.env` file with your actual values:
```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=5000

# Database Configuration
HONEYPOT_DB_PATH=/app/data/honeypot.db
HONEYPOT_LOG_FILE=honeypot.log

# Admin Authentication
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password
JWT_SECRET=your-jwt-secret-key

# GeoIP Database
GEOIP_DB_PATH=/app/data/GeoLite2-City.mmdb

# Log Management
MAX_LOG_SIZE=10485760
BACKUP_COUNT=5

# Domain for CORS (used by the application)
DOMAIN=your-actual-domain.com
```

#### Caddyfile Setup
Edit the `Caddyfile` and replace `example.com` with your actual domain:
```bash
your-actual-domain.com {
    reverse_proxy honeypot:5000
    encode gzip

    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    }
}

# Redirect HTTP to HTTPS
http://your-actual-domain.com {
    redir https://your-actual-domain.com{uri} permanent
}
```

### Docker Compose Services

The deployment consists of two services:

1. **honeypot**: The main Go application serving the honeypot
2. **caddy**: Reverse proxy handling SSL termination and security headers

### SSL Certificate Automation

Caddy will automatically:
- Obtain SSL certificates from Let's Encrypt for your domain
- Renew certificates before expiration
- Handle HTTP to HTTPS redirects
- Apply security headers

### Testing Your Deployment

1. **Test HTTPS Access**:
   ```bash
   curl -I https://your-domain.com
   ```

2. **Test Health Endpoint**:
   ```bash
   curl https://your-domain.com/health
   ```

3. **Test Honeypot Pages**:
   - Main Login: `https://your-domain.com`
   - Registration: `https://your-domain.com/register.html`
   - Admin Dashboard: `https://your-domain.com/admin/login`

### Monitoring and Maintenance

**View Logs**:
```bash
docker compose logs honeypot
docker compose logs caddy
```

**Restart Services**:
```bash
docker compose restart
```

**Update Deployment**:
```bash
docker compose pull
docker compose up -d --build
```

### Troubleshooting

**Common Issues**:

1. **SSL Certificate Errors**:
   - Ensure domain DNS points to correct IP
   - Check port 80 is accessible for ACME challenges

2. **CORS Errors**:
   - Verify `DOMAIN` environment variable is set correctly in `.env`
   - Check browser console for specific errors

3. **Database Issues**:
   ```bash
   docker compose down -v
   docker compose up -d
   ```

### Security Considerations

- Change default admin credentials immediately
- Use strong JWT secrets
- Regularly update Docker images
- Monitor access logs for suspicious activity

### File Structure
```
honeybee/
├── .env.example          # Environment variables template
├── Caddyfile.example     # Caddy configuration template
├── docker-compose.yml    # Docker services configuration
├── Dockerfile           # Application container build
└── ...                  # Other project files
```

This simple approach requires minimal configuration while providing full SSL automation and security features through Caddy.
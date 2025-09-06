# Honeybee Honeypot Deployment Guide

## Dynamic Domain Configuration

This guide explains how to deploy the Honeybee Honeypot with dynamic domain configuration using environment variables.

### Prerequisites

- Docker and Docker Compose installed
- A domain name pointing to your server's IP address
- Ports 80 and 443 open on your server

### Environment Variables Setup

Create a `.env` file in the project root with the following variables:

```bash
# Required: Your public domain name
DOMAIN=your-actual-domain.com

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
```

### Quick Deployment

1. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

2. **Start Services**:
   ```bash
   docker-compose up -d
   ```

3. **Verify Deployment**:
   ```bash
   docker-compose logs -f
   ```

### Domain Configuration

The system uses the `DOMAIN` environment variable to dynamically configure:

- **Caddy Reverse Proxy**: Automatically sets up SSL with Let's Encrypt
- **CORS Headers**: Configures allowed origins for cross-origin requests
- **Security Headers**: Proper Content Security Policy for your domain

### SSL Certificate Automation

Caddy will automatically:
- Obtain SSL certificates from Let's Encrypt
- Renew certificates before expiration
- Redirect HTTP to HTTPS
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
docker-compose logs honeypot
docker-compose logs caddy
```

**Restart Services**:
```bash
docker-compose restart
```

**Update Deployment**:
```bash
docker-compose pull
docker-compose up -d --build
```

### Troubleshooting

**Common Issues**:

1. **SSL Certificate Errors**:
   - Ensure domain DNS points to correct IP
   - Check port 80 is accessible for ACME challenges

2. **CORS Errors**:
   - Verify `DOMAIN` environment variable is set correctly
   - Check browser console for specific errors

3. **Database Issues**:
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

### Backup and Data Management

**Database Backup**:
```bash
docker-compose exec honeypot cp /app/data/honeypot.db /app/data/honeypot.db.backup
```

**Export Data**:
Access the admin dashboard at `https://your-domain.com/admin` and use the export features.

### Security Considerations

- Change default admin credentials immediately
- Use strong JWT secrets
- Regularly update Docker images
- Monitor access logs for suspicious activity
- Consider firewall rules to restrict access if needed

### Scaling Considerations

For production deployments:
- Add monitoring (Prometheus/Grafana)
- Implement log aggregation
- Set up automated backups
- Consider database replication for high availability

### Support

For issues with this deployment method, check:
- Docker logs: `docker-compose logs`
- Caddy logs: `docker-compose logs caddy`
- Application logs: `docker-compose logs honeypot`

Ensure all environment variables are properly set and the domain DNS propagation is complete before reporting issues.
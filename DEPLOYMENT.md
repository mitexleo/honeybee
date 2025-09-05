# Production Deployment Guide

This guide covers secure production deployment of the Nextcloud Honeypot with Caddy reverse proxy.

## 🚨 Security Issues Fixed

The production version (`production_server.py`) addresses critical security vulnerabilities:

### **Fixed Issues:**
- ✅ **Admin Authentication**: HTTP Basic Auth required for admin routes
- ✅ **SQL Injection Prevention**: Parameterized queries throughout
- ✅ **Rate Limiting**: Flask-Limiter with configurable limits
- ✅ **Input Validation**: Sanitization and length limits
- ✅ **Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- ✅ **IP Detection**: Proper header handling behind reverse proxy
- ✅ **Database Security**: Secure file permissions and encryption-ready
- ✅ **Error Handling**: Graceful error handling without information leakage
- ✅ **Memory Management**: Limited mouse tracking and data size limits

## 🏗️ Deployment Options

### Option 1: Manual Deployment (Recommended)

#### **Prerequisites:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install python3 python3-pip python3-venv sqlite3 curl

# Install Caddy
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

#### **Step 1: Setup Application**
```bash
# Clone/copy honeypot files
cd /opt
sudo mkdir honeypot && cd honeypot
sudo chown $USER:$USER /opt/honeypot

# Copy files
cp /path/to/your/ncphishing/* .

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### **Step 2: Configure Environment**
```bash
# Copy and edit configuration
cp .env.example .env
nano .env
```

**Critical Configuration (.env):**
```bash
# CHANGE THESE IMMEDIATELY!
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD=your_very_strong_password_here
SECRET_KEY=generate_random_32_char_hex_string

# Database and logging
HONEYPOT_DB_PATH=/opt/honeypot/data/honeypot.db
HONEYPOT_LOG_FILE=honeypot.log
RATE_LIMIT=50 per hour

# Your domain
DOMAIN=your-domain.com
ADMIN_EMAIL=admin@your-domain.com
```

#### **Step 3: Setup Directories**
```bash
# Create secure directories
mkdir -p data logs backups
chmod 750 data logs backups
chmod 600 .env

# Initialize database with secure permissions
python production_server.py &
sleep 5
kill %1
```

#### **Step 4: Configure Caddy**
```bash
# Edit Caddyfile with your domain
sudo nano /etc/caddy/Caddyfile
```

Replace `your-domain.com` with your actual domain in the Caddyfile.

#### **Step 5: Create Systemd Service**
```bash
sudo nano /etc/systemd/system/honeypot.service
```

```ini
[Unit]
Description=Nextcloud Honeypot
After=network.target

[Service]
Type=exec
User=honeypot
Group=honeypot
WorkingDirectory=/opt/honeypot
Environment=PATH=/opt/honeypot/venv/bin
ExecStart=/opt/honeypot/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --timeout 60 --keepalive 2 --max-requests 1000 --max-requests-jitter 50 --preload production_server:app
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### **Step 6: Create User and Set Permissions**
```bash
# Create dedicated user
sudo useradd -r -s /bin/false honeypot
sudo chown -R honeypot:honeypot /opt/honeypot
sudo chmod 600 /opt/honeypot/data/honeypot.db
```

#### **Step 7: Start Services**
```bash
# Enable and start services
sudo systemctl enable honeypot
sudo systemctl start honeypot
sudo systemctl reload caddy

# Check status
sudo systemctl status honeypot
sudo systemctl status caddy
```

### Option 2: Docker Deployment

#### **Prerequisites:**
```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### **Step 1: Prepare Environment**
```bash
# Copy project files
cp .env.example .env
nano .env  # Configure as above

# Download GeoIP database (optional)
# Register at https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb to project directory
```

#### **Step 2: Deploy with Docker**
```bash
# Basic deployment
docker-compose up -d

# With all monitoring services
docker-compose --profile monitoring --profile backup up -d

# Check status
docker-compose ps
docker-compose logs -f honeypot
```

## 🔒 Security Configuration

### **1. Change Default Credentials**
```bash
# Generate strong password
openssl rand -base64 32

# Generate secret key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### **2. Configure Firewall**
```bash
# UFW example
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

### **3. SSL/TLS Configuration**
Caddy automatically handles SSL with Let's Encrypt. For custom certificates:

```caddyfile
your-domain.com {
    tls /path/to/cert.pem /path/to/key.pem
    # ... rest of configuration
}
```

### **4. Database Encryption (Optional)**
```bash
# Install sqlcipher
sudo apt install sqlcipher

# Encrypt existing database
sqlcipher honeypot.db "PRAGMA key='your-encryption-key'; ATTACH DATABASE 'honeypot_encrypted.db' AS encrypted KEY 'your-encryption-key'; SELECT sqlcipher_export('encrypted'); DETACH DATABASE encrypted;"
```

## 📊 Monitoring and Maintenance

### **1. Log Monitoring**
```bash
# View honeypot logs
tail -f logs/honeypot.log

# View Caddy access logs
sudo tail -f /var/log/caddy/honeypot-access.log

# Check system logs
journalctl -fu honeypot
```

### **2. Database Monitoring**
```bash
# Check database size
ls -lh data/honeypot.db

# View recent activity
sqlite3 data/honeypot.db "SELECT COUNT(*) FROM login_attempts WHERE timestamp > datetime('now', '-1 day');"
```

### **3. Automated Backups**
```bash
# Create backup script
nano /opt/honeypot/backup.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/opt/honeypot/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup
sqlite3 /opt/honeypot/data/honeypot.db ".backup $BACKUP_DIR/honeypot_$DATE.db"
gzip "$BACKUP_DIR/honeypot_$DATE.db"

# Keep only last 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete
```

```bash
# Add to crontab
chmod +x /opt/honeypot/backup.sh
crontab -e
# Add: 0 2 * * * /opt/honeypot/backup.sh
```

### **4. Health Monitoring**
```bash
# Create monitoring script
nano /opt/honeypot/monitor.sh
```

```bash
#!/bin/bash
HEALTH_URL="https://your-domain.com/health"
WEBHOOK_URL="your-alert-webhook-url"

# Check health
if ! curl -f -s "$HEALTH_URL" > /dev/null; then
    # Send alert
    curl -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" \
         -d '{"text":"🚨 Honeypot health check failed!"}'
    
    # Restart service
    sudo systemctl restart honeypot
fi
```

## 🧪 Testing Your Deployment

### **1. Local Testing**
```bash
# Test the production server locally
python test_honeypot.py --url http://localhost:5000

# Test with Caddy proxy
python test_honeypot.py --url https://your-domain.com
```

### **2. Security Testing**
```bash
# Test rate limiting
for i in {1..30}; do curl -X POST https://your-domain.com/api/honeypot/log; done

# Test admin authentication
curl -I https://your-domain.com/admin/dashboard

# Test security headers
curl -I https://your-domain.com/
```

### **3. Load Testing**
```bash
# Install Apache Bench
sudo apt install apache2-utils

# Basic load test
ab -n 1000 -c 10 https://your-domain.com/

# Test login endpoint
ab -n 100 -c 5 -p login_payload.json -T "application/json" https://your-domain.com/api/honeypot/log
```

## 🚨 Incident Response

### **When Attackers Are Detected:**

#### **1. Immediate Actions**
```bash
# View recent attacks
sqlite3 data/honeypot.db "SELECT ip_address, username, timestamp FROM login_attempts WHERE timestamp > datetime('now', '-1 hour') ORDER BY timestamp DESC;"

# Block suspicious IPs (if needed)
sudo ufw deny from suspicious.ip.address
```

#### **2. Evidence Collection**
```bash
# Export attack data
curl -u admin:password https://your-domain.com/api/export/json > attack_evidence_$(date +%Y%m%d).json

# Create incident report
sqlite3 -header -csv data/honeypot.db "SELECT * FROM login_attempts WHERE ip_address='attacker.ip';" > incident_report.csv
```

#### **3. Reporting to Authorities**
- Document IP addresses, timestamps, and attack patterns
- Include geolocation data if available
- Provide evidence files and logs
- Contact appropriate cybersecurity authorities

## 🔧 Troubleshooting

### **Common Issues:**

#### **Service Won't Start**
```bash
# Check logs
journalctl -fu honeypot
sudo systemctl status honeypot

# Check permissions
ls -la /opt/honeypot/data/
sudo chown -R honeypot:honeypot /opt/honeypot
```

#### **Database Locked**
```bash
# Check for stale connections
lsof /opt/honeypot/data/honeypot.db

# Restart service
sudo systemctl restart honeypot
```

#### **Caddy SSL Issues**
```bash
# Check Caddy logs
sudo journalctl -fu caddy

# Verify domain DNS
dig your-domain.com

# Test configuration
sudo caddy validate --config /etc/caddy/Caddyfile
```

#### **Rate Limiting Too Aggressive**
```bash
# Adjust in .env
RATE_LIMIT=200 per hour

# Or in Caddyfile
rate_limit {
    zone honeypot {
        events 200
        window 1h
    }
}
```

## 📝 Legal and Compliance

### **Important Considerations:**

1. **Deploy only on networks you own or have explicit permission to monitor**
2. **Comply with local data protection laws (GDPR, CCPA, etc.)**
3. **Implement appropriate data retention policies**
4. **Document the purpose and scope of your honeypot**
5. **Establish procedures for handling collected data**
6. **Consider privacy implications and minimize data collection where possible**

### **Data Retention Script**
```bash
# Clean old data automatically
sqlite3 /opt/honeypot/data/honeypot.db "DELETE FROM activity_log WHERE timestamp < datetime('now', '-90 days');"
sqlite3 /opt/honeypot/data/honeypot.db "DELETE FROM login_attempts WHERE timestamp < datetime('now', '-90 days');"
```

## 🎯 Performance Optimization

### **For High-Traffic Deployments:**

#### **1. Database Optimization**
```sql
-- Add indexes for better performance
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen);
```

#### **2. Caddy Configuration**
```caddyfile
# Add compression and caching
encode gzip

# Increase worker limits
{
    servers {
        max_header_size 16KB
    }
}
```

#### **3. System Limits**
```bash
# Increase file descriptors
echo "honeypot soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "honeypot hard nofile 65536" | sudo tee -a /etc/security/limits.conf
```

## 📈 Scaling Considerations

For enterprise deployments:

1. **Database**: Consider PostgreSQL for better concurrent access
2. **Load Balancing**: Multiple honeypot instances behind load balancer
3. **Centralized Logging**: ELK stack or similar for log aggregation
4. **Monitoring**: Prometheus + Grafana for metrics and alerting
5. **Backup Strategy**: Automated database replication and backups

---

**Remember**: This honeypot is a powerful tool for detecting malicious activity. Use it responsibly and in accordance with applicable laws and regulations. Always prioritize the security and privacy of legitimate users.
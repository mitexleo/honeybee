# Nextcloud Honeypot Server 🍯

A simple honeypot designed to mimic a Nextcloud login and registration system to detect and log malicious login attempts. This project creates realistic-looking login pages that capture detailed information about attackers while appearing to be a legitimate cloud storage service.

## ⚠️ IMPORTANT LEGAL WARNING

**This honeypot is designed for legitimate cybersecurity research and threat detection purposes only.**

- Only deploy on networks and systems you own or have explicit permission to monitor
- Ensure compliance with local laws and regulations regarding data collection and monitoring
- Consider privacy implications and data protection laws (GDPR, CCPA, etc.)
- Use responsibly and ethically - do not use to harm or deceive legitimate users
- The authors are not responsible for misuse of this software

## Features

### 🎭 Authentic Nextcloud Interface
- **Pixel-perfect Nextcloud design** - Matches authentic Nextcloud login pages
- **Responsive design** - Works on desktop, tablet, and mobile devices
- **Real Nextcloud logo** - Properly styled SVG logo that scales correctly
- **Authentic color scheme** - Uses official Nextcloud blue (#0082c9) gradient backgrounds
- **Professional typography** - Inter font family for modern appearance

### 🔍 Advanced Data Collection
- **Browser fingerprinting** - WebGL, Canvas, Audio, and Font fingerprinting
- **Hardware detection** - CPU cores, memory, screen resolution, device capabilities
- **Network analysis** - Connection speed, RTT, WebRTC IP leak detection
- **Behavioral tracking** - Mouse movements, keystroke patterns, typing speed analysis
- **Form interaction analysis** - Field focus times, typing patterns, copy/paste detection
- **Developer tools detection** - Multiple methods to detect debugging attempts
- **Geolocation tracking** - GPS coordinates if user permits
- **Battery status** - Device battery information (where supported)

### 📊 Professional Dashboard
- **Real-time statistics** - Live attack metrics and threat analysis
- **Interactive charts** - Visual representation of attack patterns
- **Geographic mapping** - Attack origins by country and city
- **Top attackers list** - Most active IPs with threat level indicators
- **Session timeline** - Attack progression over time
- **Auto-refresh** - Real-time updates every 30 seconds

### 💾 Comprehensive Data Export
- **CSV exports** - Login attempts, registrations, sessions, activity logs
- **JSON export** - Structured data for analysis tools
- **ZIP archives** - Bulk export of all data types
- **Filtering options** - Export by date range (up to 90 days)
- **Forensic ready** - All timestamps, IPs, and behavioral data preserved

### 🔒 Security Features
- **Secure database** - SQLite with proper permissions (0600)
- **Input sanitization** - XSS prevention on dashboard
- **Logging rotation** - Automatic log file management
- **JWT authentication** - Secure token-based admin access
- **CORS handling** - Properly configured for frontend-backend communication

### 🖥️ Admin Dashboard
- **Live Monitoring** - Real-time view of login attempts
- **Statistics** - Session counts, unique IPs, geographic distribution
- **Data Export** - Complete data export in JSON format
- **Log Management** - Rotating file logs with configurable retention

## 📁 Project Structure

```
honeybee/
├── config/
│   └── config.go  # Configuration management with godotenv
├── controllers/
│   ├── controllers.go  # Route handlers
├── routes/
│   └── routes.go  # Route definitions
├── frontend/
│   ├── dashboard.html
│   ├── index.html
│   ├── nextcloud.webp
│   ├── register.html
│   ├── register.js
│   ├── script.js
│   └── styles.css
├── middleware/
│   └── middleware.go  # HTTP middleware for auth, CORS, security
├── models/
│   └── models.go  # Database models and init
├── utils/
│   ├── auth.go     # JWT and authentication utilities
│   ├── helpers.go  # Helper functions for IP, geolocation
│   ├── middleware.go  # Moved to middleware/ package
├── go.mod
├── go.sum
├── main.go
├── nginx.conf
├── .env
├── .env.example
├── GeoLite2-City.mmdb
├── LICENSE
└── README.md
```

## 🛠️ Installation & Setup

### Prerequisites
- Go 1.22+
- Modern web browser
- 2GB RAM minimum
- 10GB storage for logs
- MaxMind GeoIP database (optional)

### Quick Start

1. **Clone or download the project:**
   ```bash
   git clone <repository-url>
   cd honeybee
   ```

2. **Download dependencies:**
   ```bash
   go mod download
   ```

3. **Configure environment** (optional)
   ```bash
   cp .env.example .env
   nano .env
   ```

**Critical Configuration (.env):**
```bash
# Admin credentials for JWT
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_this_password
JWT_SECRET=your_jwt_secret_key_here

# Database and logging
HONEYPOT_DB_PATH=data/honeypot.db
HONEYPOT_LOG_FILE=honeypot.log

# Geolocation (optional)
GEOIP_DB_PATH=GeoLite2-City.mmdb

# Other settings
MAX_LOG_SIZE=10485760
BACKUP_COUNT=5
```

4. **Build and start the server:**
   ```bash
   go build -o honeybee main.go
   ./honeybee
   ```

5. **Access the honeypot:**
   - Main login page: http://localhost:5000
   - Registration page: http://localhost:5000/register.html
   - Admin dashboard: http://localhost:5000/admin (requires JWT login)

## 🎯 Data Collection Capabilities

### User Fingerprinting
- **Browser Information**: User agent, platform, language, plugins
- **Hardware Details**: CPU cores, memory, screen resolution, color depth
- **Network Metrics**: Connection speed, RTT, effective connection type
- **WebGL Fingerprinting**: Graphics card vendor, renderer, capabilities
- **Canvas Fingerprinting**: Unique browser rendering signatures
- **Audio Fingerprinting**: Audio context properties and capabilities
- **Font Detection**: Available system fonts enumeration

### Behavioral Analysis
- **Mouse Tracking**: Movement patterns, click locations, scroll behavior
- **Keystroke Analysis**: Typing speed, rhythm, pause patterns
- **Form Interaction**: Field focus times, completion patterns, backspace usage
- **Copy/Paste Detection**: Clipboard operations and patterns
- **Tab Switching**: Visibility change detection and focus patterns
- **Touch Events**: Mobile interaction patterns (if applicable)

### Session Intelligence
- **IP Geolocation**: Country, city, ISP information
- **Session Duration**: Time spent on pages, interaction depth
- **Navigation Patterns**: Page flow, referrer analysis
- **Technical Profiling**: Screen size, timezone, device capabilities
- **Security Evasion**: VPN detection, proxy identification

## 📊 Dashboard Features

### Real-time Monitoring
- **Live Statistics**: Active sessions, unique attackers, countries
- **Threat Indicators**: Risk levels based on activity patterns
- **Geographic Distribution**: World map of attack origins
- **Activity Timeline**: Hourly/daily attack progression

### Attack Analysis
- **Credential Harvesting**: Captured usernames and passwords
- **Registration Attempts**: Fake account creation attempts
- **Behavioral Clustering**: Similar attack pattern grouping
- **Repeat Offenders**: Multi-session attacker identification

### Export Capabilities
```bash
# CSV exports
GET /admin/export/csv?type=all        # ZIP file with all data
GET /admin/export/csv?type=login      # Login attempts CSV

# JSON export
GET /admin/export/json                # JSON format export
```

#### Admin Dashboard
```bash
GET /admin               # Serves dashboard HTML (requires JWT)
GET /admin/dashboard     # Dashboard data JSON (requires JWT)
```

## 🔒 Security Features

### Data Protection
- **Encrypt sensitive data** if deploying in production
- **Implement access controls** for the admin dashboard
- **Regular log rotation** to prevent disk space issues
- **Secure database backups** if data is valuable

### Authentication
- **JWT tokens** for secure admin access
- **Token expiration** configurable
- **Password hashing** using bcrypt

## 🚀 Deployment Options

### Manual Deployment

#### Prerequisites:
```bash
# Linux/Mac
Install Go 1.22+
```

#### Step 1: Setup Application
```bash
# Clone and build
cd /opt
sudo mkdir honeypot && cd honeypot
sudo chown $USER:$USER /opt/honeypot

# Copy files and build
go mod download
go build -o honeybee main.go
```

#### Step 2: Configure Environment
```bash
# Copy and edit configuration
cp .env.example .env
nano .env
```

#### Step 3: Create User and Set Permissions
```bash
# Create dedicated user (optional)
sudo useradd -r -s /bin/false honeypot
sudo chown -R honeypot:honeypot /opt/honeypot
```

#### Step 4: Start the Service
```bash
# Run directly or create systemd service
./honeybee
```

### Docker Deployment

#### Prerequisites:
```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Logout and login back in

# Install Docker Compose (if not included)
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### Step 1: Prepare Environment
```bash
# Copy project files
cp .env.example .env
nano .env  # Configure all environment variables - Docker Compose will read these

# Update Caddyfile with your domain
sed -i 's/your-domain.com/your-actual-domain.com/g' Caddyfile
nano Caddyfile  # Ensure domain is correct

# Optional: Download GeoIP database
# wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz
# Extract and place GeoLite2-City.mmdb in project root
```

#### Step 2: Deploy with Caddy (Automatic SSL)
```bash
# Build and run with automatic HTTPS
# Docker Compose reads all config from .env (port, DB path, secrets, etc.)
docker-compose up -d

# Caddy will automatically obtain SSL certificates on first run
# Check logs for certificate status
docker-compose logs -f caddy
```

#### Monitoring:
```bash
# View honeypot logs
docker-compose logs -f honeypot

# Check Caddy logs
docker-compose logs -f caddy
```

#### SSL and Domain Setup:
- Replace `your-domain.com` in Caddyfile with your actual domain
- DNS A/AAAA records must point to your server
- Caddy handles SSL automatically via Let's Encrypt
- Certificate renewal is automatic

#### Backup:
```bash
# Backup data
docker run --rm -v honeypot_honeypot_data:/data alpine tar czf - -C /data . > honeypot_backup.tar.gz
```

## 🔒 Security Configuration

### **1. Change Default Credentials**
```bash
# Generate strong password
openssl rand -base64 32

# Generate secret key
openssl rand -hex 32
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
sudo journalctl -fu caddy
```

### **2. Database Monitoring**
```bash
# Check database size
ls -lh data/honeypot.db

# View recent activity
sqlite3 data/honeypot.db "SELECT COUNT(*) FROM login_attempts WHERE timestamp > datetime('now', '-1 day');"
```

## 🧪 Testing Your Deployment

### **1. Local Testing**
```bash
# Test the server
curl http://localhost:5000/health
```

### **2. Security Testing**
```bash
# Test security headers
curl -I http://localhost:5000/
```

## 📝 Legal and Compliance

### Important Considerations:

1. **Deploy only on networks you own or have explicit permission to monitor**
2. **Comply with local data protection laws (GDPR, CCPA, etc.)**
3. **Implement appropriate data retention policies**
4. **Document the purpose and scope of your honeypot**
5. **Establish procedures for handling collected data**
6. **Consider privacy implications and minimize data collection where possible**

## 🐳 Docker Setup Summary

- **Caddy**: Automatic HTTPS with Let's Encrypt
- **Production Ready**: Graceful shutdown, health checks, security headers
- **One Command**: `docker-compose up -d` for full deployment
- **Volumes**: Data and logs persist across restarts
- **Networking**: Isolated network for services

---

**Remember**: This honeypot is a powerful tool for detecting malicious activity. Use it responsibly and in accordance with applicable laws and regulations. Always prioritize the security and privacy of legitimate users.

```

#### Step 1: Deploy with Docker
```bash
# Build and run
docker build -t honeypot .
docker run -p 5000:5000 -v ./data:/app/data honeypot
```

#### Step 2: Using Docker Compose
```bash
# Basic deployment
docker-compose up -d

# Check status
docker-compose logs -f honeypot
```

### Production Deployment Notes
- Use reverse proxy (nginx/Caddy) for SSL
- Configure firewall to limit access
- Implement health checks
- Set up monitoring and alerts
- Regular data backups
- Log aggregation

## 🔒 Configuration Options

### Environment Variables
```bash
ADMIN_USERNAME=admin                          # Admin username for JWT
ADMIN_PASSWORD=secure_password_here          # Admin password for JWT
JWT_SECRET=your_secret_jwt_key               # JWT signing key
HONEYPOT_DB_PATH=data/honeypot.db             # Database file path
GEOIP_DB_PATH=GeoLite2-City.mmdb             # GeoIP database path
MAX_LOG_SIZE=10485760                        # Log file size limit
BACKUP_COUNT=5                              # Log rotation count
```

### Database Schema
The system automatically creates tables for:
- `sessions` - Visitor session data
- `login_attempts` - Login form submissions
- `registration_attempts` - Registration form submissions
- `activity_log` - Detailed behavioral logs

## ⚠️ Legal and Ethical Considerations

### Important Considerations:
1. **Deploy only on networks you own or have explicit permission to monitor**
2. **Comply with local data protection laws (GDPR, CCPA, etc.)**
3. **Implement appropriate data retention policies**
4. **Document the purpose and scope of your honeypot**
5. **Establish procedures for handling collected data**
6. **Consider privacy implications and minimize data collection where possible**

## 📝 Troubleshooting

### Common Issues
1. **Dashboard not loading**: Ensure JWT token is valid
2. **No data collection**: Verify frontend CORS and JS enabled
3. **Database errors**: Check file permissions and paths
4. **Export failures**: Ensure sufficient disk space

### Debug Mode
```bash
# Run with verbose logging
./honeybee  # Built with log.Printf statements
```

### Log Analysis
```bash
# Check logs (integrated with Go log package)
tail -f /path/to/logs/honeypot.log
```

## 🔒 Security Features

### Production-Ready Enhancements
- **Graceful Shutdown**: Proper signal handling for clean termination
- **Configuration Management**: Secure loading of environment variables
- **Middleware Separation**: Organized HTTP middleware for auth and security
- **Error Handling**: Structured error responses and logging
- **Database Initialization**: Configurable paths and WAL mode for performance

## 🤝 Contributing

### Development Setup
```bash
git clone <repository>
cd honeybee
go mod download
go build -o honebee main.go
```

### Code Style
- Go: Follow standard Go conventions and use `go fmt`
  - Packages: `models`, `controllers`, `utils`, `middleware`
- JavaScript: Use ESLint configuration
- HTML/CSS: Maintain consistent formatting

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

## ⚠️ Disclaimer

This software is provided for educational and research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.

---

**Version**: 2.0 Enhanced (Go Edition)
**Last Updated**: 2024
**Maintained By**: Go Refactored

**Tech Stack**: Go with Gin web framework and GORM ORM

**Remember**: A honeypot is only as good as the analysis of the data it collects. Use this tool responsibly to improve cybersecurity and protect legitimate users.

Buy me a coffee: https://bio.link/mitexleo
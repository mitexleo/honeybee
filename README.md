# Nextcloud Honeypot Server 🍯

A sophisticated honeypot designed to mimic a Nextcloud login and registration system to detect and log malicious login attempts. This project creates realistic-looking login pages that capture detailed information about attackers while appearing to be a legitimate cloud storage service.

## 📖 Table of Contents
- [⚠️ Legal Warning](#️-legal-warning)
- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [🛠️ Installation & Setup](#️-installation--setup)
- [📊 Dashboard Features](#-dashboard-features)
- [🔒 Security Features](#-security-features)
- [🐳 Docker Deployment](#-docker-deployment)
- [🤝 Contributing](#-contributing)
- [🧪 Testing](#-testing)
- [📝 Troubleshooting](#-troubleshooting)
- [📄 License](#-license)

## ⚠️ Legal Warning

**This honeypot is designed for legitimate cybersecurity research and threat detection purposes only.**

- Only deploy on networks and systems you own or have explicit permission to monitor
- Ensure compliance with local laws and regulations regarding data collection and monitoring
- Consider privacy implications and data protection laws (GDPR, CCPA, etc.)
- Use responsibly and ethically - do not use to harm or deceive legitimate users
- The authors are not responsible for misuse of this software

## ✨ Features

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

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- A domain name pointing to your server's IP address (optional)
- Ports 80 and 443 open on your server

### Quick Deployment

1. **Clone and setup**:
   ```bash
   git clone https://github.com/your-username/honeybee.git
   cd honeybee
   ```

2. **Copy configuration files**:
   ```bash
   cp .env.example .env
   cp Caddyfile.example Caddyfile
   ```

3. **Edit configuration**:
   - Update `.env` with your actual values
   - Edit `Caddyfile` and replace `example.com` with your actual domain (if using)

4. **Deploy the application**:
   ```bash
   docker compose up -d
   ```

5. **Access the honeypot**:
   - Main Login: `http://localhost:5000` or your domain
   - Admin Dashboard: `http://localhost:5000/admin/login`

## 🛠️ Installation & Setup

### Environment Configuration

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

### Build and Update Commands

**For initial installation or updates:**
```bash
# Pull latest changes
git pull

# Build with no cache to ensure fresh images
docker compose build --no-cache

# Start with force recreate
docker compose up -d --force-recreate
```

**For routine updates:**
```bash
# Simple update process
git pull
docker compose up -d --build
```

### Manual Deployment (Without Docker)

1. **Install Go** (version 1.23+)
2. **Build the application**:
   ```bash
   go mod download
   go build -o honeypot main.go
   ```
3. **Run the server**:
   ```bash
   ./honeypot
   ```

## 📊 Dashboard Features

### Real-time Monitoring
- Live view of active login attempts
- Real-time statistics updates
- Geographic attack mapping
- Threat level indicators

### Attack Analysis
- Session duration tracking
- Behavioral pattern analysis
- IP reputation scoring
- Attack vector classification

### Export Capabilities
- CSV/JSON data exports
- Filtered exports by date range
- Bulk data downloads
- Forensic analysis formats

#### Admin Dashboard
- Secure JWT-based authentication
- Comprehensive data visualization
- Export management interface
- System health monitoring

## 🔒 Security Features

### Data Protection
- SQLite database encryption support
- Secure file permissions (0600)
- Input validation and sanitization
- XSS prevention mechanisms

### Authentication
- JWT token-based authentication
- Secure password handling
- Session management
- Role-based access control

### Production Security
- Graceful shutdown handling
- Configuration management
- Middleware security layers
- Error handling and logging

## 🐳 Docker Deployment

### Docker Compose Services

The deployment consists of two services:

1. **honeypot**: The main Go application serving the honeypot
2. **caddy**: Reverse proxy handling SSL termination and security headers

### SSL Certificate Automation

Caddy automatically:
- Obtains SSL certificates from Let's Encrypt for your domain
- Renews certificates before expiration
- Handles HTTP to HTTPS redirects
- Applies security headers

### Caddyfile Configuration

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
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; media-src 'self' data:"
    }
}

# Redirect HTTP to HTTPS
http://your-actual-domain.com {
    redir https://your-actual-domain.com{uri} permanent
}
```

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

## 🤝 Contributing

### Tech Stack Overview

**Backend (Go)**:
- **Web Framework**: Gin Gonic - High performance HTTP web framework
- **Database ORM**: GORM - ORM library for Go with SQLite support
- **Authentication**: JWT (golang-jwt) - JSON Web Token implementation
- **Configuration**: godotenv - Environment variable management
- **GeoIP**: maxminddb-golang - MaxMind GeoIP2 database reader

**Frontend**:
- **HTML/CSS**: Pure vanilla with Nextcloud-style design
- **JavaScript**: Vanilla JS with modern ES6+ features
- **Charts**: Custom SVG-based visualizations
- **Fingerprinting**: Advanced browser fingerprinting techniques

**Infrastructure**:
- **Containerization**: Docker with multi-stage builds
- **Reverse Proxy**: Caddy - Automatic HTTPS and security headers
- **Database**: SQLite with WAL mode for performance

### Development Setup

1. **Clone the repository**:
   ```bash
   git clone <repository>
   cd honeybee
   ```

2. **Install dependencies**:
   ```bash
   go mod download
   ```

3. **Build and run**:
   ```bash
   go build -o honeypot main.go
   ./honeypot
   ```

4. **Development with Docker**:
   ```bash
   docker compose -f docker-compose.dev.yml up --build
   ```

### Architecture Philosophy

The project follows a modular architecture:

1. **Separation of Concerns**: Clear separation between models, controllers, middleware, and utilities
2. **Security First**: Built-in security headers, input validation, and authentication
3. **Performance**: Lightweight Go backend with efficient database operations
4. **Realism**: Authentic Nextcloud interface to effectively trap attackers

### Code Style Guidelines

- **Go**: Follow standard Go conventions and use `go fmt`
  - Packages: `models`, `controllers`, `utils`, `middleware`
  - Error handling: Proper error wrapping and logging
  - Testing: Comprehensive test coverage

- **JavaScript**: Use modern ES6+ features
  - Modular code organization
  - Error handling with try-catch
  - Consistent naming conventions

- **HTML/CSS**: Maintain Nextcloud authenticity
  - Responsive design principles
  - Accessibility considerations
  - Performance optimization

### Contribution Areas

1. **New Fingerprinting Techniques**: Additional browser/hardware detection methods
2. **Enhanced Dashboard**: Improved data visualization and analytics
3. **Export Formats**: Additional forensic data formats
4. **Integration**: SIEM integration, alerting systems
5. **Documentation**: Improved guides and examples

## 🧪 Testing

### Local Testing
```bash
# Test HTTPS Access
curl -I https://your-domain.com

# Test Health Endpoint
curl https://your-domain.com/health

# Test Honeypot Pages
curl https://your-domain.com/
curl https://your-domain.com/register.html
```

### Security Testing
- Test authentication bypass attempts
- Verify input sanitization
- Check CORS configuration
- Validate JWT token security

## 📝 Troubleshooting

### Common Issues

1. **Dashboard not loading**: Ensure JWT token is valid
2. **No data collection**: Verify frontend CORS and JS enabled
3. **Database errors**: Check file permissions and paths
4. **Export failures**: Ensure sufficient disk space

### Debug Mode
```bash
# Run with verbose logging
./honeypot  # Built with log.Printf statements
```

### Log Analysis
```bash
# Check logs
tail -f /path/to/logs/honeypot.log

# Docker logs
docker compose logs -f honeypot
```

### SSL Certificate Issues
- Ensure domain DNS points to correct IP
- Check port 80 is accessible for ACME challenges
- Verify Caddyfile configuration

### CORS Errors
- Verify `DOMAIN` environment variable is set correctly
- Check browser console for specific errors
- Ensure proper CORS headers are set

### Database Issues
```bash
# Reset database (warning: deletes all data)
docker compose down -v
docker compose up -d
```

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

## ⚠️ Disclaimer

This software is provided for educational and research purposes only. The authors are not responsible for any misuse of this software. Users must ensure compliance with all applicable laws and regulations in their jurisdiction.

---

**Remember**: This honeypot is a powerful tool for detecting malicious activity. Use it responsibly and in accordance with applicable laws and regulations. Always prioritize the security and privacy of legitimate users.

For support and contributions, please see the GitHub repository issues and discussions sections.

## ☕ Support This Project

If you find this honeypot useful and would like to support its development, consider buying me a coffee!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://bio.link/mitexleo)

Your support helps maintain and improve this project for the cybersecurity community!
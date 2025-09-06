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
- **Rate limiting** - Prevents dashboard abuse (configurable)
- **Basic authentication** - Admin dashboard protection
- **Input sanitization** - XSS prevention on dashboard
- **Logging rotation** - Automatic log file management
- **Operational Security** - Minimal footprint, low resource requirements

### 🖥️ Admin Dashboard
- **Live Monitoring** - Real-time view of login attempts
- **Statistics** - Session counts, unique IPs, geographic distribution
- **Data Export** - Complete data export in JSON format
- **Log Management** - Rotating file logs with configurable retention

## 📁 Project Structure

```
honeybee/
├── frontend/
│   ├── dashboard.html
│   ├── index.html
│   ├── register.html
│   ├── register.js
│   ├── script.js
│   ├── styles.css
│   └── nextcloud.webp
├── go.mod
├── go.sum
├── main.go
├── .gitignore
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

3. **Optional: Download GeoIP Database**
   - Visit [MaxMind](https://www.maxmind.com/en/geolite2/signup)
   - Download GeoLite2-City.mmdb
   - Place it in the project directory

4. **Configure environment** (optional)
   ```bash
   export ADMIN_USERNAME="admin"
   export ADMIN_PASSWORD="secure_password_here"
   export SECRET_KEY="your_secret_key_here"
   export GEOIP_DB_PATH="GeoLite2-City.mmdb"
   export MAX_LOG_SIZE=10485760
   export BACKUP_COUNT=5
   ```

5. **Build and start the server:**
   ```bash
   go build -o honeybee main.go
   ./honeybee
   ```
   Or run directly:
   ```bash
   go run main.go
   ```

6. **Access the honeypot:**
   - Main login page: http://localhost:5000
   - Registration page: http://localhost:5000/register.html
   - Admin dashboard: http://localhost:5000/admin

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
# Export formats available:
GET /api/export/csv?type=all        # ZIP file with all data
GET /api/export/csv?type=login      # Login attempts CSV
GET /api/export/csv?type=register   # Registration attempts CSV
GET /api/export/csv?type=sessions   # Session data CSV
GET /api/export/json                # JSON format export
```

## 🔒 Security Features

### Data Protection
- **Encrypt sensitive data** if deploying in production
- **Implement access controls** for the admin dashboard
- **Regular log rotation** to prevent disk space issues
- **Secure database backups** if data is valuable

### Network Security
- **Firewall configuration** to limit access
- **HTTPS deployment** for production use
- **Rate limiting** to prevent abuse
- **IP whitelisting** for admin access

## Usage

### Basic Monitoring

1. **Start the server** and share the URL with suspected attackers
2. **Monitor the admin dashboard** at `/admin`
3. **Check logs** in the `logs/` directory
4. **Export data** via `/api/export/json` endpoint

### Advanced Analysis

The honeypot logs extensive data for behavioral analysis:

- **Timing Analysis**: How quickly forms are filled
- **Mouse Patterns**: Movement tracking for bot detection
- **Browser Fingerprinting**: Detailed technical profiling
- **Multi-session Tracking**: Cross-visit behavior patterns

## 📈 Analytics & Intelligence

### Data Points Collected
- **Authentication attempts**: 50+ data points per login
- **Registration attempts**: 60+ data points per registration
- **Session fingerprints**: 40+ browser/system characteristics
- **Behavioral metrics**: Mouse, keyboard, and interaction patterns
- **Network intelligence**: IP, geolocation, connection analysis

### Use Cases
- **Threat intelligence** - Understanding attacker TTPs
- **Security research** - Academic and commercial research
- **Incident response** - Attack pattern analysis
- **Honeypot networks** - Integration with threat feeds

## 🚀 Deployment Options

### Development
```bash
go run main.go
# Runs on localhost:5000
```

### Production
```bash
go build -o honeybee main.go
./honeybee
```

### Reverse Proxy Setup (Nginx example)
```nginx
server {
    listen 80;
    server_name your-honeypot.domain.com;
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📊 Sample Data Output

### Login Attempt (CSV)
```csv
Timestamp,Session ID,Username,Password,IP Address,User Agent,Mouse Movements,Keystrokes,Country
2024-01-15 14:30:22,session_abc123,admin,password123,192.168.1.100,Mozilla/5.0...,{"points": 156},{"average_interval": 120},United States
```

### Behavioral Analysis (JSON)
```json
{
  "session_id": "session_abc123",
  "typing_patterns": {
    "average_interval": 120,
    "rhythm_variance": 0.23,
    "backspace_ratio": 0.15
  },
  "mouse_patterns": {
    "total_distance": 2847,
    "average_speed": 156.3,
    "click_accuracy": 0.94
  },
  "fingerprint": {
    "canvas_hash": "a1b2c3d4...",
    "webgl_vendor": "NVIDIA Corporation",
    "fonts_available": 47
  }
}
```

## 🔧 Configuration Options

### Environment Variables
```bash
HONEYPOT_DB_PATH=honeypot.db        # Database file path
ADMIN_USERNAME=admin                # Dashboard username
ADMIN_PASSWORD=secure123            # Dashboard password
SECRET_KEY=random_secret_key        # Secret key for hashing
GEOIP_DB_PATH=GeoLite2-City.mmdb   # GeoIP database path
MAX_LOG_SIZE=10485760               # Log file size limit
BACKUP_COUNT=5                      # Log rotation count
```

### Database Schema
The system automatically creates tables for:
- `sessions` - Visitor session data
- `login_attempts` - Login form submissions
- `registration_attempts` - Registration form submissions
- `activity_log` - Detailed behavioral logs

## 🚨 Legal & Ethical Considerations

### ⚖️ Legal Compliance
- **Logging Disclosure**: Consider privacy laws in your jurisdiction
- **Data Retention**: Implement appropriate data retention policies
- **Terms of Service**: Display clear terms about data collection
- **Geographic Restrictions**: Some regions may restrict honeypot deployment

### 🛡️ Responsible Use
- **Research Purpose**: Intended for security research and threat intelligence
- **No Entrapment**: Avoid targeting specific individuals
- **Data Security**: Secure collected data appropriately
- **Ethical Guidelines**: Follow responsible disclosure practices

## 🔍 Troubleshooting

### Common Issues
1. **Dashboard not loading**: Check authentication credentials
2. **No data collection**: Verify JavaScript is enabled
3. **Database errors**: Check file permissions (0600)
4. **Export failures**: Ensure sufficient disk space

### Debug Mode
Run with verbose logging or use Go's built-in debugging tools.

### Log Analysis
```bash
tail -f logs/honeypot.log
```

## 🤝 Contributing

### Development Setup
```bash
git clone <repository>
cd honeybee
go mod download
```

### Code Style
- Go: Follow Go standard conventions and use gofmt
- JavaScript: Use ESLint configuration
- HTML/CSS: Maintain consistent formatting

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

## ⚠️ Disclaimer

This software is provided for educational and research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.

---

**Version**: 2.0 Enhanced (Go Edition)
**Last Updated**: [Current Date]
**Maintained By**: [Your Name or Original]

**Tech Stack**: Go with Gin web framework and GORM ORM

Buy me a coffee: https://bio.link/mitexleo
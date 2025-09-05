# Nextcloud Honeypot Server 🍯

A sophisticated honeypot designed to mimic a Nextcloud login and registration system to detect and log malicious login attempts. This project creates realistic-looking login pages that capture detailed information about attackers while appearing to be a legitimate cloud storage service.

## ⚠️ IMPORTANT LEGAL WARNING

**This honeypot is designed for legitimate cybersecurity research and threat detection purposes only.**

- Only deploy on networks and systems you own or have explicit permission to monitor
- Ensure compliance with local laws and regulations regarding data collection and monitoring
- Consider privacy implications and data protection laws (GDPR, CCPA, etc.)
- Use responsibly and ethically - do not use to harm or deceive legitimate users
- The authors are not responsible for misuse of this software

## Features

### 🎭 Realistic Frontend
- **Authentic Nextcloud Design**: Pixel-perfect recreation of Nextcloud's login interface
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Interactive Elements**: Functional forms with realistic validation feedback
- **Alternative Login Options**: Fake Google/Microsoft SSO buttons
- **Registration System**: Complete signup flow to gather more attacker data

### 📊 Comprehensive Logging
- **Login Attempts**: Username, password, IP address, browser details
- **Registration Data**: Full name, email, username, passwords
- **Behavioral Analytics**: Mouse movements, typing patterns, form completion time
- **Technical Fingerprinting**: Screen resolution, browser capabilities, timezone
- **Session Tracking**: Multi-page user journeys and interaction patterns

### 🔒 Security Features
- **SQLite Database**: Secure local storage of all collected data
- **Password Hashing**: SHA-256 hashing of captured passwords
- **IP Geolocation**: Country/city detection (requires GeoIP database)
- **Real-time Logging**: Immediate data capture and storage
- **Export Capabilities**: JSON export of all collected data

### 🖥️ Admin Dashboard
- **Live Monitoring**: Real-time view of login attempts
- **Statistics**: Session counts, unique IPs, geographic distribution
- **Data Export**: Complete data export in JSON format
- **Log Management**: Rotating file logs with configurable retention

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Quick Setup

1. **Clone or download the project:**
   ```bash
   git clone <repository-url>
   cd ncphishing
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Optional: Download GeoIP Database**
   - Visit [MaxMind](https://www.maxmind.com/en/geolite2/signup)
   - Download GeoLite2-City.mmdb
   - Place it in the project directory

4. **Start the server:**
   ```bash
   python server.py
   ```

5. **Access the honeypot:**
   - Main login page: http://localhost:5000
   - Registration page: http://localhost:5000/register.html
   - Admin dashboard: http://localhost:5000/admin/dashboard

## Project Structure

```
ncphishing/
├── index.html          # Main login page
├── register.html       # Registration page
├── styles.css          # Nextcloud-style CSS
├── script.js           # Login page JavaScript
├── register.js         # Registration page JavaScript
├── server.py           # Flask server with logging
├── requirements.txt    # Python dependencies
├── README.md          # This file
├── honeypot.db        # SQLite database (created automatically)
└── logs/              # Log files directory (created automatically)
```

## Configuration

### Server Settings
Edit `server.py` to modify:
- **Port**: Default is 5000
- **Database path**: Default is `honeypot.db`
- **Log rotation**: Default is 10MB with 5 backups
- **GeoIP database**: Default is `GeoLite2-City.mmdb`

### Frontend Customization
- **Company branding**: Modify HTML files to change logos/text
- **Styling**: Edit `styles.css` for visual customization
- **Behavior**: Adjust JavaScript files for different responses

## Usage

### Basic Monitoring

1. **Start the server** and share the URL with suspected attackers
2. **Monitor the admin dashboard** at `/admin/dashboard`
3. **Check logs** in the `logs/` directory
4. **Export data** via `/api/export/json` endpoint

### Advanced Analysis

The honeypot logs extensive data for behavioral analysis:

- **Timing Analysis**: How quickly forms are filled
- **Mouse Patterns**: Movement tracking for bot detection  
- **Browser Fingerprinting**: Detailed technical profiling
- **Multi-session Tracking**: Cross-visit behavior patterns

### Dashboard Features

The admin dashboard provides:
- Recent login and registration attempts
- IP addresses and geographic locations
- User agents and technical details
- Session statistics and trends

## Data Collection

### Login Attempts
- Username and password (plaintext + hashed)
- IP address and geolocation
- User agent and browser details
- Form completion timing
- Mouse movement patterns

### Registration Attempts  
- Full name, email, username, password
- Terms acceptance and newsletter subscription
- Same technical fingerprinting as login
- Form abandonment tracking

### General Activity
- Page loads and navigation
- Developer tools detection
- Copy/paste operations
- Tab switching behavior

## Security Considerations

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

## Legal and Ethical Guidelines

### Deployment Requirements
- Deploy only on networks you control
- Clearly document the honeypot's purpose
- Establish data retention policies
- Implement appropriate access controls

### Data Handling
- Follow applicable privacy laws
- Secure storage of collected data
- Regular data purging if not needed
- Proper disposal of sensitive information

### Responsible Disclosure
- Report findings to appropriate authorities
- Share threat intelligence with security community
- Protect legitimate user data
- Document attack patterns for research

## Troubleshooting

### Common Issues

**Server won't start:**
- Check if port 5000 is available
- Verify Python dependencies are installed
- Ensure SQLite database can be created

**No geolocation data:**
- Download the MaxMind GeoLite2-City database
- Place it in the project root directory
- Restart the server

**Dashboard shows no data:**
- Verify JavaScript is enabled in browsers
- Check browser console for errors
- Confirm server logging endpoint is accessible

### Log Analysis

Check the following log files:
- `logs/honeypot.log` - Server activity and errors
- `honeypot.db` - SQLite database with all collected data
- Browser console - JavaScript errors and client-side logs

## Contributing

This project is for educational and research purposes. If you have improvements:

1. Ensure changes maintain the realistic appearance
2. Add comprehensive logging for new features
3. Follow ethical guidelines for honeypot development
4. Test thoroughly before deployment

## Disclaimer

This software is provided "as is" without warranty. The developers are not responsible for:
- Misuse of the honeypot system
- Legal consequences of deployment
- Data breaches or security issues
- Compliance with local regulations

Always consult with legal counsel before deploying honeypots in production environments.

## License

This project is intended for educational and research purposes only. Use responsibly and in accordance with applicable laws and regulations.

---

**Remember**: A honeypot is only as good as the analysis of the data it collects. Use this tool responsibly to improve cybersecurity and protect legitimate users.
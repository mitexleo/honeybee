#!/usr/bin/env python3
"""
Routes for Nextcloud Honeypot Dashboard and Export Functions
Provides clean route definitions for dashboard and CSV export functionality.
"""

from flask import jsonify, request
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import os
from export_utils import (
    export_login_attempts_csv,
    export_registration_attempts_csv,
    export_sessions_csv,
    export_all_csv,
    export_json_data,
    get_dashboard_data
)

# Configuration from environment
DATABASE_PATH = os.environ.get('HONEYPOT_DB_PATH', 'honeypot.db')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'change_this_password')

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

def register_routes(app):
    """Register all dashboard and export routes with the Flask app."""

    @app.route('/admin')
    @app.route('/dashboard')
    @require_admin_auth
    def admin_dashboard():
        """Serve the enhanced dashboard HTML file."""
        try:
            with open('dashboard.html', 'r') as f:
                return f.read()
        except FileNotFoundError:
            return """
            <!DOCTYPE html>
            <html>
            <head><title>Dashboard Not Found</title></head>
            <body>
            <h1>Dashboard file not found</h1>
            <p>Please ensure dashboard.html exists in the project directory.</p>
            </body>
            </html>
            """, 404

    @app.route('/api/dashboard/data')
    @require_admin_auth
    def dashboard_data():
        """API endpoint for dashboard data."""
        try:
            data = get_dashboard_data(DATABASE_PATH)
            return jsonify(data)
        except Exception as e:
            app.logger.error(f"Dashboard data error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/export/csv')
    @require_admin_auth
    def export_csv():
        """Export honeypot data as CSV files."""
        try:
            export_type = request.args.get('type', 'all')
            days_back = min(int(request.args.get('days', 30)), 90)

            if export_type == 'login':
                return export_login_attempts_csv(DATABASE_PATH, days_back)
            elif export_type == 'register':
                return export_registration_attempts_csv(DATABASE_PATH, days_back)
            elif export_type == 'sessions':
                return export_sessions_csv(DATABASE_PATH, days_back)
            else:
                return export_all_csv(DATABASE_PATH, days_back)

        except Exception as e:
            app.logger.error(f"CSV Export error: {e}")
            return f"Export error: {e}", 500

    @app.route('/api/export/json')
    @require_admin_auth
    def export_json():
        """Export honeypot data as JSON with limits."""
        try:
            days_back = min(int(request.args.get('days', 30)), 90)
            return export_json_data(DATABASE_PATH, days_back)
        except Exception as e:
            app.logger.error(f"JSON Export error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stats')
    @require_admin_auth
    def get_stats():
        """Get basic statistics for monitoring."""
        try:
            data = get_dashboard_data(DATABASE_PATH)
            return jsonify({
                'status': 'active',
                'stats': data['stats'],
                'timestamp': data['timestamp']
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

#!/usr/bin/env python3
"""
CSV Export Utilities for Nextcloud Honeypot
Provides comprehensive data export functionality in multiple formats.
"""

import sqlite3
import csv
import io
import zipfile
import json
from datetime import datetime, timezone
from flask import make_response, jsonify


def export_login_attempts_csv(db_path, days_back=30):
    """Export login attempts as CSV."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                timestamp, session_id, attempt_number, username, password,
                remember_me, ip_address, user_agent, referrer,
                screen_info, browser_info, timezone, plugins, do_not_track,
                form_fill_time, mouse_movements, keystrokes, focus_events
            FROM login_attempts
            WHERE timestamp > datetime('now', '-{} days')
            ORDER BY timestamp DESC
        '''.format(days_back))

        rows = cursor.fetchall()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Timestamp', 'Session ID', 'Attempt Number', 'Username', 'Password',
            'Remember Me', 'IP Address', 'User Agent', 'Referrer',
            'Screen Info', 'Browser Info', 'Timezone', 'Plugins', 'Do Not Track',
            'Form Fill Time (ms)', 'Mouse Movements', 'Keystrokes', 'Focus Events'
        ])

        # Data rows
        for row in rows:
            writer.writerow([
                row['timestamp'], row['session_id'], row['attempt_number'],
                row['username'], row['password'], row['remember_me'],
                row['ip_address'], row['user_agent'], row['referrer'],
                row['screen_info'], row['browser_info'], row['timezone'],
                row['plugins'], row['do_not_track'], row['form_fill_time'],
                row['mouse_movements'], row['keystrokes'], row['focus_events']
            ])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=login_attempts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-type"] = "text/csv"

        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def export_registration_attempts_csv(db_path, days_back=30):
    """Export registration attempts as CSV."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                timestamp, session_id, attempt_number, fullname, email, username,
                password, password_confirm, terms_accepted, newsletter_subscribed,
                ip_address, user_agent, referrer, screen_info, browser_info,
                timezone, plugins, do_not_track, form_fill_time,
                mouse_movements, keystrokes, focus_events, field_interactions
            FROM registration_attempts
            WHERE timestamp > datetime('now', '-{} days')
            ORDER BY timestamp DESC
        '''.format(days_back))

        rows = cursor.fetchall()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Timestamp', 'Session ID', 'Attempt Number', 'Full Name', 'Email', 'Username',
            'Password', 'Password Confirm', 'Terms Accepted', 'Newsletter Subscribed',
            'IP Address', 'User Agent', 'Referrer', 'Screen Info', 'Browser Info',
            'Timezone', 'Plugins', 'Do Not Track', 'Form Fill Time (ms)',
            'Mouse Movements', 'Keystrokes', 'Focus Events', 'Field Interactions'
        ])

        # Data rows
        for row in rows:
            writer.writerow([
                row['timestamp'], row['session_id'], row['attempt_number'],
                row['fullname'], row['email'], row['username'],
                row['password'], row['password_confirm'], row['terms_accepted'], row['newsletter_subscribed'],
                row['ip_address'], row['user_agent'], row['referrer'],
                row['screen_info'], row['browser_info'], row['timezone'],
                row['plugins'], row['do_not_track'], row['form_fill_time'],
                row['mouse_movements'], row['keystrokes'], row['focus_events'], row['field_interactions']
            ])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=registration_attempts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-type"] = "text/csv"

        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def export_sessions_csv(db_path, days_back=30):
    """Export sessions as CSV."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                session_id, first_seen, last_seen, ip_address, user_agent,
                country, city, latitude, longitude, fingerprint_hash,
                total_requests, last_activity_type
            FROM sessions
            WHERE last_seen > datetime('now', '-{} days')
            ORDER BY last_seen DESC
        '''.format(days_back))

        rows = cursor.fetchall()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Session ID', 'First Seen', 'Last Seen', 'IP Address', 'User Agent',
            'Country', 'City', 'Latitude', 'Longitude', 'Fingerprint Hash',
            'Total Requests', 'Last Activity Type'
        ])

        # Data rows
        for row in rows:
            writer.writerow([
                row['session_id'], row['first_seen'], row['last_seen'],
                row['ip_address'], row['user_agent'], row['country'], row['city'],
                row['latitude'], row['longitude'], row['fingerprint_hash'],
                row['total_requests'], row['last_activity_type']
            ])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=sessions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-type"] = "text/csv"

        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def export_all_csv(db_path, days_back=30):
    """Export all data as a ZIP file containing multiple CSV files."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Create in-memory ZIP file
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Export login attempts
            cursor.execute('''
                SELECT * FROM login_attempts
                WHERE timestamp > datetime('now', '-{} days')
                ORDER BY timestamp DESC
            '''.format(days_back))

            login_csv = io.StringIO()
            writer = csv.writer(login_csv)
            writer.writerow([description[0] for description in cursor.description])
            writer.writerows(cursor.fetchall())
            zip_file.writestr('login_attempts.csv', login_csv.getvalue())

            # Export registration attempts
            cursor.execute('''
                SELECT * FROM registration_attempts
                WHERE timestamp > datetime('now', '-{} days')
                ORDER BY timestamp DESC
            '''.format(days_back))

            reg_csv = io.StringIO()
            writer = csv.writer(reg_csv)
            writer.writerow([description[0] for description in cursor.description])
            writer.writerows(cursor.fetchall())
            zip_file.writestr('registration_attempts.csv', reg_csv.getvalue())

            # Export sessions
            cursor.execute('''
                SELECT * FROM sessions
                WHERE last_seen > datetime('now', '-{} days')
                ORDER BY last_seen DESC
            '''.format(days_back))

            sessions_csv = io.StringIO()
            writer = csv.writer(sessions_csv)
            writer.writerow([description[0] for description in cursor.description])
            writer.writerows(cursor.fetchall())
            zip_file.writestr('sessions.csv', sessions_csv.getvalue())

            # Export activity log
            cursor.execute('''
                SELECT * FROM activity_log
                WHERE timestamp > datetime('now', '-{} days')
                ORDER BY timestamp DESC
                LIMIT 5000
            '''.format(days_back))

            activity_csv = io.StringIO()
            writer = csv.writer(activity_csv)
            writer.writerow([description[0] for description in cursor.description])
            writer.writerows(cursor.fetchall())
            zip_file.writestr('activity_log.csv', activity_csv.getvalue())

        conn.close()
        zip_buffer.seek(0)

        response = make_response(zip_buffer.read())
        response.headers["Content-Disposition"] = f"attachment; filename=honeypot_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        response.headers["Content-type"] = "application/zip"

        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def export_json_data(db_path, days_back=30):
    """Export honeypot data as JSON."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        data = {
            'export_timestamp': datetime.now(timezone.utc).isoformat(),
            'export_period_days': days_back
        }

        # Export recent sessions only
        cursor.execute('''
            SELECT * FROM sessions
            WHERE last_seen > datetime('now', '-{} days')
            ORDER BY last_seen DESC
        '''.format(days_back))
        data['sessions'] = [dict(row) for row in cursor.fetchall()]

        # Export recent login attempts
        cursor.execute('''
            SELECT id, session_id, attempt_number, username, remember_me, timestamp,
                   ip_address, user_agent, referrer, form_fill_time, timezone, plugins, do_not_track
            FROM login_attempts
            WHERE timestamp > datetime('now', '-{} days')
            ORDER BY timestamp DESC
        '''.format(days_back))
        data['login_attempts'] = [dict(row) for row in cursor.fetchall()]

        # Export recent registration attempts (excluding password hashes)
        cursor.execute('''
            SELECT id, session_id, attempt_number, fullname, email, username,
                   terms_accepted, newsletter_subscribed, timestamp, ip_address,
                   user_agent, referrer, form_fill_time, timezone, plugins, do_not_track
            FROM registration_attempts
            WHERE timestamp > datetime('now', '-{} days')
            ORDER BY timestamp DESC
        '''.format(days_back))
        data['registration_attempts'] = [dict(row) for row in cursor.fetchall()]

        # Export recent activity log (limited)
        cursor.execute('''
            SELECT id, session_id, activity_type, timestamp, ip_address
            FROM activity_log
            WHERE timestamp > datetime('now', '-{} days')
            ORDER BY timestamp DESC
            LIMIT 1000
        '''.format(days_back))
        data['activity_log'] = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return jsonify(data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def get_dashboard_data(db_path):
    """Get data for the dashboard API."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get comprehensive session statistics
        cursor.execute('''
            SELECT
                COUNT(*) as total_sessions,
                COUNT(DISTINCT ip_address) as unique_ips,
                COUNT(DISTINCT country) as countries,
                COUNT(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 END) as recent_sessions,
                COUNT(CASE WHEN last_seen > datetime('now', '-24 hours') THEN 1 END) as sessions_24h
            FROM sessions
        ''')
        stats = dict(cursor.fetchone())

        # Get total attacks count
        cursor.execute('''
            SELECT
                (SELECT COUNT(*) FROM login_attempts) +
                (SELECT COUNT(*) FROM registration_attempts) as total_attacks
        ''')
        stats['total_attacks'] = cursor.fetchone()[0]

        # Get top attacking IPs (last 7 days)
        cursor.execute('''
            SELECT
                la.ip_address,
                COUNT(*) as attempts,
                s.country,
                s.city
            FROM login_attempts la
            LEFT JOIN sessions s ON la.ip_address = s.ip_address
            WHERE la.timestamp > datetime('now', '-7 days')
            GROUP BY la.ip_address
            ORDER BY attempts DESC
            LIMIT 10
        ''')
        top_ips = [dict(row) for row in cursor.fetchall()]

        # Get recent login attempts (last 50)
        cursor.execute('''
            SELECT
                la.timestamp, la.ip_address, la.username, la.password,
                la.session_id, la.attempt_number, la.user_agent,
                s.country
            FROM login_attempts la
            LEFT JOIN sessions s ON la.ip_address = s.ip_address
            ORDER BY la.timestamp DESC
            LIMIT 50
        ''')
        login_attempts = [dict(row) for row in cursor.fetchall()]

        # Get recent registration attempts (last 50)
        cursor.execute('''
            SELECT
                ra.timestamp, ra.ip_address, ra.fullname, ra.email,
                ra.username, ra.password, ra.session_id,
                s.country
            FROM registration_attempts ra
            LEFT JOIN sessions s ON ra.ip_address = s.ip_address
            ORDER BY ra.timestamp DESC
            LIMIT 50
        ''')
        registration_attempts = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            'stats': stats,
            'top_ips': top_ips,
            'login_attempts': login_attempts,
            'registration_attempts': registration_attempts,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        raise Exception(f"Dashboard data error: {e}")

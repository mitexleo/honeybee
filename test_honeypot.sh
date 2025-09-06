
#!/bin/bash
echo '=== Testing Honeypot Data Flow ==='
echo ''

echo '1. Testing login API directly:'
curl -X POST http://localhost:5000/api/honeypot/log \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "login_attempt",
    "data": {
      "session_id": "test-session-123",
      "username": "test@example.com",
      "password": "testpass123",
      "timestamp": "2025-01-01T00:00:00Z"
    }
  }' -s | head -c 100
echo ''

echo '2. Checking if data was saved:'
docker exec nextcloud_honeypot python3 -c "
import sqlite3
import os
db_path = os.environ.get('HONEYPOT_DB_PATH', '/app/data/honeypot.db')
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM login_attempts')
    count = cursor.fetchone()[0]
    print(f'Login attempts in DB: {count}')
    
    cursor.execute('SELECT * FROM login_attempts ORDER BY timestamp DESC LIMIT 1')
    last = cursor.fetchone()
    if last:
        print(f'Last attempt: {last[2]} @ {last[0]}')
    conn.close()
else:
    print('Database not found')
"

echo '3. Testing dashboard data:'
curl -s http://localhost:5000/api/dashboard/data \
  -u admin:your_admin_password | jq '.login_attempts | length' 2>/dev/null || echo 'Dashboard query failed'
echo ''


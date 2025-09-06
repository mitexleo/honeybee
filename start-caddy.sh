#!/bin/sh

# Caddy startup script
# Uses DOMAIN environment variable or falls back to localhost

set -e

# Use DOMAIN environment variable or fallback to localhost
DOMAIN="${DOMAIN:-localhost}"
echo "Starting Caddy with domain: $DOMAIN"

# Validate domain format (basic check)
if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9.-]+$'; then
    echo "ERROR: Invalid domain format: $DOMAIN"
    exit 1
fi

# Create Caddyfile in /tmp (writable location)
cat > /tmp/Caddyfile << EOF
$DOMAIN {
    reverse_proxy honeypot:5000
    encode gzip

    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    }
}
EOF

echo "Generated Caddyfile:"
cat /tmp/Caddyfile
echo ""

# Validate Caddyfile syntax before starting
echo "Validating Caddyfile syntax..."
if ! caddy validate --config /tmp/Caddyfile --adapter caddyfile 2>/dev/null; then
    echo "ERROR: Caddyfile validation failed"
    echo "Debug info - Caddyfile content:"
    cat /tmp/Caddyfile
    echo "=== END DEBUG ==="
    exit 1
fi

echo "Caddyfile validation successful"
echo "Starting Caddy server..."

# Start Caddy with the generated configuration
exec caddy run --config /tmp/Caddyfile --adapter caddyfile

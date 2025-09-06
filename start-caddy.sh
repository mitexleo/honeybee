#!/bin/sh

# Caddy startup script with template processing
# Reads DOMAIN environment variable and generates Caddyfile

set -e

# Check if DOMAIN environment variable is set
if [ -z "$DOMAIN" ]; then
    echo "ERROR: DOMAIN environment variable is not set"
    echo "Please set DOMAIN in your .env file or docker-compose environment"
    exit 1
fi

echo "Starting Caddy with domain: $DOMAIN"

# Create Caddyfile from template
cat > /etc/caddy/Caddyfile << EOF
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
echo "===================="
cat /etc/caddy/Caddyfile
echo "===================="

# Start Caddy with the generated configuration
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile

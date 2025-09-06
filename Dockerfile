# Multi-stage Dockerfile for Nextcloud Honeypot (Go)

# Builder stage with Debian-based Go for better CGO compatibility
FROM golang:1.24.6-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y git ca-certificates && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum first for caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./
COPY config/ ./config/
COPY models/ ./models/
COPY controllers/ ./controllers/
COPY routes/ ./routes/
COPY utils/ ./utils/
COPY middleware/ ./middleware/

# Build the binary with CGO enabled
ENV GO111MODULE=on
ENV CGO_ENABLED=1
RUN go build -o honeypot main.go

# Make sure binary is executable
RUN chmod +x honeypot

# Minimal verification without execution
RUN test -f honeypot && echo "Binary created successfully"

# Production stage - use Alpine for minimal footprint
FROM alpine:3.21

# Install ca-certificates, tzdata, and SQLite runtime dependencies
RUN apk --no-cache add ca-certificates tzdata libc6-compat

# Create non-root user
RUN addgroup -g 1000 honeypot && \
    adduser -D -s /bin/sh -u 1000 -G honeypot honeypot

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/honeypot .

# Copy frontend files
COPY frontend ./frontend/

# Copy GeoLite2 database (optional)
COPY GeoLite2-City.mmdb ./GeoLite2-City.mmdb

# Create data and logs directories
RUN mkdir -p data logs && \
    chown -R honeypot:honeypot /app

# Switch to non-root user
USER honeypot

# Expose port
EXPOSE 5000

# Health check (simple shell-based approach)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD sh -c 'exec 3<>/dev/tcp/localhost/5000 && echo -e "GET /health HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n" >&3 && head -1 <&3 | grep -q "200"'

# Environment variables with defaults
ENV HONEYPOT_DB_PATH=data/honeypot.db \
    HONEYPOT_LOG_FILE=honeypot.log \
    ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=change_this_password \
    JWT_SECRET=your_jwt_secret_key_here \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=5000 \
    GEOIP_DB_PATH=GeoLite2-City.mmdb

# Run the binary
CMD ["./honeypot"]

# Multi-stage Dockerfile for Nextcloud Honeypot (Go)

# Builder stage with Debian-based Go for CGO compatibility
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

# Production stage - use Debian for compatibility
FROM debian:bookworm-slim

# Install runtime dependencies including curl for healthcheck
RUN apt-get update && apt-get install -y ca-certificates tzdata curl && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --gid 1000 honeypot && \
    adduser --disabled-password --shell /bin/sh --uid 1000 --ingroup honeypot honeypot

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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Environment variables with defaults (will be overridden by .env file or docker-compose)
ENV HONEYPOT_DB_PATH=data/honeypot.db \
    HONEYPOT_LOG_FILE=honeypot.log \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=5000 \
    GEOIP_DB_PATH=GeoLite2-City.mmdb \
    MAX_LOG_SIZE=10485760 \
    BACKUP_COUNT=5

# Run the binary
CMD ["./honeypot"]

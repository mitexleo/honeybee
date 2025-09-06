# Multi-stage Dockerfile for Nextcloud Honeypot (Go version)

# Builder stage
FROM golang:1.22 as builder

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum first for caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./
COPY frontend/ ./frontend/

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o honeybee main.go

# Production stage
FROM debian:bookworm-slim

# Install curl for healthcheck and sqlite3 if needed
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r honeypot && useradd -r -g honeypot -u 1000 honeypot

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/honeybee .

# Copy frontend files
COPY --from=builder /app/frontend ./frontend/

# Optional: Copy GeoIP database if present
COPY GeoLite2-City.mmdb ./

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/backups && \
    chown -R honeypot:honeypot /app && \
    chmod 755 /app && \
    chmod 750 /app/data /app/logs /app/backups && \
    chmod 644 /app/frontend/* && \
    chmod +x /app/honeybee

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Switch to non-root user
USER honeypot

# Expose port
EXPOSE 5000

# Environment variables
ENV HONEYPOT_DB_PATH=/app/data/honeypot.db \
    HONEYPOT_LOG_FILE=honeypot.log

# Run the binary
CMD ["./honeybee"]

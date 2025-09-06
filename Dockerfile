# Multi-stage Dockerfile for Nextcloud Honeypot (Go)

# Builder stage with latest Go
FROM golang:latest AS builder

# Install git and ca-certificates for dependencies
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

# Build the binary
ENV GO111MODULE=on
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o honeypot main.go

# Make sure binary is executable
RUN chmod +x honeypot

# Minimal verification without execution
RUN test -f honeypot && echo "Binary created successfully"

# Production stage
FROM alpine:latest

# Install ca-certificates, tzdata, curl, and SQLite runtime library for CGO
RUN apk --no-cache add ca-certificates tzdata curl libc6-compat

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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

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

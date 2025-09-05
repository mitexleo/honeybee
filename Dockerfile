# Multi-stage Dockerfile for Nextcloud Honeypot
FROM python:3.11-slim as base

# Security updates and dependencies
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r honeypot && useradd -r -g honeypot -u 1000 honeypot

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM base as production

# Copy application code
COPY production_server.py .
COPY index.html .
COPY register.html .
COPY styles.css .
COPY script.js .
COPY register.js .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/backups && \
    chown -R honeypot:honeypot /app

# Set file permissions
RUN chmod 755 /app && \
    chmod 644 /app/*.html /app/*.css /app/*.js && \
    chmod 755 /app/production_server.py && \
    chmod 750 /app/data /app/logs /app/backups

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Switch to non-root user
USER honeypot

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_ENV=production \
    PYTHONPATH=/app \
    HONEYPOT_DB_PATH=/app/data/honeypot.db \
    HONEYPOT_LOG_FILE=honeypot.log

# Run the application with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "60", "--keepalive", "2", "--max-requests", "1000", "--max-requests-jitter", "50", "--preload", "production_server:app"]

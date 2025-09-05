#!/bin/bash

# Nextcloud Honeypot Setup Script
# This script sets up the honeypot environment automatically

set -e

echo "🍯 Nextcloud Honeypot Setup Script"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if Python is installed
print_header "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_status "Found Python: $PYTHON_VERSION"
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_VERSION=$(python --version)
    if [[ $PYTHON_VERSION == *"Python 3"* ]]; then
        print_status "Found Python: $PYTHON_VERSION"
        PYTHON_CMD="python"
    else
        print_error "Python 3 is required. Found: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

# Check if pip is installed
print_header "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    print_status "Found pip3"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    print_status "Found pip"
    PIP_CMD="pip"
else
    print_error "pip is not installed. Please install pip."
    exit 1
fi

# Install Python dependencies
print_header "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    print_status "Installing packages from requirements.txt..."
    $PIP_CMD install -r requirements.txt
    print_status "Python dependencies installed successfully!"
else
    print_error "requirements.txt not found!"
    exit 1
fi

# Create logs directory
print_header "Creating logs directory..."
if [ ! -d "logs" ]; then
    mkdir -p logs
    print_status "Created logs directory"
else
    print_status "Logs directory already exists"
fi

# Check for GeoIP database
print_header "Checking for GeoIP database..."
if [ ! -f "GeoLite2-City.mmdb" ]; then
    print_warning "GeoLite2-City.mmdb not found"
    echo ""
    echo "To enable IP geolocation:"
    echo "1. Visit https://www.maxmind.com/en/geolite2/signup"
    echo "2. Create a free account"
    echo "3. Download GeoLite2-City.mmdb"
    echo "4. Place it in this directory"
    echo ""
    echo "The honeypot will work without it, but won't show geographic data."
else
    print_status "GeoIP database found"
fi

# Set executable permissions on server script
print_header "Setting permissions..."
chmod +x server.py 2>/dev/null || print_warning "Could not set executable permission on server.py"

# Display legal warning
print_header "IMPORTANT LEGAL WARNING"
echo ""
print_warning "This honeypot is for legitimate cybersecurity research only!"
echo ""
echo "Before deploying:"
echo "• Only use on networks you own or have permission to monitor"
echo "• Ensure compliance with local laws and regulations"
echo "• Consider privacy laws (GDPR, CCPA, etc.)"
echo "• Use responsibly and ethically"
echo ""
print_warning "The authors are not responsible for misuse of this software."
echo ""

# Final setup message
print_header "Setup Complete!"
echo ""
print_status "The Nextcloud honeypot is ready to run!"
echo ""
echo "To start the server:"
echo "  $PYTHON_CMD server.py"
echo ""
echo "Once running, access:"
echo "  • Login page: http://localhost:5000"
echo "  • Registration: http://localhost:5000/register.html"
echo "  • Admin dashboard: http://localhost:5000/admin/dashboard"
echo ""
echo "Files created:"
echo "  • logs/ - Log files directory"
echo "  • honeypot.db - SQLite database (created when first run)"
echo ""

# Ask if user wants to start the server immediately
read -p "Would you like to start the honeypot server now? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Starting honeypot server..."
    echo ""
    exec $PYTHON_CMD server.py
fi

print_status "Setup script completed successfully!"
echo ""
echo "Remember to use this honeypot responsibly and in accordance with"
echo "applicable laws and regulations."

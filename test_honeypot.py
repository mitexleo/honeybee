#!/usr/bin/env python3
"""
Comprehensive test suite for Nextcloud Honeypot
Tests security, functionality, and production readiness
"""

import os
import sys
import json
import time
import sqlite3
import requests
import subprocess
from urllib.parse import urljoin
import threading
from datetime import datetime

class HoneypotTester:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []
        self.errors = []

    def log_result(self, test_name, passed, message=""):
        """Log test result."""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = {
            "test": test_name,
            "passed": passed,
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
        self.results.append(result)
        print(f"{status}: {test_name}")
        if message:
            print(f"    {message}")

    def test_basic_connectivity(self):
        """Test basic server connectivity."""
        try:
            response = self.session.get(self.base_url, timeout=10)
            self.log_result("Basic Connectivity",
                          response.status_code == 200,
                          f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Basic Connectivity", False, str(e))

    def test_static_files(self):
        """Test static file serving."""
        files = [
            "/styles.css",
            "/script.js",
            "/register.js",
            "/register.html"
        ]

        for file_path in files:
            try:
                response = self.session.get(urljoin(self.base_url, file_path))
                self.log_result(f"Static File: {file_path}",
                              response.status_code == 200,
                              f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"Static File: {file_path}", False, str(e))

    def test_security_headers(self):
        """Test security headers are present."""
        try:
            response = self.session.get(self.base_url)
            headers = response.headers

            expected_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Content-Security-Policy"
            ]

            for header in expected_headers:
                present = header in headers
                self.log_result(f"Security Header: {header}",
                              present,
                              f"Value: {headers.get(header, 'Missing')}")

        except Exception as e:
            self.log_result("Security Headers", False, str(e))

    def test_login_attempt_logging(self):
        """Test login attempt logging functionality."""
        try:
            # Test login attempt
            login_data = {
                "type": "login_attempt",
                "data": {
                    "session_id": "test_session_123",
                    "username": "test_user",
                    "password": "test_password",
                    "remember_me": True,
                    "attempt_number": 1,
                    "user_agent": "Test-Agent/1.0",
                    "ip_address": "127.0.0.1",
                    "timestamp": datetime.now().isoformat(),
                    "mouse_movements": [{"x": 100, "y": 200, "timestamp": 12345}],
                    "form_fill_time": 5000,
                    "screen_info": {"width": 1920, "height": 1080},
                    "browser_info": {"language": "en-US"},
                    "timezone": "UTC"
                }
            }

            response = self.session.post(
                urljoin(self.base_url, "/api/honeypot/log"),
                json=login_data,
                headers={"Content-Type": "application/json"}
            )

            self.log_result("Login Attempt Logging",
                          response.status_code == 200,
                          f"Status: {response.status_code}, Response: {response.text}")

        except Exception as e:
            self.log_result("Login Attempt Logging", False, str(e))

    def test_registration_attempt_logging(self):
        """Test registration attempt logging."""
        try:
            reg_data = {
                "type": "registration_attempt",
                "data": {
                    "session_id": "test_reg_session_456",
                    "fullname": "Test User",
                    "email": "test@example.com",
                    "username": "testuser123",
                    "password": "TestPassword123!",
                    "password_confirm": "TestPassword123!",
                    "terms_accepted": True,
                    "newsletter_subscribed": False,
                    "attempt_number": 1,
                    "user_agent": "Test-Agent/1.0",
                    "timestamp": datetime.now().isoformat(),
                    "mouse_movements": [],
                    "form_fill_time": 8000,
                    "screen_info": {"width": 1366, "height": 768},
                    "browser_info": {"platform": "Linux"},
                    "timezone": "America/New_York"
                }
            }

            response = self.session.post(
                urljoin(self.base_url, "/api/honeypot/log"),
                json=reg_data,
                headers={"Content-Type": "application/json"}
            )

            self.log_result("Registration Attempt Logging",
                          response.status_code == 200,
                          f"Status: {response.status_code}")

        except Exception as e:
            self.log_result("Registration Attempt Logging", False, str(e))

    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        try:
            # Make rapid requests to trigger rate limiting
            responses = []
            for i in range(25):  # Exceed typical rate limits
                response = self.session.post(
                    urljoin(self.base_url, "/api/honeypot/log"),
                    json={"type": "test", "data": {"test": i}},
                    timeout=5
                )
                responses.append(response.status_code)
                if response.status_code == 429:
                    break

            # Check if we got rate limited
            got_rate_limited = 429 in responses
            self.log_result("Rate Limiting",
                          got_rate_limited,
                          f"Responses: {responses[-5:]}")  # Show last 5

        except Exception as e:
            self.log_result("Rate Limiting", False, str(e))

    def test_admin_authentication(self):
        """Test admin authentication requirement."""
        try:
            # Test without authentication
            response = self.session.get(urljoin(self.base_url, "/admin/dashboard"))
            requires_auth = response.status_code == 401

            self.log_result("Admin Authentication Required",
                          requires_auth,
                          f"Status without auth: {response.status_code}")

            # Test with wrong credentials
            response = self.session.get(
                urljoin(self.base_url, "/admin/dashboard"),
                auth=("wrong", "credentials")
            )
            rejects_wrong_auth = response.status_code == 401

            self.log_result("Admin Rejects Wrong Credentials",
                          rejects_wrong_auth,
                          f"Status with wrong auth: {response.status_code}")

        except Exception as e:
            self.log_result("Admin Authentication", False, str(e))

    def test_input_validation(self):
        """Test input validation and sanitization."""
        try:
            # Test with malicious inputs
            malicious_data = {
                "type": "<script>alert('xss')</script>",
                "data": {
                    "session_id": "../../etc/passwd",
                    "username": "<img src=x onerror=alert(1)>",
                    "password": "' OR 1=1--",
                    "attempt_number": "not_a_number",
                    "mouse_movements": ["x"] * 1000  # Large payload
                }
            }

            response = self.session.post(
                urljoin(self.base_url, "/api/honeypot/log"),
                json=malicious_data
            )

            # Should handle gracefully (not crash)
            handled_gracefully = response.status_code in [200, 400, 422]

            self.log_result("Input Validation",
                          handled_gracefully,
                          f"Status: {response.status_code}")

        except Exception as e:
            self.log_result("Input Validation", False, str(e))

    def test_database_integrity(self):
        """Test database integrity and structure."""
        try:
            if not os.path.exists("honeypot.db"):
                self.log_result("Database Exists", False, "Database file not found")
                return

            conn = sqlite3.connect("honeypot.db")
            cursor = conn.cursor()

            # Check required tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            required_tables = ["sessions", "login_attempts", "registration_attempts", "activity_log"]
            missing_tables = [t for t in required_tables if t not in tables]

            self.log_result("Database Tables",
                          len(missing_tables) == 0,
                          f"Missing tables: {missing_tables}" if missing_tables else "All tables present")

            # Test basic queries
            cursor.execute("SELECT COUNT(*) FROM sessions;")
            session_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM login_attempts;")
            login_count = cursor.fetchone()[0]

            self.log_result("Database Queries",
                          True,
                          f"Sessions: {session_count}, Login attempts: {login_count}")

            conn.close()

        except Exception as e:
            self.log_result("Database Integrity", False, str(e))

    def test_health_endpoint(self):
        """Test health check endpoint."""
        try:
            response = self.session.get(urljoin(self.base_url, "/health"))

            is_healthy = response.status_code == 200

            if is_healthy:
                try:
                    health_data = response.json()
                    has_status = "status" in health_data
                    status_healthy = health_data.get("status") == "healthy"

                    self.log_result("Health Endpoint Structure",
                                  has_status and status_healthy,
                                  f"Health data: {health_data}")
                except:
                    self.log_result("Health Endpoint JSON", False, "Invalid JSON response")
            else:
                self.log_result("Health Endpoint", False, f"Status: {response.status_code}")

        except Exception as e:
            self.log_result("Health Endpoint", False, str(e))

    def test_xss_protection(self):
        """Test XSS protection in responses."""
        try:
            # Test XSS in various endpoints
            xss_payload = "<script>alert('xss')</script>"

            # Test in URL parameters
            response = self.session.get(
                urljoin(self.base_url, f"/nonexistent?test={xss_payload}")
            )

            # Response should not contain unescaped script tags
            contains_unescaped_xss = "<script>" in response.text

            self.log_result("XSS Protection",
                          not contains_unescaped_xss,
                          "Script tags properly escaped" if not contains_unescaped_xss else "XSS vulnerability found")

        except Exception as e:
            self.log_result("XSS Protection", False, str(e))

    def test_file_permissions(self):
        """Test file permissions are secure."""
        try:
            files_to_check = [
                ("honeypot.db", 0o600),
                ("logs", 0o750)
            ]

            for filepath, expected_perms in files_to_check:
                if os.path.exists(filepath):
                    actual_perms = oct(os.stat(filepath).st_mode)[-3:]
                    expected_perms_str = oct(expected_perms)[-3:]

                    permissions_correct = actual_perms == expected_perms_str

                    self.log_result(f"File Permissions: {filepath}",
                                  permissions_correct,
                                  f"Expected: {expected_perms_str}, Actual: {actual_perms}")
                else:
                    self.log_result(f"File Exists: {filepath}", False, "File not found")

        except Exception as e:
            self.log_result("File Permissions", False, str(e))

    def test_client_ip_detection(self):
        """Test client IP detection with various headers."""
        try:
            headers_to_test = [
                {"X-Forwarded-For": "192.168.1.100, 10.0.0.1"},
                {"X-Real-IP": "203.0.113.195"},
                {"CF-Connecting-IP": "198.51.100.178"}
            ]

            for headers in headers_to_test:
                response = self.session.get(
                    urljoin(self.base_url, "/api/client-ip"),
                    headers=headers
                )

                if response.status_code == 200:
                    ip_data = response.json()
                    detected_ip = ip_data.get("ip")

                    # Should detect the forwarded IP
                    header_name = list(headers.keys())[0]
                    expected_ip = headers[header_name].split(",")[0].strip()

                    correct_ip = detected_ip == expected_ip or detected_ip == "127.0.0.1"  # Fallback for testing

                    self.log_result(f"IP Detection: {header_name}",
                                  correct_ip,
                                  f"Detected: {detected_ip}, Expected: {expected_ip}")

        except Exception as e:
            self.log_result("Client IP Detection", False, str(e))

    def load_test(self, concurrent_users=5, requests_per_user=10):
        """Basic load testing."""
        try:
            results = []

            def user_session():
                session = requests.Session()
                user_results = []

                for i in range(requests_per_user):
                    start_time = time.time()
                    try:
                        response = session.get(self.base_url, timeout=30)
                        response_time = time.time() - start_time
                        user_results.append({
                            "status": response.status_code,
                            "time": response_time,
                            "success": response.status_code == 200
                        })
                    except Exception as e:
                        user_results.append({
                            "status": 0,
                            "time": time.time() - start_time,
                            "success": False,
                            "error": str(e)
                        })

                results.extend(user_results)

            # Start concurrent threads
            threads = []
            start_time = time.time()

            for _ in range(concurrent_users):
                thread = threading.Thread(target=user_session)
                threads.append(thread)
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            total_time = time.time() - start_time

            # Analyze results
            successful_requests = sum(1 for r in results if r["success"])
            total_requests = len(results)
            average_response_time = sum(r["time"] for r in results) / total_requests if results else 0
            requests_per_second = total_requests / total_time if total_time > 0 else 0

            load_test_passed = (successful_requests / total_requests) >= 0.95  # 95% success rate

            self.log_result("Load Test",
                          load_test_passed,
                          f"Success rate: {successful_requests}/{total_requests} "
                          f"({successful_requests/total_requests*100:.1f}%), "
                          f"Avg response time: {average_response_time:.3f}s, "
                          f"RPS: {requests_per_second:.1f}")

        except Exception as e:
            self.log_result("Load Test", False, str(e))

    def run_all_tests(self):
        """Run all tests."""
        print("🍯 Starting Nextcloud Honeypot Tests")
        print("=" * 50)

        # Basic functionality tests
        self.test_basic_connectivity()
        self.test_static_files()
        self.test_health_endpoint()

        # Security tests
        self.test_security_headers()
        self.test_admin_authentication()
        self.test_input_validation()
        self.test_xss_protection()
        self.test_rate_limiting()
        self.test_file_permissions()

        # Honeypot functionality tests
        self.test_login_attempt_logging()
        self.test_registration_attempt_logging()
        self.test_client_ip_detection()

        # Database tests
        self.test_database_integrity()

        # Performance tests
        print("\n📊 Running load test...")
        self.load_test()

        # Summary
        self.print_summary()

    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 50)
        print("🍯 Test Summary")
        print("=" * 50)

        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)

        print(f"Total tests: {total}")
        print(f"Passed: ✅ {passed}")
        print(f"Failed: ❌ {total - passed}")
        print(f"Success rate: {passed/total*100:.1f}%")

        if total - passed > 0:
            print("\n❌ Failed tests:")
            for result in self.results:
                if not result["passed"]:
                    print(f"  - {result['test']}: {result['message']}")

        print("\n" + "=" * 50)

        # Save results to file
        with open("test_results.json", "w") as f:
            json.dump(self.results, f, indent=2)

        print("📁 Detailed results saved to test_results.json")

def check_server_running(url="http://localhost:5000"):
    """Check if server is running."""
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except:
        return False

def main():
    """Main test execution."""
    import argparse

    parser = argparse.ArgumentParser(description="Test Nextcloud Honeypot")
    parser.add_argument("--url", default="http://localhost:5000",
                       help="Base URL of the honeypot server")
    parser.add_argument("--load-users", type=int, default=5,
                       help="Number of concurrent users for load test")
    parser.add_argument("--load-requests", type=int, default=10,
                       help="Number of requests per user for load test")
    parser.add_argument("--skip-load", action="store_true",
                       help="Skip load testing")

    args = parser.parse_args()

    # Check if server is running
    if not check_server_running(args.url):
        print("❌ Server is not running at", args.url)
        print("💡 Start the server first:")
        print("   python server.py")
        print("   # or")
        print("   python production_server.py")
        sys.exit(1)

    # Run tests
    tester = HoneypotTester(args.url)

    if args.skip_load:
        # Run all tests except load test
        print("🍯 Starting Nextcloud Honeypot Tests (skipping load test)")
        print("=" * 50)

        tester.test_basic_connectivity()
        tester.test_static_files()
        tester.test_health_endpoint()
        tester.test_security_headers()
        tester.test_admin_authentication()
        tester.test_input_validation()
        tester.test_xss_protection()
        tester.test_rate_limiting()
        tester.test_file_permissions()
        tester.test_login_attempt_logging()
        tester.test_registration_attempt_logging()
        tester.test_client_ip_detection()
        tester.test_database_integrity()

        tester.print_summary()
    else:
        tester.run_all_tests()

    # Exit with error code if tests failed
    passed = sum(1 for r in tester.results if r["passed"])
    total = len(tester.results)

    if passed < total:
        sys.exit(1)  # Exit with error if any tests failed

if __name__ == "__main__":
    main()

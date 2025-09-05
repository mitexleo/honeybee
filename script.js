// Nextcloud Login Page JavaScript with Honeypot Functionality

document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  const userInput = document.getElementById("user");
  const passwordInput = document.getElementById("password");
  const errorMessage = document.getElementById("error-message");
  const loadingSpinner = document.getElementById("loading-spinner");
  const submitButton = document.getElementById("submit-button");

  // Track login attempts for honeypot
  let attemptCount = 0;
  const maxAttempts = 3;
  const sessionId = generateSessionId();

  // Initialize page
  initializePage();

  function initializePage() {
    // Hide any visible messages
    hideMessage(errorMessage);
    hideMessage(loadingSpinner);

    // Add input event listeners for realistic behavior
    userInput.addEventListener("input", handleInputChange);
    passwordInput.addEventListener("input", handleInputChange);

    // Add form submission handler
    loginForm.addEventListener("submit", handleLogin);

    // Log page load
    logActivity("page_load", {
      timestamp: new Date().toISOString(),
      user_agent: navigator.userAgent,
      referrer: document.referrer,
      screen_resolution: `${screen.width}x${screen.height}`,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      language: navigator.language,
      platform: navigator.platform,
      session_id: sessionId,
    });

    // Track mouse movements (for behavioral analysis)
    let mouseMovements = [];
    document.addEventListener("mousemove", function (e) {
      if (mouseMovements.length < 50) {
        // Limit to prevent excessive data
        mouseMovements.push({
          x: e.clientX,
          y: e.clientY,
          timestamp: Date.now(),
        });
      }
    });

    // Store mouse movements for later use
    window.mouseMovements = mouseMovements;
  }

  function handleInputChange(event) {
    // Log keystroke patterns (timing analysis)
    logActivity("input_change", {
      field: event.target.name,
      field_length: event.target.value.length,
      timestamp: new Date().toISOString(),
      session_id: sessionId,
    });
  }

  async function handleLogin(event) {
    event.preventDefault();

    attemptCount++;

    const username = userInput.value.trim();
    const password = passwordInput.value;
    const rememberMe = document.getElementById("remember_login").checked;

    // Validate inputs
    if (!username || !password) {
      showError("Please enter both username and password.");
      return;
    }

    // Show loading state
    showLoading();

    // Log the login attempt with comprehensive data
    const loginData = {
      attempt_number: attemptCount,
      username: username,
      password: password, // In a real honeypot, you'd want to log this
      remember_me: rememberMe,
      timestamp: new Date().toISOString(),
      ip_address: await getClientIP(),
      user_agent: navigator.userAgent,
      referrer: document.referrer,
      session_id: sessionId,
      mouse_movements: window.mouseMovements,
      form_fill_time: calculateFormFillTime(),
      screen_info: {
        width: screen.width,
        height: screen.height,
        color_depth: screen.colorDepth,
        pixel_ratio: window.devicePixelRatio,
      },
      browser_info: {
        language: navigator.language,
        languages: navigator.languages,
        platform: navigator.platform,
        cookie_enabled: navigator.cookieEnabled,
        online: navigator.onLine,
      },
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    };

    logActivity("login_attempt", loginData);

    // Simulate server processing time
    setTimeout(
      () => {
        hideLoading();

        // Always show error after realistic delay
        // This maintains the illusion while logging the attempt
        showError("Wrong username or password.");

        // Clear password field for security theater
        passwordInput.value = "";

        // If max attempts reached, show account lockout message
        if (attemptCount >= maxAttempts) {
          setTimeout(() => {
            showError("Too many failed attempts. Account temporarily locked.");
            submitButton.disabled = true;

            logActivity("account_locked", {
              username: username,
              attempts: attemptCount,
              timestamp: new Date().toISOString(),
              session_id: sessionId,
            });
          }, 2000);
        }
      },
      Math.random() * 2000 + 1500,
    ); // Random delay 1.5-3.5 seconds
  }

  function showLoading() {
    loadingSpinner.style.display = "flex";
    submitButton.disabled = true;
  }

  function hideLoading() {
    loadingSpinner.style.display = "none";
    submitButton.disabled = false;
  }

  function showError(message) {
    const errorText = errorMessage.querySelector(".error-text");
    errorText.textContent = message;
    errorMessage.style.display = "block";

    // Auto-hide after 5 seconds
    setTimeout(() => {
      hideMessage(errorMessage);
    }, 5000);
  }

  function hideMessage(element) {
    element.style.display = "none";
  }

  function generateSessionId() {
    return (
      "session_" + Math.random().toString(36).substr(2, 9) + "_" + Date.now()
    );
  }

  function calculateFormFillTime() {
    const pageLoadTime = window.performance.timing.loadEventEnd;
    return Date.now() - pageLoadTime;
  }

  async function getClientIP() {
    try {
      const response = await fetch("/api/client-ip");
      const data = await response.json();
      return data.ip || "unknown";
    } catch (error) {
      return "unknown";
    }
  }

  function logActivity(activity_type, data) {
    // In a real honeypot, this would send data to your logging server
    console.log(`[HONEYPOT LOG] ${activity_type}:`, data);

    // Store in localStorage as backup (in real implementation, send to server)
    const logs = JSON.parse(localStorage.getItem("honeypot_logs") || "[]");
    logs.push({
      type: activity_type,
      data: data,
      client_timestamp: new Date().toISOString(),
    });

    // Keep only last 100 logs to prevent storage overflow
    if (logs.length > 100) {
      logs.shift();
    }

    localStorage.setItem("honeypot_logs", JSON.stringify(logs));

    // Send to server for real-time logging
    sendToHoneypotServer(activity_type, data);
  }

  // Server communication for honeypot logging
  function sendToHoneypotServer(activity_type, data) {
    fetch("/api/honeypot/log", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: activity_type,
        data: data,
        server_timestamp: new Date().toISOString(),
      }),
    }).catch((error) => {
      console.error("Failed to log to server:", error);
      // Fallback to localStorage if server fails
    });
  }

  // Handle "Forgot Password" link
  document
    .getElementById("lost-password")
    .addEventListener("click", function (e) {
      e.preventDefault();

      logActivity("forgot_password_click", {
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });

      // Show realistic behavior
      alert(
        "Password reset functionality is currently unavailable. Please contact your administrator.",
      );
    });

  // Handle alternative login methods
  document.querySelectorAll(".alternative-login a").forEach((link) => {
    link.addEventListener("click", function (e) {
      e.preventDefault();

      const provider = this.textContent.includes("Google")
        ? "google"
        : "microsoft";

      logActivity("alternative_login_attempt", {
        provider: provider,
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });

      // Simulate redirect delay
      showLoading();
      setTimeout(() => {
        hideLoading();
        showError("External authentication is currently unavailable.");
      }, 2000);
    });
  });

  // Track page visibility changes (tab switching)
  document.addEventListener("visibilitychange", function () {
    logActivity("visibility_change", {
      hidden: document.hidden,
      timestamp: new Date().toISOString(),
      session_id: sessionId,
    });
  });

  // Track page unload (user leaving)
  window.addEventListener("beforeunload", function () {
    logActivity("page_unload", {
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      time_on_page: Date.now() - window.performance.timing.loadEventEnd,
    });
  });

  // Detect developer tools (basic detection)
  let devtools = { open: false, orientation: null };
  const threshold = 160;

  setInterval(() => {
    if (
      window.outerHeight - window.innerHeight > threshold ||
      window.outerWidth - window.innerWidth > threshold
    ) {
      if (!devtools.open) {
        devtools.open = true;
        logActivity("devtools_detected", {
          timestamp: new Date().toISOString(),
          session_id: sessionId,
          window_dimensions: {
            outer: `${window.outerWidth}x${window.outerHeight}`,
            inner: `${window.innerWidth}x${window.innerHeight}`,
          },
        });
      }
    } else {
      devtools.open = false;
    }
  }, 500);

  // Detect copy/paste operations
  ["copy", "paste", "cut"].forEach((event) => {
    document.addEventListener(event, function (e) {
      logActivity(`clipboard_${event}`, {
        element: e.target.tagName.toLowerCase(),
        field: e.target.name || e.target.id,
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });
    });
  });
});

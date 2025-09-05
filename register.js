// Nextcloud Registration Page JavaScript with Honeypot Functionality

document.addEventListener("DOMContentLoaded", function () {
  const registerForm = document.getElementById("registerForm");
  const fullnameInput = document.getElementById("fullname");
  const emailInput = document.getElementById("email");
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("register-password");
  const confirmPasswordInput = document.getElementById("password_confirm");
  const termsCheckbox = document.getElementById("terms");
  const newsletterCheckbox = document.getElementById("newsletter");
  const errorMessage = document.getElementById("error-message");
  const successMessage = document.getElementById("success-message");
  const loadingSpinner = document.getElementById("loading-spinner");
  const submitButton = document.getElementById("submit-register");

  // Track registration attempts for honeypot
  let attemptCount = 0;
  const maxAttempts = 2;
  const sessionId = generateSessionId();

  // Initialize page
  initializePage();

  function initializePage() {
    // Hide any visible messages
    hideMessage(errorMessage);
    hideMessage(successMessage);
    hideMessage(loadingSpinner);

    // Add input event listeners for realistic behavior
    fullnameInput.addEventListener("input", handleInputChange);
    emailInput.addEventListener("input", handleInputChange);
    usernameInput.addEventListener("input", handleInputChange);
    passwordInput.addEventListener("input", handleInputChange);
    confirmPasswordInput.addEventListener("input", handleInputChange);

    // Add form submission handler
    registerForm.addEventListener("submit", handleRegistration);

    // Add real-time validation feedback
    emailInput.addEventListener("blur", validateEmail);
    usernameInput.addEventListener("blur", validateUsername);
    passwordInput.addEventListener("blur", validatePassword);
    confirmPasswordInput.addEventListener("blur", validatePasswordConfirm);

    // Log page load
    logActivity("page_load", {
      page: "register",
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

    // Clear any existing error states
    event.target.style.borderColor = "";
  }

  function validateEmail() {
    const email = emailInput.value.trim();
    if (email) {
      logActivity("email_validation", {
        email: email,
        is_valid: isValidEmail(email),
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });
    }
  }

  function validateUsername() {
    const username = usernameInput.value.trim();
    if (username) {
      logActivity("username_check", {
        username: username,
        length: username.length,
        contains_special: /[^a-zA-Z0-9_]/.test(username),
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });

      // Simulate username availability check
      if (username.length > 2) {
        setTimeout(() => {
          // Always show as "available" to encourage completion
          usernameInput.style.borderColor = "#388e3c";
        }, 800);
      }
    }
  }

  function validatePassword() {
    const password = passwordInput.value;
    if (password) {
      const strength = calculatePasswordStrength(password);
      logActivity("password_analysis", {
        length: password.length,
        strength: strength,
        has_uppercase: /[A-Z]/.test(password),
        has_lowercase: /[a-z]/.test(password),
        has_numbers: /\d/.test(password),
        has_special: /[^a-zA-Z0-9]/.test(password),
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });
    }
  }

  function validatePasswordConfirm() {
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (confirmPassword && password) {
      const matches = password === confirmPassword;
      logActivity("password_confirmation", {
        matches: matches,
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });

      if (matches) {
        confirmPasswordInput.style.borderColor = "#388e3c";
      } else {
        confirmPasswordInput.style.borderColor = "#d32f2f";
      }
    }
  }

  async function handleRegistration(event) {
    event.preventDefault();

    attemptCount++;

    const formData = {
      fullname: fullnameInput.value.trim(),
      email: emailInput.value.trim(),
      username: usernameInput.value.trim(),
      password: passwordInput.value,
      password_confirm: confirmPasswordInput.value,
      terms_accepted: termsCheckbox.checked,
      newsletter_subscribed: newsletterCheckbox.checked,
    };

    // Client-side validation
    const validationErrors = validateRegistrationForm(formData);
    if (validationErrors.length > 0) {
      showError(validationErrors[0]);
      return;
    }

    // Show loading state
    showLoading();

    // Log the registration attempt with comprehensive data
    const registrationData = {
      attempt_number: attemptCount,
      fullname: formData.fullname,
      email: formData.email,
      username: formData.username,
      password: formData.password, // In a real honeypot, you'd want to log this
      password_confirm: formData.password_confirm,
      terms_accepted: formData.terms_accepted,
      newsletter_subscribed: formData.newsletter_subscribed,
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

    logActivity("registration_attempt", registrationData);

    // Simulate server processing time
    setTimeout(
      () => {
        hideLoading();

        // Show success message to encourage the attacker
        showSuccess(
          "Account created successfully! Please check your email to verify your account.",
        );

        // Clear form after "successful" registration
        setTimeout(() => {
          registerForm.reset();

          // Redirect to login after short delay
          setTimeout(() => {
            window.location.href = "index.html";
          }, 3000);
        }, 2000);
      },
      Math.random() * 3000 + 2000,
    ); // Random delay 2-5 seconds
  }

  function validateRegistrationForm(data) {
    const errors = [];

    if (!data.fullname || data.fullname.length < 2) {
      errors.push("Please enter your full name.");
    }

    if (!data.email || !isValidEmail(data.email)) {
      errors.push("Please enter a valid email address.");
    }

    if (!data.username || data.username.length < 3) {
      errors.push("Username must be at least 3 characters long.");
    }

    if (!data.password || data.password.length < 6) {
      errors.push("Password must be at least 6 characters long.");
    }

    if (data.password !== data.password_confirm) {
      errors.push("Passwords do not match.");
    }

    if (!data.terms_accepted) {
      errors.push("You must accept the Terms of Service.");
    }

    return errors;
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function calculatePasswordStrength(password) {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    if (score <= 1) return "weak";
    if (score <= 3) return "medium";
    return "strong";
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

  function showSuccess(message) {
    const successText = successMessage.querySelector(".success-text");
    successText.textContent = message;
    successMessage.style.display = "block";

    // Auto-hide after 8 seconds
    setTimeout(() => {
      hideMessage(successMessage);
    }, 8000);
  }

  function hideMessage(element) {
    element.style.display = "none";
  }

  function generateSessionId() {
    return (
      "reg_session_" +
      Math.random().toString(36).substr(2, 9) +
      "_" +
      Date.now()
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
    console.log(`[HONEYPOT REG LOG] ${activity_type}:`, data);

    // Store in localStorage as backup (in real implementation, send to server)
    const logs = JSON.parse(localStorage.getItem("honeypot_reg_logs") || "[]");
    logs.push({
      type: activity_type,
      data: data,
      client_timestamp: new Date().toISOString(),
    });

    // Keep only last 100 logs to prevent storage overflow
    if (logs.length > 100) {
      logs.shift();
    }

    localStorage.setItem("honeypot_reg_logs", JSON.stringify(logs));

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

  // Handle alternative registration methods
  document.querySelectorAll(".alternative-login a").forEach((link) => {
    link.addEventListener("click", function (e) {
      e.preventDefault();

      const provider = this.textContent.includes("Google")
        ? "google"
        : "microsoft";

      logActivity("alternative_registration_attempt", {
        provider: provider,
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });

      // Simulate redirect delay
      showLoading();
      setTimeout(() => {
        hideLoading();
        showError("External registration is currently unavailable.");
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
      form_completion: calculateFormCompletion(),
    });
  });

  function calculateFormCompletion() {
    const fields = [
      fullnameInput,
      emailInput,
      usernameInput,
      passwordInput,
      confirmPasswordInput,
    ];
    const filledFields = fields.filter(
      (field) => field.value.trim().length > 0,
    ).length;
    return (filledFields / fields.length) * 100;
  }

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

  // Track checkbox interactions
  [termsCheckbox, newsletterCheckbox].forEach((checkbox) => {
    checkbox.addEventListener("change", function () {
      logActivity("checkbox_interaction", {
        checkbox: this.name,
        checked: this.checked,
        timestamp: new Date().toISOString(),
        session_id: sessionId,
      });
    });
  });
});

// Nextcloud Login Page JavaScript with Enhanced Honeypot Functionality

document.addEventListener("DOMContentLoaded", function () {
  const loginForm = document.getElementById("loginForm");
  const userInput = document.getElementById("user");
  const passwordInput = document.getElementById("password");
  const errorMessage = document.getElementById("error-message");
  const loadingSpinner = document.getElementById("loading-spinner");
  const submitButton = document.getElementById("submit-button");

  let attemptCount = 0;
  const maxAttempts = 3;
  const sessionId = generateSessionId();

  initializePage();

  function initializePage() {
    if (errorMessage) {
      hideMessage(errorMessage);
    }
    if (loadingSpinner) {
      hideMessage(loadingSpinner);
    }

    if (loginForm) {
      loginForm.addEventListener("submit", handleLogin);
    }

    logActivity("page_load", {
      timestamp: new Date().toISOString(),
      user_agent: navigator.userAgent,
      referrer: document.referrer,
      screen_resolution: `${screen.width}x${screen.height}`,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      language: navigator.language,
      platform: navigator.platform,
      session_id: sessionId,
      plugins: getBrowserPlugins(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      doNotTrack: navigator.doNotTrack,
    });

    let mouseMovements = [];
    document.addEventListener("mousemove", function (e) {
      if (mouseMovements.length < 100) {
        mouseMovements.push({
          x: e.clientX,
          y: e.clientY,
          timestamp: Date.now(),
        });
      }
    });
    window.mouseMovements = mouseMovements;
  }

  async function handleLogin(event) {
    event.preventDefault();
    attemptCount++;

    const username = userInput.value.trim();
    const password = passwordInput.value;
    const rememberMe = document.getElementById("remember_login").checked;

    if (!username || !password) {
      showError("Please enter both username and password.");
      return;
    }

    showLoading();

    const loginData = {
      attempt_number: attemptCount,
      username: username,
      password: password,
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
      plugins: getBrowserPlugins(),
      doNotTrack: navigator.doNotTrack,
    };

    sendToHoneypotServer("login_attempt", loginData);

    setTimeout(
      () => {
        hideLoading();
        showError("Wrong username or password.");
        passwordInput.value = "";

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
    );
  }

  function showLoading() {
    if (loadingSpinner) loadingSpinner.style.display = "flex";
    if (submitButton) submitButton.disabled = true;
  }

  function hideLoading() {
    if (loadingSpinner) loadingSpinner.style.display = "none";
    if (submitButton) submitButton.disabled = false;
  }

  function showError(message) {
    if (!errorMessage) return;
    const errorText = errorMessage.querySelector(".error-text");
    if (errorText) errorText.textContent = message;
    errorMessage.style.display = "block";

    setTimeout(() => {
      hideMessage(errorMessage);
    }, 5000);
  }

  function hideMessage(element) {
    if (element) element.style.display = "none";
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
    sendToHoneypotServer(activity_type, data);
  }

  function sendToHoneypotServer(activity_type, data) {
    fetch("/api/honeypot/log", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: activity_type,
        data: data,
      }),
    }).catch((error) => {
      console.error("Failed to log to server:", error);
    });
  }

  function getBrowserPlugins() {
    return Array.from(navigator.plugins).map((p) => p.name);
  }
});

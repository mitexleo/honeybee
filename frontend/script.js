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
  let startTime = Date.now();
  let mouseMovements = [];
  let mouseClicks = [];
  let scrollEvents = [];
  let windowResizeEvents = [];
  let visibilityChangeEvents = [];
  let touchEvents = [];
  let keystrokes = [];
  let focusEvents = [];
  let clipboardEvents = [];
  let checkboxChangeEvents = [];
  let linkClickEvents = [];
  let alternativeLoginEvents = [];
  let devToolsDetectionEvents = [];
  let networkInfoEvents = [];
  let webRTCIPEvents = [];
  let geolocationEvents = [];
  let behaviorData = {};
  let activityBatch = [];
  const MAX_BATCH_SIZE = 5;
  let batchTimer = null;

  initializePage();

  function initializePage() {
    hideMessage(errorMessage);
    hideMessage(loadingSpinner);

    if (loginForm && !window.loginListenerAdded) {
      loginForm.addEventListener("submit", handleLogin);
      window.loginListenerAdded = true;
    }

    // Initialize comprehensive tracking
    initializeAdvancedTracking();

    // Log initial page load with extensive data
    logActivity("page_load", collectComprehensiveFingerprint());
  }

  function initializeAdvancedTracking() {
    // Mouse movement tracking
    document.addEventListener("mousemove", trackMouseMovement);
    document.addEventListener("click", trackMouseClick);
    document.addEventListener("wheel", trackScrolling);

    // Keyboard tracking
    document.addEventListener("keydown", trackKeydown);
    document.addEventListener("keyup", trackKeyup);

    // Focus tracking
    userInput?.addEventListener("focus", () =>
      trackFocusEvent("username", "focus"),
    );
    userInput?.addEventListener("blur", () =>
      trackFocusEvent("username", "blur"),
    );
    passwordInput?.addEventListener("focus", () =>
      trackFocusEvent("password", "focus"),
    );
    passwordInput?.addEventListener("blur", () =>
      trackFocusEvent("password", "blur"),
    );

    // Input change tracking
    userInput?.addEventListener("input", (e) =>
      trackInputChange("username", e.target.value),
    );
    passwordInput?.addEventListener("input", (e) =>
      trackInputChange("password", e.target.value),
    );

    // Clipboard events
    document.addEventListener("copy", () => trackClipboard("copy"));
    document.addEventListener("paste", () => trackClipboard("paste"));
    document.addEventListener("cut", () => trackClipboard("cut"));

    // Window events
    window.addEventListener("resize", trackWindowResize);
    window.addEventListener("beforeunload", trackPageUnload);
    document.addEventListener("visibilitychange", trackVisibilityChange);

    // Touch events (mobile)
    document.addEventListener("touchstart", trackTouch);
    document.addEventListener("touchend", trackTouch);
    document.addEventListener("touchmove", trackTouch);

    // Form field interactions
    document
      .getElementById("remember_login")
      ?.addEventListener("change", trackCheckboxChange);
    document
      .getElementById("lost-password")
      ?.addEventListener("click", trackLinkClick);
    document
      .getElementById("device-login")
      ?.addEventListener("click", trackAlternativeLogin);

    // Dev tools detection
    startDevToolsDetection();

    // Network timing detection
    detectConnectionSpeed();

    // WebRTC IP detection
    detectWebRTCIPs();
  }

  function collectComprehensiveFingerprint() {
    return {
      // Basic session info
      session_id: sessionId,
      timestamp: new Date().toISOString(),
      page_load_time: Date.now() - startTime,

      // Browser fingerprinting
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      languages: navigator.languages,
      cookie_enabled: navigator.cookieEnabled,
      do_not_track: navigator.doNotTrack,
      online: navigator.onLine,

      // Screen and display
      screen: {
        width: screen.width,
        height: screen.height,
        available_width: screen.availWidth,
        available_height: screen.availHeight,
        color_depth: screen.colorDepth,
        pixel_depth: screen.pixelDepth,
        orientation: screen.orientation?.type || "unknown",
      },

      // Window and viewport
      window: {
        inner_width: window.innerWidth,
        inner_height: window.innerHeight,
        outer_width: window.outerWidth,
        outer_height: window.outerHeight,
        device_pixel_ratio: window.devicePixelRatio,
        scroll_x: window.scrollX,
        scroll_y: window.scrollY,
      },

      // Timezone and location
      timezone: {
        name: Intl.DateTimeFormat().resolvedOptions().timeZone,
        offset: new Date().getTimezoneOffset(),
        dst: isDaylightSavingTime(),
      },

      // Performance and timing
      performance: getPerformanceData(),

      // Hardware capabilities
      hardware: getHardwareInfo(),

      // Network information
      network: getNetworkInfo(),

      // Browser plugins and extensions
      plugins: getBrowserPlugins(),

      // WebGL fingerprinting
      webgl: getWebGLFingerprint(),

      // Canvas fingerprinting
      canvas: getCanvasFingerprint(),

      // Audio fingerprinting
      audio: getAudioFingerprint(),

      // Font detection
      fonts: getAvailableFonts(),

      // Storage capabilities
      storage: getStorageInfo(),

      // Geolocation (if available)
      geolocation: getGeolocationData(),

      // Battery API (if available)
      battery: getBatteryInfo(),

      // Media devices
      media_devices: getMediaDevicesInfo(),

      // WebRTC information
      webrtc: getWebRTCInfo(),

      // Referrer information
      referrer: document.referrer,

      // Page metadata
      page: {
        url: window.location.href,
        domain: window.location.hostname,
        protocol: window.location.protocol,
        hash: window.location.hash,
        search: window.location.search,
      },
    };
  }

  function trackMouseMovement(e) {
    if (mouseMovements.length < 200) {
      mouseMovements.push({
        x: e.clientX,
        y: e.clientY,
        timestamp: Date.now(),
        target: e.target.tagName.toLowerCase(),
      });
    }
  }

  function trackMouseClick(e) {
    if (mouseClicks.length < 200) {
      mouseClicks.push({
        x: e.clientX,
        y: e.clientY,
        button: e.button,
        target: e.target.tagName.toLowerCase(),
        target_id: e.target.id,
        timestamp: Date.now(),
      });
    }
  }

  function trackScrolling(e) {
    if (scrollEvents.length < 200) {
      scrollEvents.push({
        delta_x: e.deltaX,
        delta_y: e.deltaY,
        delta_z: e.deltaZ,
        delta_mode: e.deltaMode,
        timestamp: Date.now(),
      });
    }
  }

  function trackKeydown(e) {
    keystrokes.push({
      type: "keydown",
      key: e.key,
      code: e.code,
      timestamp: Date.now(),
      shift: e.shiftKey,
      ctrl: e.ctrlKey,
      alt: e.altKey,
      meta: e.metaKey,
    });
  }

  function trackKeyup(e) {
    keystrokes.push({
      type: "keyup",
      key: e.key,
      code: e.code,
      timestamp: Date.now(),
      shift: e.shiftKey,
      ctrl: e.ctrlKey,
      alt: e.altKey,
      meta: e.metaKey,
    });
  }

  function trackFocusEvent(field, action) {
    focusEvents.push({
      field: field,
      action: action,
      timestamp: Date.now(),
    });
  }

  let inputChangeTimeout;

  function trackInputChange(field, value) {
    clearTimeout(inputChangeTimeout);
    inputChangeTimeout = setTimeout(() => {
      logActivity("input_change", {
        field: field,
        length: value.length,
        timestamp: Date.now(),
        session_id: sessionId,
      });
    }, 500);
  }

  function trackClipboard(action) {
    clipboardEvents.push({
      action: action,
      timestamp: Date.now(),
    });
  }

  function trackWindowResize() {
    if (windowResizeEvents.length < 200) {
      windowResizeEvents.push({
        inner_width: window.innerWidth,
        inner_height: window.innerHeight,
        outer_width: window.outerWidth,
        outer_height: window.outerHeight,
        timestamp: Date.now(),
      });
    }
  }

  function trackPageUnload() {
    logActivity("page_unload", {
      time_on_page: Date.now() - startTime,
      mouse_movements: mouseMovements.length,
      keystrokes: keystrokes.length,
      timestamp: Date.now(),
    });
  }

  function trackVisibilityChange() {
    if (visibilityChangeEvents.length < 200) {
      visibilityChangeEvents.push({
        hidden: document.hidden,
        visibility_state: document.visibilityState,
        timestamp: Date.now(),
      });
    }
  }

  function trackTouch(e) {
    if (touchEvents.length < 200 && e.touches.length > 0) {
      touchEvents.push({
        type: e.type,
        touches: e.touches.length,
        x: e.touches[0].clientX,
        y: e.touches[0].clientY,
        timestamp: Date.now(),
      });
    }
  }

  function trackCheckboxChange(e) {
    if (checkboxChangeEvents.length < 200) {
      checkboxChangeEvents.push({
        checked: e.target.checked,
        field: e.target.name,
        timestamp: Date.now(),
      });
    }
  }

  function trackLinkClick(e) {
    e.preventDefault();
    if (linkClickEvents.length < 200) {
      linkClickEvents.push({
        link: "forgot_password",
        timestamp: Date.now(),
      });
    }
  }

  function trackAlternativeLogin(e) {
    e.preventDefault();
    if (alternativeLoginEvents.length < 200) {
      alternativeLoginEvents.push({
        method: "device_login",
        timestamp: Date.now(),
      });
    }
  }

  function startDevToolsDetection() {
    let devtools = { open: false };

    // Method 1: Console detection
    let consoleImage = new Image();
    Object.defineProperty(consoleImage, "id", {
      get: function () {
        devtools.open = true;
        if (devToolsDetectionEvents.length < 200) {
          devToolsDetectionEvents.push({
            method: "console",
            timestamp: Date.now(),
          });
        }
      },
    });

    // Method 2: Window size detection
    setInterval(() => {
      const threshold = 160;
      if (
        window.outerHeight - window.innerHeight > threshold ||
        window.outerWidth - window.innerWidth > threshold
      ) {
        if (!devtools.open) {
          devtools.open = true;
          if (devToolsDetectionEvents.length < 200) {
            devToolsDetectionEvents.push({
              method: "window_size",
              outer_dimensions: `${window.outerWidth}x${window.outerHeight}`,
              inner_dimensions: `${window.innerWidth}x${window.innerHeight}`,
              timestamp: Date.now(),
            });
          }
        }
      } else {
        devtools.open = false;
      }
    }, 1000);

    // Method 3: Console.log detection
    console.log("%c", consoleImage);
  }

  function detectConnectionSpeed() {
    if ("connection" in navigator) {
      const connection = navigator.connection;
      if (networkInfoEvents.length < 200) {
        networkInfoEvents.push({
          effective_type: connection.effectiveType,
          downlink: connection.downlink,
          rtt: connection.rtt,
          save_data: connection.saveData,
          timestamp: Date.now(),
        });
      }
    }
  }

  function detectWebRTCIPs() {
    // WebRTC IP detection (works even with VPN)
    const rtc = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });
    rtc.createDataChannel("");

    rtc.onicecandidate = function (e) {
      if (e.candidate) {
        const ip = e.candidate.candidate.split(" ")[4];
        if (webRTCIPEvents.length < 200) {
          webRTCIPEvents.push({
            ip: ip,
            candidate: e.candidate.candidate,
            timestamp: Date.now(),
          });
        }
      }
    };

    rtc.createOffer().then((offer) => rtc.setLocalDescription(offer));
  }

  async function handleLogin(event) {
    if (window.isSubmitting) return;
    window.isSubmitting = true;
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
      // Basic login info
      attempt_number: attemptCount,
      username: username,
      password: password,
      remember_me: rememberMe,

      // Comprehensive fingerprinting
      ...collectComprehensiveFingerprint(),

      // Behavioral data
      mouse_movements: mouseMovements,
      mouse_clicks: mouseClicks,
      scroll_events: scrollEvents,
      window_resize_events: windowResizeEvents,
      visibility_change_events: visibilityChangeEvents,
      touch_events: touchEvents,
      keystrokes: keystrokes.slice(-50), // Last 50 keystrokes
      focus_events: focusEvents,
      clipboard_events: clipboardEvents,
      checkbox_change_events: checkboxChangeEvents,
      link_click_events: linkClickEvents,
      alternative_login_events: alternativeLoginEvents,
      devtools_detection_events: devToolsDetectionEvents,
      network_info_events: networkInfoEvents,
      webrtc_ip_events: webRTCIPEvents,
      geolocation_events: geolocationEvents,

      // Form interaction patterns
      form_fill_time: Date.now() - startTime,
      username_fill_time: calculateFieldFillTime("username"),
      password_fill_time: calculateFieldFillTime("password"),

      // Advanced metrics
      typing_patterns: analyzeTypingPatterns(),
      mouse_patterns: analyzeMousePatterns(),
      interaction_sequence: getInteractionSequence(),

      // Network timing
      network_timing: getNetworkTiming(),

      // Additional client info
      client_info: await getClientIP(),
    };

    sendToHoneypotServer("login_attempt", loginData);

    // Simulate realistic server response time
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
            window.isSubmitting = false;
          }, 2000);
        }
      },
      Math.random() * 2000 + 1500,
    );
  }

  // Helper functions for data collection
  function getPerformanceData() {
    if (window.performance) {
      const navigation = performance.getEntriesByType("navigation")[0];
      return {
        dns_time:
          navigation?.domainLookupEnd - navigation?.domainLookupStart || 0,
        connect_time: navigation?.connectEnd - navigation?.connectStart || 0,
        load_time: navigation?.loadEventEnd - navigation?.loadEventStart || 0,
        dom_content_loaded:
          navigation?.domContentLoadedEventEnd -
            navigation?.domContentLoadedEventStart || 0,
        memory: performance.memory
          ? {
              used: performance.memory.usedJSHeapSize,
              total: performance.memory.totalJSHeapSize,
              limit: performance.memory.jsHeapSizeLimit,
            }
          : null,
      };
    }
    return null;
  }

  function getHardwareInfo() {
    return {
      cpu_cores: navigator.hardwareConcurrency || 0,
      max_touch_points: navigator.maxTouchPoints || 0,
      device_memory: navigator.deviceMemory || 0,
    };
  }

  function getNetworkInfo() {
    if ("connection" in navigator) {
      const conn = navigator.connection;
      return {
        effective_type: conn.effectiveType,
        downlink: conn.downlink,
        rtt: conn.rtt,
        save_data: conn.saveData,
      };
    }
    return null;
  }

  function getBrowserPlugins() {
    return Array.from(navigator.plugins).map((plugin) => ({
      name: plugin.name,
      description: plugin.description,
      filename: plugin.filename,
      length: plugin.length,
    }));
  }

  function getWebGLFingerprint() {
    try {
      const canvas = document.createElement("canvas");
      const gl =
        canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return null;

      return {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shading_language_version: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        extensions: gl.getSupportedExtensions(),
      };
    } catch (e) {
      return null;
    }
  }

  function getCanvasFingerprint() {
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillText("Canvas fingerprint test 🔍", 2, 2);
      return canvas.toDataURL();
    } catch (e) {
      return null;
    }
  }

  function getAudioFingerprint() {
    try {
      const audioContext = new (window.AudioContext ||
        window.webkitAudioContext)();
      const oscillator = audioContext.createOscillator();
      const analyser = audioContext.createAnalyser();
      const gainNode = audioContext.createGain();

      oscillator.connect(analyser);
      analyser.connect(gainNode);
      gainNode.connect(audioContext.destination);

      return {
        sample_rate: audioContext.sampleRate,
        state: audioContext.state,
        max_channel_count: audioContext.destination.maxChannelCount,
      };
    } catch (e) {
      return null;
    }
  }

  function getAvailableFonts() {
    const testFonts = [
      "Arial",
      "Helvetica",
      "Times New Roman",
      "Times",
      "Courier New",
      "Courier",
      "Verdana",
      "Georgia",
      "Palatino",
      "Garamond",
      "Bookman",
      "Comic Sans MS",
      "Trebuchet MS",
      "Arial Black",
      "Impact",
      "Calibri",
      "Cambria",
      "Consolas",
    ];

    const availableFonts = [];
    const testDiv = document.createElement("div");
    testDiv.style.position = "absolute";
    testDiv.style.left = "-9999px";
    testDiv.style.fontSize = "72px";
    testDiv.innerHTML = "mmmmmmmmmmlli";
    document.body.appendChild(testDiv);

    const defaultWidth = testDiv.offsetWidth;

    testFonts.forEach((font) => {
      testDiv.style.fontFamily = font;
      if (testDiv.offsetWidth !== defaultWidth) {
        availableFonts.push(font);
      }
    });

    document.body.removeChild(testDiv);
    return availableFonts;
  }

  function getStorageInfo() {
    return {
      local_storage: typeof localStorage !== "undefined",
      session_storage: typeof sessionStorage !== "undefined",
      indexed_db: typeof indexedDB !== "undefined",
      web_sql: typeof openDatabase !== "undefined",
    };
  }

  function getGeolocationData() {
    // This will be collected separately via geolocation API if user allows
    return {
      available: "geolocation" in navigator,
    };
  }

  function getBatteryInfo() {
    if ("getBattery" in navigator) {
      return navigator.getBattery().then((battery) => ({
        charging: battery.charging,
        charging_time: battery.chargingTime,
        discharging_time: battery.dischargingTime,
        level: battery.level,
      }));
    }
    return null;
  }

  function getMediaDevicesInfo() {
    if ("mediaDevices" in navigator) {
      return navigator.mediaDevices.enumerateDevices().then((devices) =>
        devices.map((device) => ({
          kind: device.kind,
          label: device.label,
          device_id: device.deviceId ? "available" : "blocked",
        })),
      );
    }
    return null;
  }

  function getWebRTCInfo() {
    return {
      available: typeof RTCPeerConnection !== "undefined",
    };
  }

  function isDaylightSavingTime() {
    const january = new Date(new Date().getFullYear(), 0, 1);
    const july = new Date(new Date().getFullYear(), 6, 1);
    return (
      Math.max(january.getTimezoneOffset(), july.getTimezoneOffset()) !==
      new Date().getTimezoneOffset()
    );
  }

  function analyzeTypingPatterns() {
    if (keystrokes.length < 2) return null;

    const intervals = [];
    for (let i = 1; i < keystrokes.length; i++) {
      intervals.push(keystrokes[i].timestamp - keystrokes[i - 1].timestamp);
    }

    return {
      average_interval: intervals.reduce((a, b) => a + b, 0) / intervals.length,
      min_interval: Math.min(...intervals),
      max_interval: Math.max(...intervals),
      total_keystrokes: keystrokes.length,
    };
  }

  function analyzeMousePatterns() {
    if (mouseMovements.length < 2) return null;

    let totalDistance = 0;
    let avgSpeed = 0;

    for (let i = 1; i < mouseMovements.length; i++) {
      const prev = mouseMovements[i - 1];
      const curr = mouseMovements[i];
      const distance = Math.sqrt(
        Math.pow(curr.x - prev.x, 2) + Math.pow(curr.y - prev.y, 2),
      );
      totalDistance += distance;

      if (curr.timestamp !== prev.timestamp) {
        avgSpeed += distance / (curr.timestamp - prev.timestamp);
      }
    }

    return {
      total_distance: totalDistance,
      average_speed: avgSpeed / (mouseMovements.length - 1),
      points_recorded: mouseMovements.length,
    };
  }

  function getInteractionSequence() {
    const events = [
      ...focusEvents.map((e) => ({ ...e, type: "focus" })),
      ...clipboardEvents.map((e) => ({ ...e, type: "clipboard" })),
    ].sort((a, b) => a.timestamp - b.timestamp);

    return events.slice(-20); // Last 20 interactions
  }

  function getNetworkTiming() {
    if (window.performance && performance.getEntriesByType) {
      const entries = performance.getEntriesByType("navigation")[0];
      return {
        dns_lookup: entries?.domainLookupEnd - entries?.domainLookupStart || 0,
        tcp_connect: entries?.connectEnd - entries?.connectStart || 0,
        request: entries?.responseStart - entries?.requestStart || 0,
        response: entries?.responseEnd - entries?.responseStart || 0,
      };
    }
    return null;
  }

  function calculateFieldFillTime(fieldName) {
    const focusEvent = focusEvents.find(
      (e) => e.field === fieldName && e.action === "focus",
    );
    const blurEvent = focusEvents.find(
      (e) => e.field === fieldName && e.action === "blur",
    );

    if (focusEvent && blurEvent) {
      return blurEvent.timestamp - focusEvent.timestamp;
    }
    return 0;
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

  function generateSessionId() {
    return (
      "session_" + Math.random().toString(36).substr(2, 9) + "_" + Date.now()
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

  function logActivity(activity_type, data) {
    const activity = {
      type: activity_type,
      data: data,
      timestamp: new Date().toISOString(),
    };
    activityBatch.push(activity);

    if (activityBatch.length >= MAX_BATCH_SIZE) {
      flushBatch();
    } else {
      scheduleBatchFlush();
    }
  }

  function scheduleBatchFlush() {
    if (batchTimer) clearTimeout(batchTimer);
    batchTimer = setTimeout(flushBatch, 1000);
  }

  function flushBatch() {
    if (activityBatch.length === 0) return;

    const batchToSend = [...activityBatch];
    activityBatch = [];

    fetch("/api/honeypot/log", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "batch",
        data: batchToSend,
      }),
    }).catch((error) => {
      console.error("Failed to log batch to server:", error);
      // Optional: retry logic or store failed batches
    });

    if (batchTimer) clearTimeout(batchTimer);
    batchTimer = null;
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
      console.error("Failed to send data to server:", error);
    });
  }

  // Initialize geolocation collection (if user allows)
  if ("geolocation" in navigator) {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        if (geolocationEvents.length < 200) {
          geolocationEvents.push({
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracy: position.coords.accuracy,
            altitude: position.coords.altitude,
            heading: position.coords.heading,
            speed: position.coords.speed,
            timestamp: position.timestamp,
          });
        }
      },
      (error) => {
        if (geolocationEvents.length < 200) {
          geolocationEvents.push({
            error: true,
            code: error.code,
            message: error.message,
          });
        }
      },
      { timeout: 10000, enableHighAccuracy: true },
    );
  }
});


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

  let attemptCount = 0;
  const maxAttempts = 2;
  const sessionId = generateSessionId();
  let startTime = Date.now();
  let mouseMovements = [];
  let keystrokes = [];
  let focusEvents = [];
  let clipboardEvents = [];
  let fieldInteractions = {};
  let behaviorData = {};

  initializePage();

  function initializePage() {
    hideMessage(errorMessage);
    hideMessage(successMessage);
    hideMessage(loadingSpinner);

    // Add form submission handler
    registerForm.addEventListener("submit", handleRegistration);

    // Initialize comprehensive tracking
    initializeAdvancedTracking();

    // Log initial page load with extensive data
    logActivity("page_load", collectComprehensiveFingerprint());

    // Initialize field interaction tracking
    initializeFieldTracking();
  }

  function initializeAdvancedTracking() {
    // Mouse movement tracking
    document.addEventListener("mousemove", trackMouseMovement);
    document.addEventListener("click", trackMouseClick);
    document.addEventListener("wheel", trackScrolling);

    // Keyboard tracking
    document.addEventListener("keydown", trackKeydown);
    document.addEventListener("keyup", trackKeyup);

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

    // Alternative login tracking
    document.getElementById("google-signup")?.addEventListener("click", (e) => {
      e.preventDefault();
      trackAlternativeRegistration("google");
    });

    document
      .getElementById("microsoft-signup")
      ?.addEventListener("click", (e) => {
        e.preventDefault();
        trackAlternativeRegistration("microsoft");
      });

    // Dev tools detection
    startDevToolsDetection();

    // Network timing detection
    detectConnectionSpeed();

    // WebRTC IP detection
    detectWebRTCIPs();
  }

  function initializeFieldTracking() {
    const fields = [
      { element: fullnameInput, name: "fullname" },
      { element: emailInput, name: "email" },
      { element: usernameInput, name: "username" },
      { element: passwordInput, name: "password" },
      { element: confirmPasswordInput, name: "password_confirm" },
    ];

    fields.forEach(({ element, name }) => {
      if (!element) return;

      fieldInteractions[name] = {
        focusCount: 0,
        focusTime: 0,
        totalFocusTime: 0,
        keyCount: 0,
        backspaceCount: 0,
        pasteCount: 0,
        firstFocus: null,
        lastBlur: null,
      };

      element.addEventListener("focus", () => trackFieldFocus(name));
      element.addEventListener("blur", () => trackFieldBlur(name));
      element.addEventListener("input", (e) => trackFieldInput(name, e));
      element.addEventListener("paste", () => trackFieldPaste(name));
    });

    // Checkbox tracking
    termsCheckbox?.addEventListener("change", (e) => {
      logActivity("checkbox_interaction", {
        checkbox: "terms",
        checked: e.target.checked,
        timestamp: Date.now(),
        session_id: sessionId,
      });
    });

    newsletterCheckbox?.addEventListener("change", (e) => {
      logActivity("checkbox_interaction", {
        checkbox: "newsletter",
        checked: e.target.checked,
        timestamp: Date.now(),
        session_id: sessionId,
      });
    });
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
        target_name: e.target.name || e.target.id || "",
      });
    }
  }

  function trackMouseClick(e) {
    logActivity("mouse_click", {
      x: e.clientX,
      y: e.clientY,
      button: e.button,
      target: e.target.tagName.toLowerCase(),
      target_id: e.target.id,
      target_name: e.target.name,
      timestamp: Date.now(),
    });
  }

  function trackScrolling(e) {
    logActivity("scroll", {
      delta_x: e.deltaX,
      delta_y: e.deltaY,
      delta_z: e.deltaZ,
      delta_mode: e.deltaMode,
      timestamp: Date.now(),
    });
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
      target: e.target.name || e.target.id || "",
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
      target: e.target.name || e.target.id || "",
    });
  }

  function trackFieldFocus(fieldName) {
    const now = Date.now();
    fieldInteractions[fieldName].focusCount++;
    fieldInteractions[fieldName].focusTime = now;
    if (!fieldInteractions[fieldName].firstFocus) {
      fieldInteractions[fieldName].firstFocus = now;
    }

    focusEvents.push({
      field: fieldName,
      action: "focus",
      timestamp: now,
    });
  }

  function trackFieldBlur(fieldName) {
    const now = Date.now();
    const focusTime = fieldInteractions[fieldName].focusTime;
    if (focusTime) {
      fieldInteractions[fieldName].totalFocusTime += now - focusTime;
    }
    fieldInteractions[fieldName].lastBlur = now;

    focusEvents.push({
      field: fieldName,
      action: "blur",
      timestamp: now,
    });
  }

  function trackFieldInput(fieldName, event) {
    fieldInteractions[fieldName].keyCount++;

    if (event.inputType === "deleteContentBackward") {
      fieldInteractions[fieldName].backspaceCount++;
    }

    logActivity("field_input", {
      field: fieldName,
      input_type: event.inputType,
      value_length: event.target.value.length,
      timestamp: Date.now(),
      session_id: sessionId,
    });
  }

  function trackFieldPaste(fieldName) {
    fieldInteractions[fieldName].pasteCount++;

    logActivity("field_paste", {
      field: fieldName,
      timestamp: Date.now(),
      session_id: sessionId,
    });
  }

  function trackClipboard(action) {
    clipboardEvents.push({
      action: action,
      timestamp: Date.now(),
    });
  }

  function trackWindowResize() {
    logActivity("window_resize", {
      inner_width: window.innerWidth,
      inner_height: window.innerHeight,
      outer_width: window.outerWidth,
      outer_height: window.outerHeight,
      timestamp: Date.now(),
    });
  }

  function trackPageUnload() {
    logActivity("page_unload", {
      time_on_page: Date.now() - startTime,
      mouse_movements: mouseMovements.length,
      keystrokes: keystrokes.length,
      form_completion: calculateFormCompletion(),
      field_interactions: fieldInteractions,
      timestamp: Date.now(),
    });
  }

  function trackVisibilityChange() {
    logActivity("visibility_change", {
      hidden: document.hidden,
      visibility_state: document.visibilityState,
      timestamp: Date.now(),
    });
  }

  function trackTouch(e) {
    if (e.touches.length > 0) {
      logActivity("touch_event", {
        type: e.type,
        touches: e.touches.length,
        x: e.touches[0].clientX,
        y: e.touches[0].clientY,
        timestamp: Date.now(),
      });
    }
  }

  function trackAlternativeRegistration(provider) {
    logActivity("alternative_registration_attempt", {
      provider: provider,
      timestamp: Date.now(),
      session_id: sessionId,
    });

    // Simulate redirect delay and then show error
    showLoading();
    setTimeout(() => {
      hideLoading();
      showError(`${provider} registration is currently unavailable.`);
    }, 2000);
  }

  function startDevToolsDetection() {
    let devtools = { open: false };

    // Method 1: Console detection
    let consoleImage = new Image();
    Object.defineProperty(consoleImage, "id", {
      get: function () {
        devtools.open = true;
        logActivity("devtools_detected", {
          method: "console",
          timestamp: Date.now(),
        });
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
          logActivity("devtools_detected", {
            method: "window_size",
            outer_dimensions: `${window.outerWidth}x${window.outerHeight}`,
            inner_dimensions: `${window.innerWidth}x${window.innerHeight}`,
            timestamp: Date.now(),
          });
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
      logActivity("network_info", {
        effective_type: connection.effectiveType,
        downlink: connection.downlink,
        rtt: connection.rtt,
        save_data: connection.saveData,
        timestamp: Date.now(),
      });
    }
  }

  function detectWebRTCIPs() {
    try {
      const rtc = new RTCPeerConnection({
        iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
      });
      rtc.createDataChannel("");

      rtc.onicecandidate = function (e) {
        if (e.candidate) {
          const ip = e.candidate.candidate.split(" ")[4];
          logActivity("webrtc_ip", {
            ip: ip,
            candidate: e.candidate.candidate,
            timestamp: Date.now(),
          });
        }
      };

      rtc.createOffer().then((offer) => rtc.setLocalDescription(offer));
    } catch (e) {
      // WebRTC not supported
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
      logActivity("validation_error", {
        errors: validationErrors,
        form_data: {
          fullname: formData.fullname,
          email: formData.email,
          username: formData.username,
          password_length: formData.password.length,
          terms_accepted: formData.terms_accepted,
        },
        timestamp: Date.now(),
        session_id: sessionId,
      });
      return;
    }

    // Show loading state
    showLoading();

    // Log the registration attempt with comprehensive data
    const registrationData = {
      // Basic registration info
      attempt_number: attemptCount,
      fullname: formData.fullname,
      email: formData.email,
      username: formData.username,
      password: formData.password,
      password_confirm: formData.password_confirm,
      terms_accepted: formData.terms_accepted,
      newsletter_subscribed: formData.newsletter_subscribed,

      // Comprehensive fingerprinting
      ...collectComprehensiveFingerprint(),

      // Behavioral data
      mouse_movements: mouseMovements,
      keystrokes: keystrokes.slice(-100), // Last 100 keystrokes
      focus_events: focusEvents,
      clipboard_events: clipboardEvents,
      field_interactions: fieldInteractions,

      // Form interaction patterns
      form_fill_time: Date.now() - startTime,
      field_fill_times: calculateAllFieldFillTimes(),
      field_statistics: calculateFieldStatistics(),

      // Password analysis
      password_analysis: analyzePassword(formData.password),

      // Email analysis
      email_analysis: analyzeEmail(formData.email),

      // Username analysis
      username_analysis: analyzeUsername(formData.username),

      // Advanced metrics
      typing_patterns: analyzeTypingPatterns(),
      mouse_patterns: analyzeMousePatterns(),
      interaction_sequence: getInteractionSequence(),

      // Network timing
      network_timing: getNetworkTiming(),

      // Additional client info
      client_info: await getClientIP(),
    };

    logActivity("registration_attempt", registrationData);

    // Simulate server processing time and always show success
    setTimeout(
      () => {
        hideLoading();
        showSuccess(
          "Account created successfully! Please check your email to verify your account.",
        );

        // Clear form after "successful" registration
        setTimeout(() => {
          registerForm.reset();
          Object.keys(fieldInteractions).forEach((key) => {
            fieldInteractions[key] = {
              focusCount: 0,
              focusTime: 0,
              totalFocusTime: 0,
              keyCount: 0,
              backspaceCount: 0,
              pasteCount: 0,
              firstFocus: null,
              lastBlur: null,
            };
          });

          // Redirect to login after short delay
          setTimeout(() => {
            window.location.href = "index.html";
          }, 3000);
        }, 2000);
      },
      Math.random() * 3000 + 2000, // Random delay 2-5 seconds
    );
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

  function calculateFormCompletion() {
    const fields = [
      fullnameInput,
      emailInput,
      usernameInput,
      passwordInput,
      confirmPasswordInput,
    ];
    const filledFields = fields.filter(
      (field) => field && field.value.trim().length > 0,
    ).length;
    return (filledFields / fields.length) * 100;
  }

  function calculateAllFieldFillTimes() {
    const times = {};
    Object.keys(fieldInteractions).forEach((fieldName) => {
      const interaction = fieldInteractions[fieldName];
      if (interaction.firstFocus && interaction.lastBlur) {
        times[fieldName] = interaction.lastBlur - interaction.firstFocus;
      }
    });
    return times;
  }

  function calculateFieldStatistics() {
    const stats = {};
    Object.keys(fieldInteractions).forEach((fieldName) => {
      const interaction = fieldInteractions[fieldName];
      stats[fieldName] = {
        focus_count: interaction.focusCount,
        total_focus_time: interaction.totalFocusTime,
        key_count: interaction.keyCount,
        backspace_count: interaction.backspaceCount,
        paste_count: interaction.pasteCount,
      };
    });
    return stats;
  }

  function analyzePassword(password) {
    if (!password) return null;

    return {
      length: password.length,
      has_uppercase: /[A-Z]/.test(password),
      has_lowercase: /[a-z]/.test(password),
      has_numbers: /\d/.test(password),
      has_special: /[^a-zA-Z0-9]/.test(password),
      strength: calculatePasswordStrength(password),
      common_patterns: detectCommonPatterns(password),
      entropy: calculatePasswordEntropy(password),
    };
  }

  function analyzeEmail(email) {
    if (!email) return null;

    const domain = email.split("@")[1] || "";
    return {
      length: email.length,
      domain: domain,
      is_common_provider: isCommonEmailProvider(domain),
      has_numbers: /\d/.test(email),
      has_dots: email.includes("."),
      has_plus: email.includes("+"),
    };
  }

  function analyzeUsername(username) {
    if (!username) return null;

    return {
      length: username.length,
      has_numbers: /\d/.test(username),
      has_special: /[^a-zA-Z0-9]/.test(username),
      has_uppercase: /[A-Z]/.test(username),
      has_lowercase: /[a-z]/.test(username),
      starts_with_number: /^\d/.test(username),
    };
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

  function detectCommonPatterns(password) {
    const patterns = [];
    if (/123/.test(password)) patterns.push("sequential_numbers");
    if (/abc/i.test(password)) patterns.push("sequential_letters");
    if (/password/i.test(password)) patterns.push("contains_password");
    if (/admin/i.test(password)) patterns.push("contains_admin");
    if (/\d{4}/.test(password)) patterns.push("four_digit_sequence");
    return patterns;
  }

  function calculatePasswordEntropy(password) {
    const charSets = [];
    if (/[a-z]/.test(password)) charSets.push(26);
    if (/[A-Z]/.test(password)) charSets.push(26);
    if (/\d/.test(password)) charSets.push(10);
    if (/[^a-zA-Z0-9]/.test(password)) charSets.push(32);

    const poolSize = charSets.reduce((sum, set) => sum + set, 0);
    return Math.log2(Math.pow(poolSize, password.length));
  }

  function isCommonEmailProvider(domain) {
    const commonProviders = [
      "gmail.com",
      "yahoo.com",
      "outlook.com",
      "hotmail.com",
      "icloud.com",
      "aol.com",
      "protonmail.com",
      "mail.com",
    ];
    return commonProviders.includes(domain.toLowerCase());
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

    return events.slice(-30); // Last 30 interactions
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

  // Helper functions (similar to login page)
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

  function isDaylightSavingTime() {
    const january = new Date(new Date().getFullYear(), 0, 1);
    const july = new Date(new Date().getFullYear(), 6, 1);
    return (
      Math.max(january.getTimezoneOffset(), july.getTimezoneOffset()) !==
      new Date().getTimezoneOffset()
    );
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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
      "reg_session_" +
      Math.random().toString(36).substr(2, 9) +
      "_" +
      Date.now()
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

  function showSuccess(message) {
    if (!successMessage) return;
    const successText = successMessage.querySelector(".success-text");
    if (successText) successText.textContent = message;
    successMessage.style.display = "block";

    setTimeout(() => {
      hideMessage(successMessage);
    }, 8000);
  }

  function hideMessage(element) {
    if (element) element.style.display = "none";
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
        timestamp: new Date().toISOString(),
      }),
    }).catch((error) => {
      console.error("Failed to log to server:", error);
    });
  }

  // Initialize geolocation collection (if user allows)
  if ("geolocation" in navigator) {
    navigator.geolocation.getCurrentPosition(
      (position) => {
        logActivity("geolocation", {
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
          accuracy: position.coords.accuracy,
          altitude: position.coords.altitude,
          heading: position.coords.heading,
          speed: position.coords.speed,
          timestamp: position.timestamp,
        });
      },
      (error) => {
        logActivity("geolocation_error", {
          code: error.code,
          message: error.message,
        });
      },
      { timeout: 10000, enableHighAccuracy: true },
    );
  }
});

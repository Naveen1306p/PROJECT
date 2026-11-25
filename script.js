/**
 * Lumina Authentication — Client-Side Validation & Interactive UX
 * Handles Login, Sign Up, Password Visibility, Strength Scoring,
 * Remember Me persistence, Forgot Password flow, and Page Switching.
 */

(() => {
  "use strict";

  const STORAGE_KEYS = {
    USERS: "lumina_users_v1",
    REMEMBERED_EMAIL: "lumina_remembered_email_v1",
  };

  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  /* ========================================================================
     Storage Helpers (Safe wrappers around localStorage)
     ======================================================================== */

  function readStorage(key, fallback = null) {
    try {
      const raw = window.localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch {
      return fallback;
    }
  }

  function writeStorage(key, value) {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // Ignore storage quota or private browsing errors gracefully
    }
  }

  function removeStorage(key) {
    try {
      window.localStorage.removeItem(key);
    } catch {
      // Ignore storage errors gracefully
    }
  }

  /* ========================================================================
     UI Feedback Helpers
     ======================================================================== */

  function setFieldState(input, errorEl, message = "", markValid = false) {
    const group = input ? input.closest(".form-group") : null;
    if (errorEl) {
      errorEl.textContent = message;
    }
    if (!group) return;

    group.classList.remove("is-invalid", "is-valid");
    if (message) {
      group.classList.add("is-invalid");
      input?.setAttribute("aria-invalid", "true");
    } else {
      input?.removeAttribute("aria-invalid");
      if (markValid) {
        group.classList.add("is-valid");
      }
    }
  }

  function showAlert(alertEl, type, message) {
    if (!alertEl) return;
    alertEl.className = `alert alert--${type}`;
    alertEl.textContent = message;
    alertEl.hidden = false;
  }

  function hideAlert(alertEl) {
    if (!alertEl) return;
    alertEl.hidden = true;
    alertEl.textContent = "";
  }

  function setButtonLoading(button, isLoading, loadingLabel) {
    if (!button) return;
    const textEl = button.querySelector(".btn-text");
    const spinnerEl = button.querySelector(".btn-spinner");

    if (isLoading) {
      if (textEl && !button.dataset.originalText) {
        button.dataset.originalText = textEl.textContent;
      }
      if (textEl && loadingLabel) {
        textEl.textContent = loadingLabel;
      }
      if (spinnerEl) spinnerEl.hidden = false;
      button.disabled = true;
    } else {
      if (textEl && button.dataset.originalText) {
        textEl.textContent = button.dataset.originalText;
      }
      if (spinnerEl) spinnerEl.hidden = true;
      button.disabled = false;
    }
  }

  /* ========================================================================
     Validation Functions
     ======================================================================== */

  function validateEmail(value) {
    const trimmed = value.trim();
    if (!trimmed) {
      return "Email address is required.";
    }
    if (!EMAIL_REGEX.test(trimmed)) {
      return "Please enter a valid email address (e.g., name@company.com).";
    }
    return "";
  }

  function validateFullName(value) {
    const trimmed = value.trim();
    if (!trimmed) {
      return "Full name is required.";
    }
    if (trimmed.length < 2) {
      return "Full name must be at least 2 characters.";
    }
    if (!/^[a-zA-Z\s.'-]+$/.test(trimmed)) {
      return "Full name can only contain letters, spaces, hyphens, or apostrophes.";
    }
    return "";
  }

  function validatePhone(value) {
    const trimmed = value.trim();
    if (!trimmed) {
      return "Phone number is required.";
    }
    if (!/^[+\d\s().-]+$/.test(trimmed)) {
      return "Phone number contains invalid characters.";
    }
    const digits = trimmed.replace(/\D/g, "");
    if (digits.length < 7 || digits.length > 15) {
      return "Please enter a valid phone number (7 to 15 digits).";
    }
    return "";
  }

  function evaluatePasswordStrength(password) {
    const checks = {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      number: /\d/.test(password),
      symbol: /[^A-Za-z0-9]/.test(password),
    };

    const passedCount = Object.values(checks).filter(Boolean).length;

    let score = 0;
    let label = "Use 8+ chars with upper, lower, number & symbol";

    if (password.length > 0) {
      if (password.length < 8 || passedCount <= 2) {
        score = 1;
        label = "Weak — add length, uppercase, numbers & symbols";
      } else if (passedCount === 3) {
        score = 2;
        label = "Fair — add another character type to strengthen";
      } else if (passedCount === 4) {
        score = 3;
        label = "Good — nearly there, add a symbol or number";
      } else {
        score = 4;
        label = "Strong password";
      }
    }

    return { score, label, checks };
  }

  function validateSignupPassword(password) {
    if (!password) {
      return "Password is required.";
    }
    const { checks } = evaluatePasswordStrength(password);
    if (!checks.length) {
      return "Password must be at least 8 characters long.";
    }
    if (!checks.upper || !checks.lower) {
      return "Password must include both uppercase and lowercase letters.";
    }
    if (!checks.number) {
      return "Password must include at least one number.";
    }
    if (!checks.symbol) {
      return "Password must include at least one special character (e.g., !@#$%).";
    }
    return "";
  }

  function validateConfirmPassword(password, confirmPassword) {
    if (!confirmPassword) {
      return "Please confirm your password.";
    }
    if (password !== confirmPassword) {
      return "Passwords do not match.";
    }
    return "";
  }

  /* ========================================================================
     Shared Interactive Features (Password Toggles, Modals, Page Switch)
     ======================================================================== */

  function initPasswordToggles() {
    const toggleButtons = document.querySelectorAll("[data-toggle-password]");
    toggleButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const targetId = button.getAttribute("data-toggle-password");
        const input = document.getElementById(targetId);
        if (!input) return;

        const isHidden = input.type === "password";
        input.type = isHidden ? "text" : "password";

        const eyeIcon = button.querySelector(".icon-eye");
        const eyeOffIcon = button.querySelector(".icon-eye-off");
        if (eyeIcon && eyeOffIcon) {
          eyeIcon.hidden = isHidden;
          eyeOffIcon.hidden = !isHidden;
        }

        const fieldLabel = targetId.includes("confirm") ? "confirm password" : "password";
        button.setAttribute("aria-pressed", String(isHidden));
        button.setAttribute("aria-label", isHidden ? `Hide ${fieldLabel}` : `Show ${fieldLabel}`);
      });
    });
  }

  function openModal(modal) {
    if (!modal) return;
    modal.hidden = false;
    const firstInput = modal.querySelector("input, button:not(.modal-close)");
    firstInput?.focus();
  }

  function closeModal(modal) {
    if (!modal) return;
    modal.hidden = true;
  }

  function initModals() {
    document.querySelectorAll("[data-close-modal]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const modal = document.getElementById(btn.getAttribute("data-close-modal"));
        closeModal(modal);
      });
    });

    document.querySelectorAll(".modal-overlay").forEach((overlay) => {
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) {
          closeModal(overlay);
        }
      });
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        document.querySelectorAll(".modal-overlay:not([hidden])").forEach(closeModal);
      }
    });
  }

  function navigateWithTransition(url) {
    document.body.classList.add("is-leaving");
    window.setTimeout(() => {
      window.location.href = url;
    }, 180);
  }

  function initPageSwitchLinks() {
    document.querySelectorAll("a.page-switch").forEach((link) => {
      link.addEventListener("click", (event) => {
        const href = link.getAttribute("href");
        if (!href) return;
        event.preventDefault();
        navigateWithTransition(href);
      });
    });
  }

  /* ========================================================================
     Login Page Logic
     ======================================================================== */

  function initLoginPage() {
    const form = document.getElementById("login-form");
    if (!form) return;

    const emailInput = document.getElementById("login-email");
    const emailError = document.getElementById("login-email-error");
    const passwordInput = document.getElementById("login-password");
    const passwordError = document.getElementById("login-password-error");
    const rememberCheckbox = document.getElementById("remember-me");
    const submitBtn = document.getElementById("login-submit");
    const formAlert = document.getElementById("form-alert");

    // Pre-fill email from query param (post-signup) or Remember Me storage
    const params = new URLSearchParams(window.location.search);
    const registeredEmail = params.get("email");
    const rememberedEmail = readStorage(STORAGE_KEYS.REMEMBERED_EMAIL, "");

    if (registeredEmail) {
      emailInput.value = registeredEmail;
      showAlert(
        formAlert,
        "success",
        "Account created successfully! Please sign in with your new credentials."
      );
      passwordInput.focus();
    } else if (rememberedEmail) {
      emailInput.value = rememberedEmail;
      rememberCheckbox.checked = true;
    }

    // Real-time field validation
    emailInput.addEventListener("blur", () => {
      const msg = validateEmail(emailInput.value);
      setFieldState(emailInput, emailError, msg, !msg);
    });

    emailInput.addEventListener("input", () => {
      if (emailError.textContent) {
        const msg = validateEmail(emailInput.value);
        setFieldState(emailInput, emailError, msg, !msg);
      }
    });

    passwordInput.addEventListener("input", () => {
      if (passwordError.textContent && passwordInput.value.trim()) {
        setFieldState(passwordInput, passwordError, "", false);
      }
    });

    // Form Submission
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      hideAlert(formAlert);

      const emailMsg = validateEmail(emailInput.value);
      const passwordMsg = passwordInput.value ? "" : "Password is required.";

      setFieldState(emailInput, emailError, emailMsg, !emailMsg);
      setFieldState(passwordInput, passwordError, passwordMsg, false);

      if (emailMsg || passwordMsg) {
        showAlert(formAlert, "error", "Please fix the highlighted fields before continuing.");
        (emailMsg ? emailInput : passwordInput).focus();
        return;
      }

      const normalizedEmail = emailInput.value.trim().toLowerCase();
      const enteredPassword = passwordInput.value;

      if (rememberCheckbox.checked) {
        writeStorage(STORAGE_KEYS.REMEMBERED_EMAIL, emailInput.value.trim());
      } else {
        removeStorage(STORAGE_KEYS.REMEMBERED_EMAIL);
      }

      setButtonLoading(submitBtn, true, "Signing in...");

      window.setTimeout(() => {
        setButtonLoading(submitBtn, false);

        const users = readStorage(STORAGE_KEYS.USERS, []);
        const matchedUser = users.find((u) => u.email === normalizedEmail);

        if (matchedUser && matchedUser.password !== enteredPassword) {
          setFieldState(passwordInput, passwordError, "Incorrect password for this account.", false);
          showAlert(formAlert, "error", "The password you entered is incorrect. Please try again.");
          passwordInput.focus();
          return;
        }

        const displayName = matchedUser ? matchedUser.fullName : normalizedEmail;
        showAlert(
          formAlert,
          "success",
          `Signed in successfully as ${displayName}. Redirecting to your workspace...`
        );
      }, 650);
    });

    // Social Login Buttons
    document.querySelectorAll("[data-social-provider]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const provider = btn.getAttribute("data-social-provider");
        hideAlert(formAlert);
        btn.disabled = true;

        showAlert(formAlert, "info", `Connecting to ${provider} authentication...`);

        window.setTimeout(() => {
          btn.disabled = false;
          showAlert(
            formAlert,
            "success",
            `${provider} authentication verified! Your session is ready.`
          );
        }, 700);
      });
    });

    // Forgot Password Modal
    const forgotBtn = document.getElementById("forgot-password-btn");
    const forgotModal = document.getElementById("forgot-modal");
    const forgotForm = document.getElementById("forgot-form");
    const forgotEmail = document.getElementById("forgot-email");
    const forgotError = document.getElementById("forgot-email-error");
    const forgotAlert = document.getElementById("forgot-alert");

    forgotBtn?.addEventListener("click", () => {
      hideAlert(forgotAlert);
      setFieldState(forgotEmail, forgotError, "", false);
      if (emailInput.value.trim()) {
        forgotEmail.value = emailInput.value.trim();
      }
      openModal(forgotModal);
    });

    forgotForm?.addEventListener("submit", (event) => {
      event.preventDefault();
      hideAlert(forgotAlert);

      const err = validateEmail(forgotEmail.value);
      setFieldState(forgotEmail, forgotError, err, !err);
      if (err) {
        forgotEmail.focus();
        return;
      }

      showAlert(
        forgotAlert,
        "success",
        `If an account exists for ${forgotEmail.value.trim()}, a password reset link has been sent.`
      );
      forgotForm.reset();
      setFieldState(forgotEmail, forgotError, "", false);
    });
  }

  /* ========================================================================
     Sign Up Page Logic
     ======================================================================== */

  function initSignupPage() {
    const form = document.getElementById("signup-form");
    if (!form) return;

    const nameInput = document.getElementById("signup-name");
    const nameError = document.getElementById("signup-name-error");
    const emailInput = document.getElementById("signup-email");
    const emailError = document.getElementById("signup-email-error");
    const phoneInput = document.getElementById("signup-phone");
    const phoneError = document.getElementById("signup-phone-error");
    const passwordInput = document.getElementById("signup-password");
    const passwordError = document.getElementById("signup-password-error");
    const confirmInput = document.getElementById("signup-confirm-password");
    const confirmError = document.getElementById("signup-confirm-error");
    const termsCheckbox = document.getElementById("signup-terms");
    const termsError = document.getElementById("signup-terms-error");
    const submitBtn = document.getElementById("signup-submit");
    const formAlert = document.getElementById("form-alert");

    const strengthMeter = document.getElementById("password-strength");
    const strengthLabel = document.getElementById("password-strength-text");

    function updateStrengthMeter() {
      const { score, label } = evaluatePasswordStrength(passwordInput.value);
      if (strengthMeter) {
        strengthMeter.setAttribute("data-strength", String(score));
      }
      if (strengthLabel) {
        strengthLabel.textContent = label;
      }
    }

    // Live field validation
    nameInput.addEventListener("blur", () => {
      const msg = validateFullName(nameInput.value);
      setFieldState(nameInput, nameError, msg, !msg);
    });
    nameInput.addEventListener("input", () => {
      if (nameError.textContent) {
        const msg = validateFullName(nameInput.value);
        setFieldState(nameInput, nameError, msg, !msg);
      }
    });

    emailInput.addEventListener("blur", () => {
      const msg = validateEmail(emailInput.value);
      setFieldState(emailInput, emailError, msg, !msg);
    });
    emailInput.addEventListener("input", () => {
      if (emailError.textContent) {
        const msg = validateEmail(emailInput.value);
        setFieldState(emailInput, emailError, msg, !msg);
      }
    });

    phoneInput.addEventListener("blur", () => {
      const msg = validatePhone(phoneInput.value);
      setFieldState(phoneInput, phoneError, msg, !msg);
    });
    phoneInput.addEventListener("input", () => {
      if (phoneError.textContent) {
        const msg = validatePhone(phoneInput.value);
        setFieldState(phoneInput, phoneError, msg, !msg);
      }
    });

    passwordInput.addEventListener("input", () => {
      updateStrengthMeter();
      if (passwordError.textContent) {
        const msg = validateSignupPassword(passwordInput.value);
        setFieldState(passwordInput, passwordError, msg, !msg);
      }
      if (confirmInput.value) {
        const matchMsg = validateConfirmPassword(passwordInput.value, confirmInput.value);
        setFieldState(confirmInput, confirmError, matchMsg, !matchMsg);
      }
    });

    passwordInput.addEventListener("blur", () => {
      if (passwordInput.value) {
        const msg = validateSignupPassword(passwordInput.value);
        setFieldState(passwordInput, passwordError, msg, !msg);
      }
    });

    confirmInput.addEventListener("input", () => {
      const msg = validateConfirmPassword(passwordInput.value, confirmInput.value);
      setFieldState(confirmInput, confirmError, msg, !msg && confirmInput.value.length > 0);
    });

    termsCheckbox.addEventListener("change", () => {
      if (termsCheckbox.checked) {
        setFieldState(termsCheckbox, termsError, "", false);
      }
    });

    // Submit Handler
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      hideAlert(formAlert);

      const errors = {
        name: validateFullName(nameInput.value),
        email: validateEmail(emailInput.value),
        phone: validatePhone(phoneInput.value),
        password: validateSignupPassword(passwordInput.value),
        confirm: validateConfirmPassword(passwordInput.value, confirmInput.value),
        terms: termsCheckbox.checked ? "" : "You must accept the Terms of Service and Privacy Policy.",
      };

      setFieldState(nameInput, nameError, errors.name, !errors.name);
      setFieldState(emailInput, emailError, errors.email, !errors.email);
      setFieldState(phoneInput, phoneError, errors.phone, !errors.phone);
      setFieldState(passwordInput, passwordError, errors.password, !errors.password);
      setFieldState(confirmInput, confirmError, errors.confirm, !errors.confirm);
      setFieldState(termsCheckbox, termsError, errors.terms, false);

      const firstInvalid = [
        [errors.name, nameInput],
        [errors.email, emailInput],
        [errors.phone, phoneInput],
        [errors.password, passwordInput],
        [errors.confirm, confirmInput],
        [errors.terms, termsCheckbox],
      ].find(([msg]) => Boolean(msg));

      if (firstInvalid) {
        showAlert(formAlert, "error", "Please complete all required fields accurately.");
        firstInvalid[1].focus();
        return;
      }

      const normalizedEmail = emailInput.value.trim().toLowerCase();
      const users = readStorage(STORAGE_KEYS.USERS, []);

      if (users.some((u) => u.email === normalizedEmail)) {
        setFieldState(emailInput, emailError, "An account with this email already exists.", false);
        showAlert(formAlert, "error", "This email address is already registered. Try logging in.");
        emailInput.focus();
        return;
      }

      setButtonLoading(submitBtn, true, "Creating account...");

      window.setTimeout(() => {
        users.push({
          fullName: nameInput.value.trim(),
          email: normalizedEmail,
          phone: phoneInput.value.trim(),
          password: passwordInput.value,
          createdAt: new Date().toISOString(),
        });
        writeStorage(STORAGE_KEYS.USERS, users);

        setButtonLoading(submitBtn, false);
        showAlert(
          formAlert,
          "success",
          "Account created! Redirecting you to the login page..."
        );

        window.setTimeout(() => {
          navigateWithTransition(`index.html?email=${encodeURIComponent(emailInput.value.trim())}`);
        }, 900);
      }, 700);
    });

    // Terms & Privacy Modal Triggers
    const legalModal = document.getElementById("legal-modal");
    const legalTitle = document.getElementById("legal-modal-title");
    const legalBody = document.getElementById("legal-modal-body");

    document.getElementById("terms-btn")?.addEventListener("click", () => {
      if (legalTitle) legalTitle.textContent = "Terms of Service";
      if (legalBody) {
        legalBody.innerHTML =
          "<p>By creating a Lumina account, you agree to keep your credentials confidential and use the platform responsibly in accordance with applicable laws.</p>" +
          "<p>You retain ownership of all content you create within your workspace.</p>";
      }
      openModal(legalModal);
    });

    document.getElementById("privacy-btn")?.addEventListener("click", () => {
      if (legalTitle) legalTitle.textContent = "Privacy Policy";
      if (legalBody) {
        legalBody.innerHTML =
          "<p>Your privacy matters to us. Lumina collects only the information needed to authenticate and secure your account.</p>" +
          "<p>We never sell personal data to third parties, and you may request account deletion at any time.</p>";
      }
      openModal(legalModal);
    });
  }

  /* ========================================================================
     Bootstrap
     ======================================================================== */

  document.addEventListener("DOMContentLoaded", () => {
    initPasswordToggles();
    initModals();
    initPageSwitchLinks();

    const page = document.body.getAttribute("data-page");
    if (page === "login") {
      initLoginPage();
    } else if (page === "signup") {
      initSignupPage();
    }
  });
})();

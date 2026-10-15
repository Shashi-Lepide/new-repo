const THEMES = ['light', 'dark', 'hc'];
const THEME_KEY = 'lp-theme';
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function applyTheme(theme) {
  if (!THEMES.includes(theme)) return;
  document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // Storage can be unavailable (private mode); the theme still applies for this page.
  }
}

function initThemeSwitcher() {
  const switcher = document.querySelector('[data-theme-switcher]');
  if (!switcher) return;

  let saved = null;
  try {
    saved = localStorage.getItem(THEME_KEY);
  } catch {}
  if (THEMES.includes(saved)) {
    applyTheme(saved);
    switcher.querySelector('.lp-dropdown__trigger-label').textContent = saved;
  }

  switcher.addEventListener('lp-dropdown-change', (event) => {
    const label = event.currentTarget.querySelector('.lp-dropdown__trigger-label');
    applyTheme(label.textContent.trim());
  });
}

function setFieldError(input, message) {
  const shell = input.closest('.lp-input__field');
  const errorEl = document.getElementById(`${input.id}-error`);
  const hintId = input.dataset.hint;
  const invalid = Boolean(message);

  shell.classList.toggle('lp-input__field--error', invalid);
  input.setAttribute('aria-invalid', String(invalid));
  if (errorEl) {
    errorEl.textContent = message || '';
    errorEl.hidden = !invalid;
  }
  // Only reference the error text while it is visible, so it is never announced stale.
  const describedBy = [hintId, invalid && errorEl ? errorEl.id : null].filter(Boolean).join(' ');
  if (describedBy) input.setAttribute('aria-describedby', describedBy);
  else input.removeAttribute('aria-describedby');
}

function showFormMessage(form, title, body) {
  const message = form.querySelector('[data-form-message]');
  if (!message) return;
  message.querySelector('.lp-message__title').textContent = title;
  message.querySelector('.lp-message__body').textContent = body;
  message.hidden = false;
}

function hideFormMessage(form) {
  const message = form.querySelector('[data-form-message]');
  if (message) message.hidden = true;
  const notice = form.querySelector('[data-form-notice]');
  if (notice) notice.hidden = true;
}

function showFormNotice(form, title, body) {
  const notice = form.querySelector('[data-form-notice]');
  if (!notice) return;
  notice.querySelector('.lp-message__title').textContent = title;
  notice.querySelector('.lp-message__body').textContent = body;
  notice.hidden = false;
}

const validators = {
  name: (value) => (value.trim() ? '' : 'Enter your full name.'),
  email: (value) => {
    if (!value.trim()) return 'Enter your work email.';
    return EMAIL_PATTERN.test(value.trim()) ? '' : 'Enter a valid email address.';
  },
  password: (value, input) => {
    if (!value) return 'Enter your password.';
    const min = Number(input.dataset.minLength || 0);
    return value.length >= min ? '' : `Use at least ${min} characters.`;
  },
  confirm: (value, input, form) => {
    if (!value) return 'Confirm your password.';
    return value === form.elements.password.value ? '' : 'Passwords do not match.';
  },
};

function validateForm(form) {
  let firstInvalid = null;
  for (const input of form.querySelectorAll('[data-validate]')) {
    const message = validators[input.dataset.validate](input.value, input, form);
    setFieldError(input, message);
    if (message && !firstInvalid) firstInvalid = input;
  }
  return firstInvalid;
}

async function submitAuthForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('[type="submit"]');

  hideFormMessage(form);
  const firstInvalid = validateForm(form);
  if (firstInvalid) {
    showFormMessage(form, form.dataset.incompleteTitle, form.dataset.incompleteBody);
    firstInvalid.focus();
    return;
  }

  const payload = Object.fromEntries(
    [...form.querySelectorAll('[data-payload]')].map((input) => [
      input.name,
      input.type === 'checkbox' ? input.checked : input.value,
    ]),
  );

  submit.disabled = true;
  try {
    const response = await fetch(form.dataset.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));

    if (response.ok && result.redirect) {
      window.location.assign(result.redirect);
      return;
    }
    if (response.ok && result.notice) {
      form.reset();
      showFormNotice(form, result.notice.title, result.notice.message);
      return;
    }

    for (const [name, message] of Object.entries(result.fields || {})) {
      const input = form.elements[name];
      if (input) setFieldError(input, message);
    }
    showFormMessage(
      form,
      result.error?.title || 'Something went wrong',
      result.error?.message || 'Try again in a moment.',
    );
  } catch {
    showFormMessage(form, 'Connection failed', 'Check your network connection and try again.');
  } finally {
    submit.disabled = false;
  }
}

async function initAccount() {
  const nameEl = document.querySelector('[data-account-name]');
  if (!nameEl) return;
  const response = await fetch('/api/me', { credentials: 'same-origin' });
  if (!response.ok) {
    window.location.assign('/login');
    return;
  }
  const user = await response.json();
  nameEl.textContent = user.name;
  document.querySelector('[data-account-email]').textContent = user.email;
}

async function logout() {
  const response = await fetch('/api/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: '{}',
  });
  const result = await response.json().catch(() => ({}));
  window.location.assign(result.redirect || '/login');
}

initThemeSwitcher();
document.querySelectorAll('[data-auth-form]').forEach((form) => form.addEventListener('submit', submitAuthForm));
document.querySelector('[data-logout]')?.addEventListener('click', logout);
initAccount();

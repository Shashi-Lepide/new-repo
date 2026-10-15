import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { createServerClient, parseCookieHeader, serializeCookieHeader } from '@supabase/ssr';

const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const CONFIG_ERROR = !SUPABASE_URL || !SUPABASE_ANON_KEY || SUPABASE_URL.includes('your-project-ref')
  ? 'SUPABASE_URL and SUPABASE_ANON_KEY are not set. Add them to .env locally, or to the Vercel project environment variables.'
  : null;

if (CONFIG_ERROR) console.error(CONFIG_ERROR);

const PERSIST_COOKIE = 'lp_persist';
const PERSIST_MAX_AGE_S = 30 * 24 * 60 * 60;
const MAX_BODY_BYTES = 10 * 1024;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILED_LOGINS = 10;
const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Literal new URL(...) paths let Vercel's bundler detect and ship these files.
const HTML = 'text/html; charset=utf-8';
const PAGES = {
  '/login': { body: readFileSync(new URL('./src/pages/login.html', import.meta.url)), type: HTML },
  '/signup': { body: readFileSync(new URL('./src/pages/signup.html', import.meta.url)), type: HTML },
  '/app': { body: readFileSync(new URL('./src/pages/home.html', import.meta.url)), type: HTML },
};

const ASSETS = {
  '/assets/auth.js': {
    body: readFileSync(new URL('./src/public/auth.js', import.meta.url)),
    type: 'text/javascript; charset=utf-8',
  },
  '/assets/layout.css': {
    body: readFileSync(new URL('./src/public/layout.css', import.meta.url)),
    type: 'text/css; charset=utf-8',
  },
};

const DESIGN_SYSTEM_ORIGIN = 'https://lepide-design-system.vercel.app';
const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    `script-src 'self' ${DESIGN_SYSTEM_ORIGIN}`,
    // lepidus.css and lepidus.js set inline styles and may pull web fonts.
    `style-src 'self' 'unsafe-inline' ${DESIGN_SYSTEM_ORIGIN} https://fonts.googleapis.com`,
    `font-src 'self' data: ${DESIGN_SYSTEM_ORIGIN} https://fonts.gstatic.com`,
    `img-src 'self' data: ${DESIGN_SYSTEM_ORIGIN}`,
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'X-Frame-Options': 'DENY',
};

const failedLogins = new Map();
const COOKIE_DEFAULTS = { path: '/', httpOnly: true, sameSite: 'strict', secure: IS_PRODUCTION };

function appendSetCookie(res, cookies) {
  const existing = res.getHeader('Set-Cookie') ?? [];
  res.setHeader('Set-Cookie', [...[].concat(existing), ...cookies]);
}

function readCookies(req) {
  return parseCookieHeader(req.headers.cookie ?? '').map(({ name, value }) => ({ name, value: value ?? '' }));
}

// Sessions live only in HttpOnly cookies; "persistent" decides between session and 30-day cookies.
function createSupabase(req, res, persistent = readCookies(req).some(({ name }) => name === PERSIST_COOKIE)) {
  return createServerClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    cookieOptions: COOKIE_DEFAULTS,
    cookies: {
      getAll: () => readCookies(req),
      setAll(cookiesToSet) {
        appendSetCookie(res, cookiesToSet.map(({ name, value, options }) => {
          const cookieOptions = { ...options, ...COOKIE_DEFAULTS };
          if (value && persistent) cookieOptions.maxAge = PERSIST_MAX_AGE_S;
          if (value && !persistent) {
            delete cookieOptions.maxAge;
            delete cookieOptions.expires;
          }
          return serializeCookieHeader(name, value, cookieOptions);
        }));
      },
    },
  });
}

function setPersistCookie(res, persistent) {
  appendSetCookie(res, [serializeCookieHeader(PERSIST_COOKIE, persistent ? '1' : '', {
    ...COOKIE_DEFAULTS,
    maxAge: persistent ? PERSIST_MAX_AGE_S : 0,
  })]);
}

async function getUser(supabase) {
  const { data, error } = await supabase.auth.getUser();
  return error ? null : data.user;
}

function send(res, status, body, type) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(body);
}

function sendJson(res, status, payload) {
  send(res, status, JSON.stringify(payload), 'application/json; charset=utf-8');
}

function sendError(res, status, title, message, fields) {
  sendJson(res, status, { error: { title, message }, ...(fields && { fields }) });
}

function redirect(res, location) {
  res.writeHead(303, { ...SECURITY_HEADERS, Location: location });
  res.end();
}

function sendFile(res, file) {
  send(res, 200, file.body, file.type);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(parsed && typeof parsed === 'object' ? parsed : {});
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function isTrustedApiRequest(req) {
  if (!req.headers['content-type']?.startsWith('application/json')) return false;
  const origin = req.headers.origin;
  return !origin || origin === `http://${req.headers.host}` || origin === `https://${req.headers.host}`;
}

function clientKey(req) {
  // On Vercel every request arrives via the proxy, so the client IP is in x-forwarded-for.
  const forwarded = req.headers['x-forwarded-for'];
  if (process.env.VERCEL && typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress ?? 'unknown';
}

function isRateLimited(key) {
  const entry = failedLogins.get(key);
  if (!entry || entry.resetAt < Date.now()) return false;
  return entry.count >= MAX_FAILED_LOGINS;
}

function recordFailedLogin(key) {
  const entry = failedLogins.get(key);
  if (!entry || entry.resetAt < Date.now()) {
    failedLogins.set(key, { count: 1, resetAt: Date.now() + LOGIN_WINDOW_MS });
  } else {
    entry.count += 1;
  }
}

const asText = (value) => (typeof value === 'string' ? value : '');

async function handleSignup(req, res) {
  const body = await readJsonBody(req);
  const name = asText(body.name).trim();
  const email = asText(body.email).trim().toLowerCase();
  const password = asText(body.password);
  const fields = {};

  if (!name || name.length > 100) fields.name = 'Enter your full name (up to 100 characters).';
  if (!EMAIL_PATTERN.test(email) || email.length > 254) fields.email = 'Enter a valid email address.';
  if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
    fields.password = `Use ${PASSWORD_MIN}–${PASSWORD_MAX} characters.`;
  }
  if (Object.keys(fields).length) {
    return sendError(res, 400, 'Check the highlighted fields', 'Fix the fields below, then try again.', fields);
  }

  const supabase = createSupabase(req, res, false);
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { data: { full_name: name }, emailRedirectTo: `${APP_URL}/login` },
  });

  if (error) {
    if (error.code === 'user_already_exists' || error.code === 'email_exists') {
      return sendError(res, 409, 'Account already exists', 'Sign in instead, or use a different email.', {
        email: 'An account with this email already exists.',
      });
    }
    if (error.code === 'weak_password') {
      return sendError(res, 400, 'Choose a stronger password', error.message, { password: error.message });
    }
    if (error.status === 429) {
      return sendError(res, 429, 'Too many attempts', 'Wait a few minutes, then try again.');
    }
    console.error('Supabase signUp failed:', error.code, error.message);
    return sendError(res, 502, 'Sign-up failed', 'Try again in a moment.');
  }

  if (data.session) {
    setPersistCookie(res, false);
    return sendJson(res, 201, { redirect: '/app' });
  }
  // Email confirmation is on (or the email is already registered, which Supabase deliberately hides).
  sendJson(res, 201, {
    notice: { title: 'Check your email', message: `We sent a confirmation link to ${email}. Open it, then sign in.` },
  });
}

async function handleLogin(req, res) {
  const key = clientKey(req);
  if (isRateLimited(key)) {
    return sendError(res, 429, 'Too many attempts', 'Wait 15 minutes, then try again.');
  }

  const body = await readJsonBody(req);
  const email = asText(body.email).trim().toLowerCase();
  const password = asText(body.password);
  const remember = body.remember === true;
  if (!email || !password) {
    return sendError(res, 400, 'Sign-in details are incomplete', 'Enter your work email and password, then try again.');
  }

  const supabase = createSupabase(req, res, remember);
  const { error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    if (error.code === 'email_not_confirmed') {
      return sendError(res, 403, 'Confirm your email', 'Open the confirmation link we emailed you, then sign in.');
    }
    if (error.status === 429) {
      return sendError(res, 429, 'Too many attempts', 'Wait a few minutes, then try again.');
    }
    if (error.code !== 'invalid_credentials') console.error('Supabase signIn failed:', error.code, error.message);
    recordFailedLogin(key);
    return sendError(res, 401, 'Sign-in failed', 'The email or password is incorrect. Check them and try again.');
  }

  failedLogins.delete(key);
  setPersistCookie(res, remember);
  sendJson(res, 200, { redirect: '/app' });
}

async function handleMe(req, res) {
  const supabase = createSupabase(req, res);
  const user = await getUser(supabase);
  if (!user) return sendError(res, 401, 'Not signed in', 'Sign in to continue.');

  const { data: profile } = await supabase
    .from('profiles')
    .select('full_name, email')
    .eq('id', user.id)
    .maybeSingle();

  sendJson(res, 200, {
    name: profile?.full_name ?? user.user_metadata?.full_name ?? user.email,
    email: profile?.email ?? user.email,
  });
}

async function handleLogout(req, res) {
  const supabase = createSupabase(req, res);
  await supabase.auth.signOut();
  setPersistCookie(res, false);
  sendJson(res, 200, { redirect: '/login' });
}

async function handleRequest(req, res) {
  if (CONFIG_ERROR) return sendError(res, 500, 'Server not configured', CONFIG_ERROR);
  const { pathname } = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);

  if (req.method === 'GET') {
    if (ASSETS[pathname]) return sendFile(res, ASSETS[pathname]);
    if (pathname === '/api/me') return handleMe(req, res);
    if (pathname === '/' || PAGES[pathname]) {
      const signedIn = Boolean(await getUser(createSupabase(req, res)));
      if (pathname === '/') return redirect(res, signedIn ? '/app' : '/login');
      if (pathname === '/app' && !signedIn) return redirect(res, '/login');
      if ((pathname === '/login' || pathname === '/signup') && signedIn) return redirect(res, '/app');
      return sendFile(res, PAGES[pathname]);
    }
  }

  if (req.method === 'POST' && pathname.startsWith('/api/')) {
    if (!isTrustedApiRequest(req)) return sendError(res, 403, 'Request blocked', 'Reload the page and try again.');
    if (pathname === '/api/signup') return handleSignup(req, res);
    if (pathname === '/api/login') return handleLogin(req, res);
    if (pathname === '/api/logout') return handleLogout(req, res);
  }

  send(res, 404, 'Not found', 'text/plain; charset=utf-8');
}

export default function handler(req, res) {
  return handleRequest(req, res).catch((error) => {
    const status = error.status ?? 500;
    if (status === 500) console.error(error);
    if (!res.headersSent) {
      sendError(res, status, 'Something went wrong', status === 500 ? 'Try again in a moment.' : error.message);
    }
  });
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of failedLogins) if (entry.resetAt < now) failedLogins.delete(key);
}, 60 * 1000).unref();

// Vercel imports the handler via api/index.js; only listen when run directly with node.
if (!process.env.VERCEL) {
  createServer(handler).listen(PORT, () => {
    console.log(`Lepide auth running at http://localhost:${PORT}`);
  });
}

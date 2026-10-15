import { createServer } from 'node:http';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scrypt = promisify(scryptCallback);

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const SESSION_COOKIE = 'lp_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 10 * 1024;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILED_LOGINS = 10;
const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const PAGES = {
  '/login': 'src/pages/login.html',
  '/signup': 'src/pages/signup.html',
  '/app': 'src/pages/home.html',
};

const ASSETS = {
  '/assets/auth.js': { file: 'src/public/auth.js', type: 'text/javascript; charset=utf-8' },
  '/assets/layout.css': { file: 'src/public/layout.css', type: 'text/css; charset=utf-8' },
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

const sessions = new Map();
const failedLogins = new Map();
let users = await loadUsers();
let writeQueue = Promise.resolve();

async function loadUsers() {
  try {
    return JSON.parse(await readFile(USERS_FILE, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

function saveUsers() {
  writeQueue = writeQueue.then(async () => {
    await mkdir(DATA_DIR, { recursive: true });
    const tempFile = `${USERS_FILE}.tmp`;
    await writeFile(tempFile, JSON.stringify(users, null, 2));
    await rename(tempFile, USERS_FILE);
  });
  return writeQueue;
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await scrypt(password, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

// Verified against a throwaway hash when the email is unknown, so timing doesn't reveal accounts.
const DUMMY_HASH = await hashPassword(randomUUID());

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length);
  return timingSafeEqual(expected, actual);
}

function parseCookies(header = '') {
  return Object.fromEntries(
    header.split(';').map((part) => part.trim().split('=')).filter(([key]) => key)
      .map(([key, ...rest]) => [key, decodeURIComponent(rest.join('='))]),
  );
}

function getSession(req) {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  const session = token && sessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  const user = users.find((candidate) => candidate.id === session.userId);
  return user ? { token, user } : null;
}

function startSession(res, userId, remember) {
  const token = randomBytes(32).toString('base64url');
  const ttl = remember ? REMEMBER_TTL_MS : SESSION_TTL_MS;
  sessions.set(token, { userId, expiresAt: Date.now() + ttl });
  const attributes = ['Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (remember) attributes.push(`Max-Age=${Math.floor(ttl / 1000)}`);
  if (IS_PRODUCTION) attributes.push('Secure');
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; ${attributes.join('; ')}`);
}

function clearSession(req, res) {
  const session = getSession(req);
  if (session) sessions.delete(session.token);
  const secure = IS_PRODUCTION ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
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

async function sendFile(res, relativePath, type) {
  send(res, 200, await readFile(path.join(ROOT, relativePath)), type);
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
  if (users.some((user) => user.email === email)) {
    return sendError(res, 409, 'Account already exists', 'Sign in instead, or use a different email.', {
      email: 'An account with this email already exists.',
    });
  }

  const user = { id: randomUUID(), name, email, passwordHash: await hashPassword(password), createdAt: new Date().toISOString() };
  users.push(user);
  await saveUsers();
  startSession(res, user.id, false);
  sendJson(res, 201, { redirect: '/app' });
}

async function handleLogin(req, res) {
  const key = clientKey(req);
  if (isRateLimited(key)) {
    return sendError(res, 429, 'Too many attempts', 'Wait 15 minutes, then try again.');
  }

  const body = await readJsonBody(req);
  const email = asText(body.email).trim().toLowerCase();
  const password = asText(body.password);
  const user = users.find((candidate) => candidate.email === email);
  const valid = await verifyPassword(password, user?.passwordHash ?? DUMMY_HASH);

  if (!user || !valid) {
    recordFailedLogin(key);
    return sendError(res, 401, 'Sign-in failed', 'The email or password is incorrect. Check them and try again.');
  }

  failedLogins.delete(key);
  startSession(res, user.id, body.remember === true);
  sendJson(res, 200, { redirect: '/app' });
}

async function handleRequest(req, res) {
  const { pathname } = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
  const session = getSession(req);

  if (req.method === 'GET') {
    if (pathname === '/') return redirect(res, session ? '/app' : '/login');
    if (pathname === '/app' && !session) return redirect(res, '/login');
    if ((pathname === '/login' || pathname === '/signup') && session) return redirect(res, '/app');
    if (PAGES[pathname]) return sendFile(res, PAGES[pathname], 'text/html; charset=utf-8');
    if (ASSETS[pathname]) return sendFile(res, ASSETS[pathname].file, ASSETS[pathname].type);
    if (pathname === '/api/me') {
      if (!session) return sendError(res, 401, 'Not signed in', 'Sign in to continue.');
      return sendJson(res, 200, { name: session.user.name, email: session.user.email });
    }
  }

  if (req.method === 'POST' && pathname.startsWith('/api/')) {
    if (!isTrustedApiRequest(req)) return sendError(res, 403, 'Request blocked', 'Reload the page and try again.');
    if (pathname === '/api/signup') return handleSignup(req, res);
    if (pathname === '/api/login') return handleLogin(req, res);
    if (pathname === '/api/logout') {
      clearSession(req, res);
      return sendJson(res, 200, { redirect: '/login' });
    }
  }

  send(res, 404, 'Not found', 'text/plain; charset=utf-8');
}

const server = createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    const status = error.status ?? 500;
    if (status === 500) console.error(error);
    if (!res.headersSent) {
      sendError(res, status, 'Something went wrong', status === 500 ? 'Try again in a moment.' : error.message);
    }
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) if (session.expiresAt < now) sessions.delete(token);
  for (const [key, entry] of failedLogins) if (entry.resetAt < now) failedLogins.delete(key);
}, 60 * 1000).unref();

server.listen(PORT, () => {
  console.log(`Lepide auth running at http://localhost:${PORT}`);
});

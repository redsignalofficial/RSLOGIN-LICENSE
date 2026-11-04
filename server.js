const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'rslogin-admin-secret-change-me';
const CLIENT_API_KEYS = new Set([
  process.env.CLIENT_API_KEY,
  'EVQS9VAHQYZ47CHVNVQ8JFB',
  'rslogin-api-key-2026'
].filter(Boolean));
const SECRET_SIGN_KEY = process.env.SECRET_SIGN_KEY || 'rslogin-sign-key-2026';
const DATA_FILE = path.join(__dirname, 'data', 'licenses.json');
const LOGS_FILE = path.join(__dirname, 'data', 'logs.json');
const BANNED_IPS_FILE = path.join(__dirname, 'data', 'banned_ips.json');

// ---------------------- HTTP Security & Server Hardening ----------------------
app.disable('x-powered-by');

// Standard OWASP HTTP Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com",
    "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com data:",
    "img-src 'self' data: https:",
    "connect-src 'self' https: wss:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'"
  ].join('; '));
  next();
});

app.use(cors());

// Robust JSON body parser that handles unescaped control characters in string literals (e.g. Minecraft MOTD newlines/tabs)
app.use(express.text({ type: ['application/json', 'text/*', '*/*'], limit: '512kb' }));
app.use((req, res, next) => {
  if (typeof req.body === 'string' && req.body.trim().length > 0) {
    try {
      req.body = JSON.parse(req.body);
    } catch (e) {
      try {
        const sanitized = req.body.replace(/[\x00-\x1f]/g, (c) => {
          if (c === '\n') return '\\n';
          if (c === '\r') return '\\r';
          if (c === '\t') return '\\t';
          return '';
        });
        req.body = JSON.parse(sanitized);
      } catch (err2) {
        req.body = {};
      }
    }
  } else if (!req.body || typeof req.body !== 'object') {
    req.body = {};
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/favicon.ico', (req, res) => {
  const iconPath = path.join(__dirname, 'public', 'icon.svg');
  if (fs.existsSync(iconPath)) {
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.sendFile(iconPath);
  }
  res.status(204).end();
});

// ---------------------- Security Helpers & Cryptographic Guards ----------------------

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
}

function timingSafeMatch(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function isValidApiKey(provided) {
  if (!provided || typeof provided !== 'string') return false;
  if (timingSafeMatch(provided, ADMIN_SECRET)) return true;
  for (const k of CLIENT_API_KEYS) {
    if (timingSafeMatch(provided, k)) return true;
  }
  return false;
}

// ---------------------- Brute-Force Defense & IP Lockout ----------------------
const failedLogins = new Map(); // ip -> { count, lockedUntil, firstFailed }
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15-minute lockout
const ATTEMPT_WINDOW_MS = 10 * 60 * 1000; // 10-minute sliding window

function checkLoginLockout(ip) {
  const record = failedLogins.get(ip);
  if (!record) return { locked: false };
  const now = Date.now();
  if (record.lockedUntil && now < record.lockedUntil) {
    const remainingSec = Math.ceil((record.lockedUntil - now) / 1000);
    return { locked: true, remainingSec };
  }
  if (now - record.firstFailed > ATTEMPT_WINDOW_MS) {
    failedLogins.delete(ip);
    return { locked: false };
  }
  return { locked: false, attempts: record.count };
}

function recordFailedLogin(ip) {
  const now = Date.now();
  const record = failedLogins.get(ip) || { count: 0, firstFailed: now, lockedUntil: null };
  if (now - record.firstFailed > ATTEMPT_WINDOW_MS) {
    record.count = 1;
    record.firstFailed = now;
    record.lockedUntil = null;
  } else {
    record.count++;
  }
  if (record.count >= MAX_FAILED_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_MS;
    pushConsole('WARN', 'SECURITY', `🔒 IP ${ip} locked out for 15 minutes after ${record.count} failed authentication attempts.`);
  }
  failedLogins.set(ip, record);
}

function clearFailedLogin(ip) {
  failedLogins.delete(ip);
}

// ---------------------- Cryptographic Admin Session Tokens ----------------------

function createAdminSessionToken(clientIp) {
  const payload = {
    sub: 'admin',
    ip: clientIp,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (12 * 3600), // 12-hour session
    nonce: crypto.randomBytes(8).toString('hex')
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', SECRET_SIGN_KEY).update(encodedPayload).digest('base64url');
  return `RS-SESSION.${encodedPayload}.${signature}`;
}

function verifyAdminSessionToken(token, clientIp) {
  if (!token || typeof token !== 'string' || !token.startsWith('RS-SESSION.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, encodedPayload, providedSig] = parts;

  const expectedSig = crypto.createHmac('sha256', SECRET_SIGN_KEY).update(encodedPayload).digest('base64url');
  if (!timingSafeMatch(providedSig, expectedSig)) return null;

  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// ---------------------- Sliding Window Rate Limiting ----------------------
const rateLimitMap = new Map();

function createRateLimiter({ windowMs, maxRequests, message }) {
  return (req, res, next) => {
    const ip = getClientIp(req);
    const key = `${ip}:${req.baseUrl || req.path}`;
    const now = Date.now();
    let record = rateLimitMap.get(key);

    if (!record || now > record.resetTime) {
      record = { count: 1, resetTime: now + windowMs };
      rateLimitMap.set(key, record);
    } else {
      record.count++;
    }

    const remaining = Math.max(0, maxRequests - record.count);
    const resetSec = Math.ceil((record.resetTime - now) / 1000);

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', resetSec);

    if (record.count > maxRequests) {
      pushConsole('WARN', 'SECURITY', `⚠️ Rate limit exceeded by ${ip} on ${req.originalUrl}`);
      return res.status(429).json({
        error: message || 'Too many requests. Please slow down.',
        retryAfter: resetSec
      });
    }
    next();
  };
}

// Global rate limiters
const validateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 120,
  message: 'Validation rate limit exceeded. Please wait.'
});

const adminLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 60,
  message: 'Admin API rate limit exceeded.'
});

// Periodic rate limiter memory cleanup every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) {
      rateLimitMap.delete(key);
    }
  }
}, 5 * 60 * 1000);

// Ensure data folder and files exist
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

// ---------------------- Real-Time Console Buffer & Streaming ----------------------
const consoleLogs = [];
const MAX_CONSOLE_LOGS = 600;
const sseClients = new Set();

function pushConsole(level, tag, message) {
  const now = new Date();
  const time = now.toLocaleTimeString();
  const entry = {
    id: Date.now() + Math.random(),
    time,
    timestamp: now.toISOString(),
    level: level.toUpperCase(), // INFO, SUCCESS, WARN, ERROR, CMD
    tag: tag.toUpperCase(),     // SYSTEM, LICENSE, SECURITY, ADMIN, CLI
    message: typeof message === 'object' ? JSON.stringify(message) : String(message)
  };
  consoleLogs.push(entry);
  if (consoleLogs.length > MAX_CONSOLE_LOGS) consoleLogs.shift();

  // Broadcast to live dashboard SSE streams
  for (const client of sseClients) {
    try {
      client.write(`data: ${JSON.stringify(entry)}\n\n`);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

// Monkey-patch console for automatic terminal logging
const origLog = console.log;
const origError = console.error;
const origWarn = console.warn;

console.log = (...args) => {
  origLog(...args);
  pushConsole('INFO', 'SYSTEM', args.join(' '));
};
console.error = (...args) => {
  origError(...args);
  pushConsole('ERROR', 'SYSTEM', args.join(' '));
};
console.warn = (...args) => {
  origWarn(...args);
  pushConsole('WARN', 'SYSTEM', args.join(' '));
};

function loadLicenses() {
  let licenses = {};
  try {
    if (fs.existsSync(DATA_FILE)) {
      const content = fs.readFileSync(DATA_FILE, 'utf8');
      licenses = JSON.parse(content) || {};
    }
  } catch (err) {
    console.error('Error reading licenses file:', err.message);
    licenses = {};
  }

  // Always ensure RS-DEFAULT-PREMIUM-KEY-2026 is loaded and active
  const DEFAULT_KEY = 'RS-DEFAULT-PREMIUM-KEY-2026';
  if (!licenses[DEFAULT_KEY] || typeof licenses[DEFAULT_KEY] !== 'object') {
    licenses[DEFAULT_KEY] = {
      key: DEFAULT_KEY,
      owner: 'ServerOwner',
      tier: 'PREMIUM',
      status: 'ACTIVE',
      ip_lock: false,
      bound_ip: null,
      max_servers: null, // Unlimited servers
      created_at: new Date().toISOString(),
      expires_at: null,
      note: 'Default master key (Unlimited servers)',
      servers: {}
    };
    saveLicenses(licenses);
  }

  return licenses;
}

function saveLicenses(licenses) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(licenses, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving licenses file:', err.message);
  }
}

function loadBannedIps() {
  try {
    if (fs.existsSync(BANNED_IPS_FILE)) {
      return JSON.parse(fs.readFileSync(BANNED_IPS_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error reading banned_ips file:', err.message);
  }
  return {};
}

function saveBannedIps(banned) {
  try {
    fs.writeFileSync(BANNED_IPS_FILE, JSON.stringify(banned, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving banned_ips file:', err.message);
  }
}

function logValidation(entry) {
  try {
    let logs = [];
    if (fs.existsSync(LOGS_FILE)) {
      try {
        logs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
      } catch (e) {
        logs = [];
      }
    }

    const targetKey = (entry.key || 'UNKNOWN').trim();
    const targetIp = (entry.ip || '').trim();

    // Look for existing log from this server (matched by key and IP)
    const existingIndex = logs.findIndex(l => (l.key || '').trim() === targetKey && (l.ip || '').trim() === targetIp);

    if (existingIndex !== -1) {
      const existing = logs[existingIndex];
      const updated = {
        ...existing,
        ...entry,
        count: (existing.count || 1) + 1,
        timestamp: new Date().toISOString()
      };
      // Move updated server record to the top
      logs.splice(existingIndex, 1);
      logs.unshift(updated);
    } else {
      logs.unshift({
        ...entry,
        count: 1,
        timestamp: new Date().toISOString()
      });
    }

    if (logs.length > 200) logs = logs.slice(0, 200);
    fs.writeFileSync(LOGS_FILE, JSON.stringify(logs, null, 2), 'utf8');
  } catch (err) {
    // Non-critical
  }
}

function generateSignature(key, status, timestamp) {
  return crypto
    .createHmac('sha256', SECRET_SIGN_KEY)
    .update(`${key}:${status}:${timestamp}`)
    .digest('hex');
}

function generateKeyString() {
  const segment = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `RS-${segment()}-${segment()}-${segment()}-${segment()}`;
}

// ---------------------- Public Health Endpoint ----------------------
app.get('/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'RSLogin License Verification API',
    version: '1.4.0',
    timestamp: new Date().toISOString()
  });
});

// ---------------------- License Validation Endpoint ----------------------
// Called by Minecraft Paper/Velocity plugins
app.post('/api/license/validate', validateLimiter, (req, res) => {
  const {
    license_key,
    api_key,
    product,
    server_ip,
    port,
    server_name,
    server_version,
    motd,
    online_players,
    max_players,
    status
  } = req.body;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || server_ip;

  // 1. IP Ban check
  const bannedIps = loadBannedIps();
  if (bannedIps[clientIp]) {
    const banInfo = bannedIps[clientIp];
    pushConsole('ERROR', 'SECURITY', `🚫 Blocked connection from banned IP ${clientIp} (${banInfo.reason || 'Blacklisted'})`);
    logValidation({ key: license_key || 'UNKNOWN', valid: false, reason: `IP ${clientIp} is BANNED (${banInfo.reason || 'Blacklisted'})`, ip: clientIp, product });
    return res.status(403).json({
      valid: false,
      status: 'IP_BANNED',
      message: `Your server IP (${clientIp}) is banned: ${banInfo.reason || 'Contact administrator.'}`
    });
  }

  // 2. API Key authentication check (constant-time verification)
  const providedApiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '').trim() || api_key;
  if (!isValidApiKey(providedApiKey)) {
    pushConsole('WARN', 'SECURITY', `⚠️ Unauthorized API key attempt from ${clientIp} (Product: ${product || 'unknown'})`);
    logValidation({ key: license_key || 'UNKNOWN', valid: false, reason: 'Invalid or missing API key', ip: clientIp, product });
    return res.status(401).json({
      valid: false,
      status: 'UNAUTHORIZED_API_KEY',
      message: 'Invalid or missing API key. Set api-key in plugin config.'
    });
  }

  // 3. License key presence (fallback to default key if omitted)
  let effectiveKey = (typeof license_key === 'string' ? license_key.trim() : '');
  if (!effectiveKey || effectiveKey.toUpperCase() === 'YOUR-LICENSE-KEY' || effectiveKey.toUpperCase() === 'PUT-YOUR-LICENSE-KEY-HERE' || effectiveKey.toUpperCase() === 'DEFAULT') {
    effectiveKey = 'RS-DEFAULT-PREMIUM-KEY-2026';
  }

  const licenses = loadLicenses();
  const license = licenses[effectiveKey];

  if (!license) {
    pushConsole('WARN', 'LICENSE', `🔴 Key not found in database: "${effectiveKey}" from ${clientIp}`);
    logValidation({ key: effectiveKey, valid: false, reason: 'Key not found', ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: 'INVALID',
      message: 'License key does not exist or was revoked.'
    });
  }

  // Handle graceful shutdown notice
  const serverId = `${clientIp}:${port || 25565}`;
  if (status === 'OFFLINE') {
    if (license.servers && license.servers[serverId]) {
      license.servers[serverId].status = 'OFFLINE';
      license.servers[serverId].last_seen = new Date().toISOString();
      license.servers[serverId].online_players = 0;
      licenses[effectiveKey] = license;
      saveLicenses(licenses);
    }
    pushConsole('INFO', 'LICENSE', `⚪ Server ${serverId} (${product || 'plugin'}) disconnected [OFFLINE]`);
    return res.status(200).json({
      valid: true,
      status: 'OFFLINE',
      message: 'Server node recorded as offline.'
    });
  }

  if (license.status !== 'ACTIVE') {
    pushConsole('WARN', 'LICENSE', `🔴 Denied ${clientIp}: key ${license.key} status is ${license.status}`);
    logValidation({ key: effectiveKey, valid: false, reason: `Status: ${license.status}`, ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: license.status,
      message: `License is currently ${license.status}. Contact administrator.`
    });
  }

  if (license.expires_at && new Date() > new Date(license.expires_at)) {
    pushConsole('WARN', 'LICENSE', `🔴 Denied ${clientIp}: key ${license.key} expired on ${license.expires_at}`);
    logValidation({ key: effectiveKey, valid: false, reason: 'License expired', ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: 'EXPIRED',
      message: 'License has expired.'
    });
  }

  // 4. IP Lock check
  if (license.ip_lock) {
    if (!license.bound_ip && clientIp) {
      license.bound_ip = clientIp;
      licenses[effectiveKey] = license;
      saveLicenses(licenses);
      pushConsole('INFO', 'LICENSE', `🔒 Key ${license.key} automatically bound to first IP: ${clientIp}`);
    } else if (license.bound_ip && license.bound_ip !== clientIp && license.bound_ip !== server_ip) {
      pushConsole('WARN', 'SECURITY', `🚫 IP mismatch for ${license.key}: bound=${license.bound_ip}, caller=${clientIp}`);
      logValidation({ key: effectiveKey, valid: false, reason: `IP mismatch (bound: ${license.bound_ip}, got: ${clientIp})`, ip: clientIp, product });
      return res.status(200).json({
        valid: false,
        status: 'IP_MISMATCH',
        message: `License is locked to IP ${license.bound_ip}.`
      });
    }
  }

  // 5. Server Count Limit check (null or 0 = unlimited)
  if (!license.servers) license.servers = {};
  const existingServers = Object.keys(license.servers);
  if (typeof license.max_servers === 'number' && license.max_servers > 0 && !license.servers[serverId] && existingServers.length >= license.max_servers) {
    pushConsole('WARN', 'LICENSE', `⚠️ Server limit exceeded for ${license.key}: ${existingServers.length}/${license.max_servers}`);
    logValidation({ key: effectiveKey, valid: false, reason: `Max server limit reached (${existingServers.length}/${license.max_servers})`, ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: 'SERVER_LIMIT_REACHED',
      message: `License server limit reached (${license.max_servers} max servers). Remove an unused server from the dashboard first.`
    });
  }

  const nodeName = (server_name && server_name.trim()) ? server_name.trim() : (motd && motd.trim() ? motd.trim() : 'Minecraft Server');
  const nodeVersion = (server_version && server_version.trim()) ? server_version.trim() : 'Unknown';
  const playersCount = (typeof online_players === 'number') ? Math.max(0, online_players) : (license.servers[serverId]?.online_players || 0);
  const maxCap = (typeof max_players === 'number') ? Math.max(0, max_players) : (license.servers[serverId]?.max_players || 0);

  // 6. Record connected server
  license.servers[serverId] = {
    id: serverId,
    ip: clientIp,
    port: port || 25565,
    product: product || 'rslogin',
    server_name: nodeName,
    server_version: nodeVersion,
    motd: motd || '',
    online_players: playersCount,
    max_players: maxCap,
    status: 'ONLINE',
    first_seen: license.servers[serverId]?.first_seen || new Date().toISOString(),
    last_seen: new Date().toISOString()
  };
  licenses[effectiveKey] = license;
  saveLicenses(licenses);

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = generateSignature(license.key, license.status, timestamp);

  pushConsole('SUCCESS', 'LICENSE', `🟢 Server "${nodeName}" [${serverId}] (${product || 'rslogin'}, ${playersCount}/${maxCap} players) verified key ${license.key} [${license.owner}]`);
  logValidation({ key: effectiveKey, valid: true, owner: license.owner, ip: clientIp, port: port || 25565, server_name: nodeName, product });

  return res.status(200).json({
    valid: true,
    status: 'ACTIVE',
    license_key: license.key,
    owner: license.owner,
    tier: license.tier || 'STANDARD',
    expires_at: license.expires_at,
    timestamp,
    signature,
    message: 'License is valid and verified.'
  });
});

// ---------------------- Admin Authentication & Rate Limiting ----------------------
app.use('/api/admin', adminLimiter);

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const clientIp = getClientIp(req);

  // Check brute force lockout
  const lockout = checkLoginLockout(clientIp);
  if (lockout.locked) {
    return res.status(429).json({
      error: `Too many failed attempts. Locked out for ${Math.ceil(lockout.remainingSec / 60)} more minute(s).`,
      retryAfter: lockout.remainingSec
    });
  }

  // 1. Direct ADMIN_SECRET match (timing-safe)
  if (timingSafeMatch(token, ADMIN_SECRET)) {
    clearFailedLogin(clientIp);
    return next();
  }

  // 2. Cryptographic session token verification
  const session = verifyAdminSessionToken(token, clientIp);
  if (session) {
    req.adminSession = session;
    clearFailedLogin(clientIp);
    return next();
  }

  // Invalid token -> record failed attempt
  recordFailedLogin(clientIp);
  pushConsole('WARN', 'SECURITY', `🚫 Unauthorized admin attempt from ${clientIp}`);
  return res.status(403).json({ error: 'Invalid admin credentials' });
}

// Dedicated secure login endpoint (with brute force defense)
app.post('/api/admin/login', (req, res) => {
  const clientIp = getClientIp(req);
  const lockout = checkLoginLockout(clientIp);
  if (lockout.locked) {
    return res.status(429).json({
      error: `Too many failed attempts. IP locked out for ${Math.ceil(lockout.remainingSec / 60)} more minute(s).`,
      retryAfter: lockout.remainingSec
    });
  }

  const { password } = req.body || {};
  if (!password || !timingSafeMatch(password, ADMIN_SECRET)) {
    recordFailedLogin(clientIp);
    const updatedLockout = checkLoginLockout(clientIp);
    if (updatedLockout.locked) {
      return res.status(429).json({
        error: 'Maximum attempts reached. Locked out for 15 minutes.',
        retryAfter: updatedLockout.remainingSec
      });
    }
    return res.status(403).json({
      error: 'Invalid admin secret password',
      attemptsLeft: Math.max(0, MAX_FAILED_ATTEMPTS - (updatedLockout.attempts || 1))
    });
  }

  clearFailedLogin(clientIp);
  const sessionToken = createAdminSessionToken(clientIp);
  pushConsole('SUCCESS', 'ADMIN', `🔑 Administrator authenticated from ${clientIp}`);
  res.json({
    success: true,
    token: sessionToken,
    expires_in: 12 * 3600,
    role: 'admin'
  });
});

// Verify current session token or secret
app.get('/api/admin/verify', requireAdmin, (req, res) => {
  res.json({ valid: true, role: 'admin' });
});

// Logout endpoint
app.post('/api/admin/logout', requireAdmin, (req, res) => {
  pushConsole('INFO', 'ADMIN', `🚪 Administrator logged out from ${getClientIp(req)}`);
  res.json({ success: true, message: 'Logged out successfully' });
});

// ---------------------- Interactive Console & Terminal CLI ----------------------

// Execute terminal command
app.post('/api/admin/console/exec', requireAdmin, (req, res) => {
  const rawCommand = (req.body.command || '').trim();
  if (!rawCommand) {
    return res.status(400).json({ error: 'Command cannot be empty' });
  }

  pushConsole('CMD', 'CLI', `$ ${rawCommand}`);

  const parts = rawCommand.split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1);

  const licenses = loadLicenses();
  const banned = loadBannedIps();

  let output = '';

  switch (cmd) {
    case 'help':
      output = [
        '======================= RSLogin License CLI =======================',
        'Available Commands:',
        '  help                           - Show this help manual',
        '  status / stats                 - View server health, memory and node telemetry',
        '  keys / list                    - List all license keys and owners',
        '  gen <owner> [tier] [max]       - Quick generate a new license key',
        '  activate <key>                 - Activate a suspended license key',
        '  suspend <key>                  - Suspend an active license key',
        '  delete <key>                   - Permanently remove a license key',
        '  servers                        - View all active Minecraft servers',
        '  kick <key> <ip:port>           - Disconnect a server node from a key',
        '  reset-ip <key>                 - Clear bound IP on an IP-locked key',
        '  ban <ip> [reason]              - Blacklist a server IP address',
        '  unban <ip>                     - Remove an IP address from blacklist',
        '  banned                         - List all blacklisted IP addresses',
        '  clear                          - Flush terminal log buffer',
        '==================================================================='
      ].join('\n');
      pushConsole('INFO', 'CLI', output);
      break;

    case 'status':
    case 'stats':
      const mem = process.memoryUsage();
      const uptimeSec = Math.floor(process.uptime());
      const hours = Math.floor(uptimeSec / 3600);
      const mins = Math.floor((uptimeSec % 3600) / 60);
      const secs = uptimeSec % 60;
      let totalSrv = 0;
      Object.values(licenses).forEach(l => { if (l.servers) totalSrv += Object.keys(l.servers).length; });

      output = [
        `System Status:        ONLINE`,
        `Uptime:               ${hours}h ${mins}m ${secs}s`,
        `Memory RSS:           ${(mem.rss / 1024 / 1024).toFixed(2)} MB`,
        `Heap Usage:           ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB`,
        `Node Runtime:         ${process.version} (${process.platform})`,
        `Total Licenses:       ${Object.keys(licenses).length}`,
        `Connected Servers:    ${totalSrv}`,
        `Banned IPs:           ${Object.keys(banned).length}`
      ].join('\n');
      pushConsole('SUCCESS', 'CLI', output);
      break;

    case 'keys':
    case 'list':
      const keyList = Object.values(licenses);
      if (keyList.length === 0) {
        output = 'No license keys found in database.';
      } else {
        output = keyList.map(k => {
          const srvCount = k.servers ? Object.keys(k.servers).length : 0;
          return `• [${k.status}] ${k.key} | Owner: ${k.owner || '—'} | Tier: ${k.tier || 'STANDARD'} | Servers: ${srvCount}/${k.max_servers || 3}${k.ip_lock ? ' (IP-Locked)' : ''}`;
        }).join('\n');
      }
      pushConsole('INFO', 'CLI', output);
      break;

    case 'gen':
    case 'create':
      const owner = args[0] || 'Customer';
      const tier = (args[1] || 'PREMIUM').toUpperCase();
      const max_servers = parseInt(args[2]) || 3;
      const newKey = generateKeyString();

      licenses[newKey] = {
        key: newKey,
        owner,
        tier,
        status: 'ACTIVE',
        max_servers,
        ip_lock: false,
        bound_ip: null,
        created_at: new Date().toISOString(),
        expires_at: null,
        note: 'Generated from Console CLI',
        servers: {}
      };
      saveLicenses(licenses);

      output = `✓ License generated: ${newKey} for ${owner} [Tier: ${tier}, Max Servers: ${max_servers}]`;
      pushConsole('SUCCESS', 'CLI', output);
      break;

    case 'activate':
      const actKey = args[0];
      if (!actKey || !licenses[actKey]) {
        output = `Error: License key "${actKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        licenses[actKey].status = 'ACTIVE';
        saveLicenses(licenses);
        output = `✓ License ${actKey} is now ACTIVE.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;

    case 'suspend':
      const suspKey = args[0];
      if (!suspKey || !licenses[suspKey]) {
        output = `Error: License key "${suspKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        licenses[suspKey].status = 'SUSPENDED';
        saveLicenses(licenses);
        output = `✓ License ${suspKey} is now SUSPENDED.`;
        pushConsole('WARN', 'CLI', output);
      }
      break;

    case 'delete':
    case 'remove':
      const delKey = args[0];
      if (!delKey || !licenses[delKey]) {
        output = `Error: License key "${delKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        delete licenses[delKey];
        saveLicenses(licenses);
        output = `✓ License ${delKey} has been permanently deleted.`;
        pushConsole('WARN', 'CLI', output);
      }
      break;

    case 'servers':
      const srvList = [];
      Object.values(licenses).forEach(k => {
        if (k.servers) {
          Object.values(k.servers).forEach(s => {
            srvList.push(`• ${s.ip}:${s.port || 25565} | Key: ${k.key} (${k.owner}) | Product: ${s.product} | Last Ping: ${s.last_seen ? new Date(s.last_seen).toLocaleTimeString() : '—'}`);
          });
        }
      });
      output = srvList.length > 0 ? srvList.join('\n') : 'No Minecraft server nodes currently connected.';
      pushConsole('INFO', 'CLI', output);
      break;

    case 'kick':
      const kKey = args[0];
      const kServerId = args[1];
      if (!kKey || !kServerId || !licenses[kKey] || !licenses[kKey].servers?.[kServerId]) {
        output = `Error: Invalid syntax or server not found. Usage: kick <license_key> <ip:port>`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        delete licenses[kKey].servers[kServerId];
        saveLicenses(licenses);
        output = `✓ Server ${kServerId} disconnected from key ${kKey}.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;

    case 'reset-ip':
      const rKey = args[0];
      if (!rKey || !licenses[rKey]) {
        output = `Error: License key "${rKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        licenses[rKey].bound_ip = null;
        saveLicenses(licenses);
        output = `✓ Bound IP cleared for ${rKey}. Next connection will re-bind.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;

    case 'ban':
      const banIp = args[0];
      const banReason = args.slice(1).join(' ') || 'Banned via Console CLI';
      if (!banIp) {
        output = 'Error: IP address is required. Usage: ban <ip> [reason]';
        pushConsole('ERROR', 'CLI', output);
      } else {
        banned[banIp.trim()] = {
          ip: banIp.trim(),
          reason: banReason,
          banned_at: new Date().toISOString()
        };
        saveBannedIps(banned);
        output = `⛔ IP ${banIp.trim()} has been blacklisted. Reason: ${banReason}`;
        pushConsole('ERROR', 'CLI', output);
      }
      break;

    case 'unban':
      const unbanIp = args[0];
      if (!unbanIp || !banned[unbanIp.trim()]) {
        output = `Error: IP "${unbanIp}" not found in blacklist.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        delete banned[unbanIp.trim()];
        saveBannedIps(banned);
        output = `✓ IP ${unbanIp.trim()} has been unbanned.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;

    case 'banned':
      const bList = Object.values(banned);
      output = bList.length > 0
        ? bList.map(b => `• ${b.ip} | Reason: ${b.reason || '—'} | Date: ${new Date(b.banned_at).toLocaleString()}`).join('\n')
        : 'No IP addresses are currently blacklisted.';
      pushConsole('INFO', 'CLI', output);
      break;

    case 'clear':
      consoleLogs.length = 0;
      output = 'Console cleared.';
      pushConsole('INFO', 'CLI', output);
      break;

    default:
      output = `Command not recognized: "${cmd}". Type "help" for a list of commands.`;
      pushConsole('WARN', 'CLI', output);
      break;
  }

  res.json({ success: true, command: rawCommand, output });
});

// Get recent console logs and telemetry metrics
app.get('/api/admin/console/logs', requireAdmin, (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    logs: consoleLogs,
    metrics: {
      uptime: Math.floor(process.uptime()),
      memory_rss_mb: (mem.rss / 1024 / 1024).toFixed(1),
      memory_heap_mb: (mem.heapUsed / 1024 / 1024).toFixed(1),
      node_version: process.version,
      platform: process.platform,
      active_streams: sseClients.size
    }
  });
});

// Real-time Server-Sent Events stream for Console Viewer
app.get('/api/admin/console/stream', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace(/^Bearer\s+/i, '').trim();
  const clientIp = getClientIp(req);
  const isDirect = timingSafeMatch(token, ADMIN_SECRET);
  const isSession = verifyAdminSessionToken(token, clientIp);

  if (!isDirect && !isSession) {
    return res.status(401).send('Unauthorized to stream console');
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  res.write(`data: ${JSON.stringify({
    id: Date.now(),
    time: new Date().toLocaleTimeString(),
    level: 'INFO',
    tag: 'SYSTEM',
    message: '🖥️ Connected to RSLogin Interactive Terminal. Type "help" to view commands.'
  })}\n\n`);

  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

// Clear console buffer
app.delete('/api/admin/console/logs', requireAdmin, (req, res) => {
  consoleLogs.length = 0;
  pushConsole('INFO', 'ADMIN', 'Console buffer cleared by administrator.');
  res.json({ success: true, message: 'Console buffer cleared.' });
});

// ---------------------- Admin License Management ----------------------

// List all licenses
app.get('/api/admin/licenses', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  const now = Date.now();
  for (const lic of Object.values(licenses)) {
    if (lic.servers) {
      for (const srv of Object.values(lic.servers)) {
        if (srv.status === 'OFFLINE') continue;
        const diffMs = now - new Date(srv.last_seen).getTime();
        if (diffMs > 5 * 60 * 1000) {
          srv.status = 'OFFLINE';
        } else if (diffMs > 2.5 * 60 * 1000) {
          srv.status = 'AWAY';
        } else {
          srv.status = 'ONLINE';
        }
      }
    }
  }
  res.json({
    count: Object.keys(licenses).length,
    licenses: Object.values(licenses)
  });
});

// Create custom license
app.post('/api/admin/licenses', requireAdmin, (req, res) => {
  let { key, owner = 'Customer', tier = 'STANDARD', max_servers = 3, ip_lock = false, bound_ip = null, expires_at = null, note = '' } = req.body || {};
  if (!key || typeof key !== 'string' || !/^[A-Za-z0-9\-_]{3,64}$/.test(key.trim())) {
    return res.status(400).json({ error: 'License key must be 3-64 alphanumeric characters, dashes, or underscores' });
  }

  const cleanKey = key.trim();
  const licenses = loadLicenses();
  if (licenses[cleanKey]) {
    return res.status(409).json({ error: 'License key already exists' });
  }

  let cleanMaxServers = null;
  if (max_servers !== undefined && max_servers !== null && max_servers !== '' && max_servers !== 0 && max_servers !== '0') {
    const num = parseInt(max_servers, 10);
    cleanMaxServers = (num > 0) ? num : null;
  }

  licenses[cleanKey] = {
    key: cleanKey,
    owner: String(owner || 'Customer').trim().slice(0, 100),
    tier: String(tier || 'STANDARD').trim().toUpperCase().slice(0, 30),
    status: 'ACTIVE',
    max_servers: cleanMaxServers,
    ip_lock: Boolean(ip_lock),
    bound_ip: bound_ip ? String(bound_ip).trim().slice(0, 60) : null,
    created_at: new Date().toISOString(),
    expires_at: expires_at ? new Date(expires_at).toISOString() : null,
    note: String(note || '').trim().slice(0, 255),
    servers: {}
  };

  saveLicenses(licenses);
  pushConsole('SUCCESS', 'ADMIN', `✨ New license created: ${cleanKey} for ${licenses[cleanKey].owner} [Tier: ${licenses[cleanKey].tier}, Max: ${licenses[cleanKey].max_servers}]`);
  res.status(201).json({
    success: true,
    message: 'License created successfully',
    license: licenses[cleanKey]
  });
});

// Update license info (supports renaming key and editing all properties)
function handleUpdateLicense(req, res) {
  const licenses = loadLicenses();
  const key = req.params.key;

  if (!licenses[key]) {
    return res.status(404).json({ error: 'License not found' });
  }

  const { new_key, key: bodyKey, status, owner, tier, max_servers, ip_lock, bound_ip, expires_at, note } = req.body || {};
  let targetKey = key;
  const requestedNewKey = new_key || (bodyKey && bodyKey !== key ? bodyKey : null);

  // Handle key renaming if requested
  if (requestedNewKey && typeof requestedNewKey === 'string' && requestedNewKey.trim() !== key) {
    const cleanNewKey = requestedNewKey.trim();
    if (!/^[A-Za-z0-9\-_]{3,64}$/.test(cleanNewKey)) {
      return res.status(400).json({ error: 'New license key must be 3-64 alphanumeric characters, dashes, or underscores' });
    }
    if (licenses[cleanNewKey]) {
      return res.status(409).json({ error: `License key "${cleanNewKey}" already exists` });
    }
    licenses[cleanNewKey] = licenses[key];
    delete licenses[key];
    licenses[cleanNewKey].key = cleanNewKey;
    targetKey = cleanNewKey;
    pushConsole('WARN', 'ADMIN', `🔑 License key renamed: "${key}" ➔ "${cleanNewKey}"`);
  }

  if (status) licenses[targetKey].status = status;
  if (owner !== undefined) licenses[targetKey].owner = String(owner || '').trim().slice(0, 100);
  if (tier !== undefined) licenses[targetKey].tier = String(tier || 'STANDARD').trim().toUpperCase().slice(0, 30);
  if (max_servers !== undefined) {
    if (max_servers === null || max_servers === 0 || max_servers === '0' || max_servers === '' || String(max_servers).toLowerCase() === 'unlimited') {
      licenses[targetKey].max_servers = null; // Unlimited
    } else {
      const num = parseInt(max_servers, 10);
      licenses[targetKey].max_servers = (num > 0) ? num : null;
    }
  }
  if (ip_lock !== undefined) licenses[targetKey].ip_lock = Boolean(ip_lock);
  if (bound_ip !== undefined) licenses[targetKey].bound_ip = bound_ip ? String(bound_ip).trim().slice(0, 60) : null;
  if (expires_at !== undefined) licenses[targetKey].expires_at = expires_at ? new Date(expires_at).toISOString() : null;
  if (note !== undefined) licenses[targetKey].note = String(note || '').trim().slice(0, 255);

  licenses[targetKey].updated_at = new Date().toISOString();
  saveLicenses(licenses);

  pushConsole('INFO', 'ADMIN', `✏️ License ${targetKey} updated (Owner: ${licenses[targetKey].owner}, Tier: ${licenses[targetKey].tier}, Status: ${licenses[targetKey].status})`);
  res.json({
    success: true,
    message: 'License updated successfully',
    license: licenses[targetKey]
  });
}

app.put('/api/admin/licenses/:key', requireAdmin, handleUpdateLicense);
app.patch('/api/admin/licenses/:key', requireAdmin, handleUpdateLicense);

// Reset IP lock on a key
app.post('/api/admin/licenses/:key/reset-ip', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  const key = req.params.key;

  if (!licenses[key]) {
    return res.status(404).json({ error: 'License not found' });
  }

  licenses[key].bound_ip = null;
  saveLicenses(licenses);
  pushConsole('INFO', 'ADMIN', `🔓 IP lock reset for key ${key}`);

  res.json({
    success: true,
    message: `IP lock for ${key} reset. Next connecting server IP will be bound.`
  });
});

// Remove a connected server from a license key
app.delete('/api/admin/licenses/:key/servers/:serverId', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  const { key, serverId } = req.params;

  if (!licenses[key]) {
    return res.status(404).json({ error: 'License not found' });
  }

  if (licenses[key].servers && licenses[key].servers[serverId]) {
    delete licenses[key].servers[serverId];
    saveLicenses(licenses);
    pushConsole('WARN', 'ADMIN', `🔌 Disconnected server node ${serverId} from key ${key}`);
    return res.json({
      success: true,
      message: `Server ${serverId} removed from license ${key}`
    });
  }

  res.status(404).json({ error: 'Server connection not found on this license' });
});

// Delete license permanently
app.delete('/api/admin/licenses/:key', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  const key = req.params.key;

  if (!licenses[key]) {
    return res.status(404).json({ error: 'License not found' });
  }

  delete licenses[key];
  saveLicenses(licenses);
  pushConsole('WARN', 'ADMIN', `🗑️ Permanently deleted license ${key}`);

  res.json({
    success: true,
    message: `License ${key} deleted successfully`
  });
});

// ---------------------- Banned IPs Management ----------------------

// List all banned IPs
app.get('/api/admin/banned-ips', requireAdmin, (req, res) => {
  const banned = loadBannedIps();
  res.json({
    count: Object.keys(banned).length,
    banned_ips: Object.values(banned)
  });
});

// Ban an IP
app.post('/api/admin/banned-ips', requireAdmin, (req, res) => {
  const { ip, reason = 'Administrative ban' } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }

  const banned = loadBannedIps();
  const cleanIp = ip.trim();
  banned[cleanIp] = {
    ip: cleanIp,
    reason: reason.trim(),
    banned_at: new Date().toISOString()
  };

  saveBannedIps(banned);
  pushConsole('ERROR', 'SECURITY', `⛔ Admin blacklisted IP ${cleanIp} (Reason: ${reason})`);
  res.status(201).json({
    success: true,
    message: `IP ${cleanIp} has been banned.`,
    entry: banned[cleanIp]
  });
});

// Unban an IP
app.delete('/api/admin/banned-ips/:ip', requireAdmin, (req, res) => {
  const cleanIp = req.params.ip.trim();
  const banned = loadBannedIps();

  if (!banned[cleanIp]) {
    return res.status(404).json({ error: 'IP not found in ban list' });
  }

  delete banned[cleanIp];
  saveBannedIps(banned);
  pushConsole('INFO', 'SECURITY', `🟢 Admin unbanned IP ${cleanIp}`);

  res.json({
    success: true,
    message: `IP ${cleanIp} has been unbanned.`
  });
});

// ---------------------- Audit Logs Management ----------------------

function collapseLogs(rawLogs) {
  if (!Array.isArray(rawLogs) || rawLogs.length === 0) return [];
  const map = new Map();
  for (const item of rawLogs) {
    const key = (item.key || 'UNKNOWN').trim();
    const ip = (item.ip || '127.0.0.1').trim();
    const serverId = `${key}@${ip}`;
    if (!map.has(serverId)) {
      map.set(serverId, { ...item, key, ip, count: item.count || 1 });
    } else {
      const existing = map.get(serverId);
      existing.count = (existing.count || 1) + (item.count || 1);
      if (!existing.timestamp || new Date(item.timestamp) > new Date(existing.timestamp)) {
        existing.timestamp = item.timestamp;
        existing.valid = item.valid;
        if (item.reason) existing.reason = item.reason;
        if (item.server_name) existing.server_name = item.server_name;
        if (item.port) existing.port = item.port;
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

// View validation logs
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  try {
    let logs = [];
    if (fs.existsSync(LOGS_FILE)) {
      logs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
    }
    res.json({ logs: collapseLogs(logs) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Clear validation logs
app.delete('/api/admin/logs', requireAdmin, (req, res) => {
  try {
    fs.writeFileSync(LOGS_FILE, JSON.stringify([], null, 2), 'utf8');
    pushConsole('INFO', 'ADMIN', `🧹 Validation audit logs cleared by admin.`);
    res.json({ success: true, message: 'Audit logs cleared successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------- Start Server ----------------------
try {
  if (fs.existsSync(LOGS_FILE)) {
    const raw = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
    const sanitized = collapseLogs(raw);
    fs.writeFileSync(LOGS_FILE, JSON.stringify(sanitized, null, 2), 'utf8');
  }
} catch (e) {}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`🚀 RSLogin License Server online on port ${PORT}`);
  console.log(`📡 Health Check: http://localhost:${PORT}/health`);
  console.log(`🔑 Admin Auth: PROTECTED`);
  console.log(`===============================================`);
});

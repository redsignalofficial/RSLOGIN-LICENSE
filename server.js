const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
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
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_2RnsoCcOGzm5@ep-spring-cloud-a1flxsrk-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

// ---------------------- PostgreSQL Connection Pool ----------------------
const pool = new Pool({ connectionString: DATABASE_URL });

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err.message);
});

// Initialize DB tables and seed default key
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        owner TEXT NOT NULL DEFAULT 'Customer',
        tier TEXT NOT NULL DEFAULT 'STANDARD',
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        max_servers INT,
        ip_lock BOOLEAN DEFAULT FALSE,
        bound_ip TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ,
        note TEXT DEFAULT '',
        servers JSONB DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS banned_ips (
        ip TEXT PRIMARY KEY,
        reason TEXT DEFAULT 'Administrative ban',
        banned_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS validation_logs (
        id SERIAL PRIMARY KEY,
        license_key TEXT NOT NULL,
        valid BOOLEAN NOT NULL,
        ip TEXT,
        port INT,
        server_name TEXT,
        product TEXT,
        reason TEXT,
        owner TEXT,
        count INT DEFAULT 1,
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(license_key, ip)
      );
    `);

    // Seed default master key if not present
    await client.query(`
      INSERT INTO licenses (key, owner, tier, status, max_servers, ip_lock, bound_ip, created_at, expires_at, note, servers)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (key) DO NOTHING
    `, [
      'RS-DEFAULT-PREMIUM-KEY-2026',
      'ServerOwner',
      'PREMIUM',
      'ACTIVE',
      null,
      false,
      null,
      new Date().toISOString(),
      null,
      'Default master key (Unlimited servers)',
      '{}'
    ]);

    console.log('🗄️ PostgreSQL connected and tables ready.');
    pushConsole('SUCCESS', 'DB', '🗄️ PostgreSQL connected and tables ready.');
  } catch (err) {
    console.error(`❌ Database init error: ${err.message}`);
    pushConsole('ERROR', 'DB', `❌ Database init error: ${err.message}`);
  } finally {
    client.release();
  }
}

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

// Ensure public folder exists for icon serving
if (!fs.existsSync(path.join(__dirname, 'public'))) {
  fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });
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

// ---------------------- Database Helpers (PostgreSQL async) ----------------------

function dbRowToLicense(row) {
  if (!row) return null;
  return {
    key: row.key,
    owner: row.owner,
    tier: row.tier,
    status: row.status,
    max_servers: row.max_servers,
    ip_lock: row.ip_lock,
    bound_ip: row.bound_ip,
    created_at: row.created_at ? row.created_at.toISOString() : null,
    expires_at: row.expires_at ? row.expires_at.toISOString() : null,
    note: row.note || '',
    servers: row.servers || {},
    updated_at: row.updated_at ? row.updated_at.toISOString() : null
  };
}

async function getLicense(key) {
  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [key]);
    return rows[0] ? dbRowToLicense(rows[0]) : null;
  } catch (err) {
    console.error('DB getLicense error:', err.message);
    return null;
  }
}

async function getAllLicenses() {
  try {
    const { rows } = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
    const result = {};
    for (const row of rows) {
      const lic = dbRowToLicense(row);
      result[lic.key] = lic;
    }
    return result;
  } catch (err) {
    console.error('DB getAllLicenses error:', err.message);
    return {};
  }
}

async function saveLicenseDB(lic) {
  try {
    await pool.query(`
      INSERT INTO licenses (key, owner, tier, status, max_servers, ip_lock, bound_ip, created_at, expires_at, note, servers, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
      ON CONFLICT (key) DO UPDATE SET
        owner = EXCLUDED.owner,
        tier = EXCLUDED.tier,
        status = EXCLUDED.status,
        max_servers = EXCLUDED.max_servers,
        ip_lock = EXCLUDED.ip_lock,
        bound_ip = EXCLUDED.bound_ip,
        expires_at = EXCLUDED.expires_at,
        note = EXCLUDED.note,
        servers = EXCLUDED.servers,
        updated_at = NOW()
    `, [
      lic.key,
      lic.owner || 'Customer',
      lic.tier || 'STANDARD',
      lic.status || 'ACTIVE',
      lic.max_servers || null,
      lic.ip_lock || false,
      lic.bound_ip || null,
      lic.created_at || new Date().toISOString(),
      lic.expires_at || null,
      lic.note || '',
      JSON.stringify(lic.servers || {})
    ]);
  } catch (err) {
    console.error('DB saveLicense error:', err.message);
  }
}

async function deleteLicenseDB(key) {
  try {
    await pool.query('DELETE FROM licenses WHERE key = $1', [key]);
  } catch (err) {
    console.error('DB deleteLicense error:', err.message);
  }
}

async function getBannedIpsDB() {
  try {
    const { rows } = await pool.query('SELECT * FROM banned_ips');
    const result = {};
    for (const row of rows) {
      result[row.ip] = {
        ip: row.ip,
        reason: row.reason,
        banned_at: row.banned_at ? row.banned_at.toISOString() : null
      };
    }
    return result;
  } catch (err) {
    console.error('DB getBannedIps error:', err.message);
    return {};
  }
}

async function banIpDB(ip, reason) {
  try {
    await pool.query(`
      INSERT INTO banned_ips (ip, reason, banned_at) VALUES ($1, $2, NOW())
      ON CONFLICT (ip) DO UPDATE SET reason = EXCLUDED.reason, banned_at = NOW()
    `, [ip.trim(), reason || 'Administrative ban']);
  } catch (err) {
    console.error('DB banIp error:', err.message);
  }
}

async function unbanIpDB(ip) {
  try {
    await pool.query('DELETE FROM banned_ips WHERE ip = $1', [ip.trim()]);
  } catch (err) {
    console.error('DB unbanIp error:', err.message);
  }
}

async function logValidation(entry) {
  try {
    const targetKey = (entry.key || 'UNKNOWN').trim();
    const targetIp = (entry.ip || '').trim();
    const targetPort = entry.port ? parseInt(entry.port, 10) : 25565;

    // Check if a record already exists for this same IP and same Port
    const { rows } = await pool.query(
      'SELECT id, count FROM validation_logs WHERE ip = $1 AND COALESCE(port, 25565) = $2 LIMIT 1',
      [targetIp, targetPort]
    );

    if (rows.length > 0) {
      // Update existing record: increment count and update latest activity
      await pool.query(`
        UPDATE validation_logs SET
          license_key = $1,
          valid = $2,
          server_name = COALESCE($3, server_name),
          product = COALESCE($4, product),
          reason = $5,
          owner = COALESCE($6, owner),
          count = count + 1,
          last_seen = NOW()
        WHERE id = $7
      `, [
        targetKey,
        entry.valid,
        entry.server_name || null,
        entry.product || null,
        entry.reason || null,
        entry.owner || null,
        rows[0].id
      ]);
    } else {
      // Insert new record
      await pool.query(`
        INSERT INTO validation_logs (license_key, valid, ip, port, server_name, product, reason, owner, count, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, NOW())
      `, [
        targetKey,
        entry.valid,
        targetIp,
        targetPort,
        entry.server_name || null,
        entry.product || null,
        entry.reason || null,
        entry.owner || null
      ]);
    }
  } catch (err) {
    // Non-critical: log silently
  }
}

async function getValidationLogsDB() {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM validation_logs ORDER BY last_seen DESC LIMIT 200'
    );
    // Deduplicate strictly by IP + Port: same IP same port will NEVER be shown again and again
    const nodeMap = new Map();
    for (const row of rows) {
      const nodeKey = `${row.ip || ''}:${row.port || 25565}`;
      if (!nodeMap.has(nodeKey)) {
        nodeMap.set(nodeKey, {
          key: row.license_key,
          valid: row.valid,
          ip: row.ip,
          port: row.port,
          server_name: row.server_name,
          product: row.product,
          reason: row.reason,
          owner: row.owner,
          count: row.count || 1,
          timestamp: row.last_seen ? row.last_seen.toISOString() : null
        });
      } else {
        const existing = nodeMap.get(nodeKey);
        existing.count = (existing.count || 1) + (row.count || 1);
        if (!existing.timestamp || (row.last_seen && new Date(row.last_seen) > new Date(existing.timestamp))) {
          existing.timestamp = row.last_seen ? row.last_seen.toISOString() : null;
          existing.valid = row.valid;
          if (row.license_key && row.license_key !== 'UNKNOWN') existing.key = row.license_key;
          if (row.reason) existing.reason = row.reason;
          if (row.server_name) existing.server_name = row.server_name;
          if (row.owner) existing.owner = row.owner;
        }
      }
    }
    return Array.from(nodeMap.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  } catch (err) {
    console.error('DB getLogs error:', err.message);
    return [];
  }
}

async function clearValidationLogsDB() {
  try {
    await pool.query('TRUNCATE validation_logs RESTART IDENTITY');
  } catch (err) {
    console.error('DB clearLogs error:', err.message);
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
app.post('/api/license/validate', validateLimiter, async (req, res) => {
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
  const bannedIps = await getBannedIpsDB();
  if (bannedIps[clientIp]) {
    const banInfo = bannedIps[clientIp];
    pushConsole('ERROR', 'SECURITY', `🚫 Blocked connection from banned IP ${clientIp} (${banInfo.reason || 'Blacklisted'})`);
    logValidation({ key: license_key || 'UNKNOWN', valid: false, reason: `IP ${clientIp} is BANNED (${banInfo.reason || 'Blacklisted'})`, ip: clientIp, port, product }).catch(() => {});
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
    logValidation({ key: license_key || 'UNKNOWN', valid: false, reason: 'Invalid or missing API key', ip: clientIp, port, product }).catch(() => {});
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

  const license = await getLicense(effectiveKey);

  if (!license) {
    pushConsole('WARN', 'LICENSE', `🔴 Key not found in database: "${effectiveKey}" from ${clientIp}`);
    logValidation({ key: effectiveKey, valid: false, reason: 'Key not found', ip: clientIp, port, product }).catch(() => {});
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
      await saveLicenseDB(license);
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
    logValidation({ key: effectiveKey, valid: false, reason: `Status: ${license.status}`, ip: clientIp, port, product }).catch(() => {});
    return res.status(200).json({
      valid: false,
      status: license.status,
      message: `License is currently ${license.status}. Contact administrator.`
    });
  }

  if (license.expires_at && new Date() > new Date(license.expires_at)) {
    pushConsole('WARN', 'LICENSE', `🔴 Denied ${clientIp}: key ${license.key} expired on ${license.expires_at}`);
    logValidation({ key: effectiveKey, valid: false, reason: 'License expired', ip: clientIp, port, product }).catch(() => {});
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
      await saveLicenseDB(license);
      pushConsole('INFO', 'LICENSE', `🔒 Key ${license.key} automatically bound to first IP: ${clientIp}`);
    } else if (license.bound_ip && license.bound_ip !== clientIp && license.bound_ip !== server_ip) {
      pushConsole('WARN', 'SECURITY', `🚫 IP mismatch for ${license.key}: bound=${license.bound_ip}, caller=${clientIp}`);
      logValidation({ key: effectiveKey, valid: false, reason: `IP mismatch (bound: ${license.bound_ip}, got: ${clientIp})`, ip: clientIp, port, product }).catch(() => {});
      return res.status(200).json({
        valid: false,
        status: 'IP_MISMATCH',
        message: `License is locked to IP ${license.bound_ip}.`
      });
    }
  }

  // 5. Server Count Limit check (null or 0 = unlimited)
  if (!license.servers) license.servers = {};
  const now = Date.now();
  const activeServerIds = Object.keys(license.servers).filter(sid => {
    const s = license.servers[sid];
    if (!s) return false;
    if (s.status === 'OFFLINE') return false;
    if (s.last_seen && (now - new Date(s.last_seen).getTime()) > 10 * 60 * 1000) return false;
    return true;
  });

  if (typeof license.max_servers === 'number' && license.max_servers > 0 && !license.servers[serverId] && activeServerIds.length >= license.max_servers) {
    pushConsole('WARN', 'LICENSE', `⚠️ Server limit exceeded for ${license.key}: ${activeServerIds.length}/${license.max_servers}`);
    logValidation({ key: effectiveKey, valid: false, reason: `Max server limit reached (${activeServerIds.length}/${license.max_servers})`, ip: clientIp, port, product }).catch(() => {});
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
  await saveLicenseDB(license);

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = generateSignature(license.key, license.status, timestamp);

  pushConsole('SUCCESS', 'LICENSE', `🟢 Server "${nodeName}" [${serverId}] (${product || 'rslogin'}, ${playersCount}/${maxCap} players) verified key ${license.key} [${license.owner}]`);
  logValidation({ key: effectiveKey, valid: true, owner: license.owner, ip: clientIp, port: port || 25565, server_name: nodeName, product }).catch(() => {});

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
app.post('/api/admin/console/exec', requireAdmin, async (req, res) => {
  const rawCommand = (req.body.command || '').trim();
  if (!rawCommand) {
    return res.status(400).json({ error: 'Command cannot be empty' });
  }

  pushConsole('CMD', 'CLI', `$ ${rawCommand}`);

  const parts = rawCommand.split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1);

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
    case 'stats': {
      const licenses = await getAllLicenses();
      const banned = await getBannedIpsDB();
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
    }

    case 'keys':
    case 'list': {
      const licenses = await getAllLicenses();
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
    }

    case 'gen':
    case 'create': {
      const owner = args[0] || 'Customer';
      const tier = (args[1] || 'PREMIUM').toUpperCase();
      const max_servers = parseInt(args[2]) || 3;
      const newKey = generateKeyString();
      const newLic = {
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
      await saveLicenseDB(newLic);
      output = `✓ License generated: ${newKey} for ${owner} [Tier: ${tier}, Max Servers: ${max_servers}]`;
      pushConsole('SUCCESS', 'CLI', output);
      break;
    }

    case 'activate': {
      const actKey = args[0];
      const actLic = actKey ? await getLicense(actKey) : null;
      if (!actLic) {
        output = `Error: License key "${actKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        actLic.status = 'ACTIVE';
        await saveLicenseDB(actLic);
        output = `✓ License ${actKey} is now ACTIVE.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;
    }

    case 'suspend': {
      const suspKey = args[0];
      const suspLic = suspKey ? await getLicense(suspKey) : null;
      if (!suspLic) {
        output = `Error: License key "${suspKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        suspLic.status = 'SUSPENDED';
        await saveLicenseDB(suspLic);
        output = `✓ License ${suspKey} is now SUSPENDED.`;
        pushConsole('WARN', 'CLI', output);
      }
      break;
    }

    case 'delete':
    case 'remove': {
      const delKey = args[0];
      const delLic = delKey ? await getLicense(delKey) : null;
      if (!delLic) {
        output = `Error: License key "${delKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        await deleteLicenseDB(delKey);
        output = `✓ License ${delKey} has been permanently deleted.`;
        pushConsole('WARN', 'CLI', output);
      }
      break;
    }

    case 'servers': {
      const licenses = await getAllLicenses();
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
    }

    case 'kick': {
      const kKey = args[0];
      const kServerId = args[1];
      const kLic = kKey ? await getLicense(kKey) : null;
      if (!kLic || !kServerId || !kLic.servers?.[kServerId]) {
        output = `Error: Invalid syntax or server not found. Usage: kick <license_key> <ip:port>`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        delete kLic.servers[kServerId];
        await saveLicenseDB(kLic);
        output = `✓ Server ${kServerId} disconnected from key ${kKey}.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;
    }

    case 'reset-ip': {
      const rKey = args[0];
      const rLic = rKey ? await getLicense(rKey) : null;
      if (!rLic) {
        output = `Error: License key "${rKey}" not found.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        rLic.bound_ip = null;
        await saveLicenseDB(rLic);
        output = `✓ Bound IP cleared for ${rKey}. Next connection will re-bind.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;
    }

    case 'ban': {
      const banIp = args[0];
      const banReason = args.slice(1).join(' ') || 'Banned via Console CLI';
      if (!banIp) {
        output = 'Error: IP address is required. Usage: ban <ip> [reason]';
        pushConsole('ERROR', 'CLI', output);
      } else {
        await banIpDB(banIp.trim(), banReason);
        output = `⛔ IP ${banIp.trim()} has been blacklisted. Reason: ${banReason}`;
        pushConsole('ERROR', 'CLI', output);
      }
      break;
    }

    case 'unban': {
      const unbanIp = args[0];
      const banned = await getBannedIpsDB();
      if (!unbanIp || !banned[unbanIp.trim()]) {
        output = `Error: IP "${unbanIp}" not found in blacklist.`;
        pushConsole('ERROR', 'CLI', output);
      } else {
        await unbanIpDB(unbanIp.trim());
        output = `✓ IP ${unbanIp.trim()} has been unbanned.`;
        pushConsole('SUCCESS', 'CLI', output);
      }
      break;
    }

    case 'banned': {
      const banned = await getBannedIpsDB();
      const bList = Object.values(banned);
      output = bList.length > 0
        ? bList.map(b => `• ${b.ip} | Reason: ${b.reason || '—'} | Date: ${new Date(b.banned_at).toLocaleString()}`).join('\n')
        : 'No IP addresses are currently blacklisted.';
      pushConsole('INFO', 'CLI', output);
      break;
    }

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
app.get('/api/admin/licenses', requireAdmin, async (req, res) => {
  const licenses = await getAllLicenses();
  const now = Date.now();
  for (const lic of Object.values(licenses)) {
    if (lic.servers) {
      let modified = false;
      for (const [sid, srv] of Object.entries(lic.servers)) {
        if (!srv) continue;
        const diffMs = now - new Date(srv.last_seen || 0).getTime();
        // Prune inactive server nodes after 15 minutes
        if (diffMs > 15 * 60 * 1000) {
          delete lic.servers[sid];
          modified = true;
        } else if (srv.status !== 'OFFLINE') {
          if (diffMs > 5 * 60 * 1000) {
            srv.status = 'OFFLINE';
          } else if (diffMs > 2.5 * 60 * 1000) {
            srv.status = 'AWAY';
          } else {
            srv.status = 'ONLINE';
          }
        }
      }
      if (modified) {
        saveLicenseDB(lic).catch(() => {});
      }
    }
  }
  res.json({
    count: Object.keys(licenses).length,
    licenses: Object.values(licenses)
  });
});

// Create custom license
app.post('/api/admin/licenses', requireAdmin, async (req, res) => {
  let { key, owner = 'Customer', tier = 'STANDARD', max_servers = 3, ip_lock = false, bound_ip = null, expires_at = null, note = '' } = req.body || {};
  if (!key || typeof key !== 'string' || !/^[A-Za-z0-9\-_]{3,64}$/.test(key.trim())) {
    return res.status(400).json({ error: 'License key must be 3-64 alphanumeric characters, dashes, or underscores' });
  }

  const cleanKey = key.trim();
  const existing = await getLicense(cleanKey);
  if (existing) {
    return res.status(409).json({ error: 'License key already exists' });
  }

  let cleanMaxServers = null;
  if (max_servers !== undefined && max_servers !== null && max_servers !== '' && max_servers !== 0 && max_servers !== '0') {
    const num = parseInt(max_servers, 10);
    cleanMaxServers = (num > 0) ? num : null;
  }

  const newLic = {
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

  await saveLicenseDB(newLic);
  pushConsole('SUCCESS', 'ADMIN', `✨ New license created: ${cleanKey} for ${newLic.owner} [Tier: ${newLic.tier}, Max: ${newLic.max_servers}]`);
  res.status(201).json({
    success: true,
    message: 'License created successfully',
    license: newLic
  });
});

// Update license info (supports renaming key and editing all properties)
async function handleUpdateLicense(req, res) {
  const key = req.params.key;
  const license = await getLicense(key);

  if (!license) {
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
    const conflict = await getLicense(cleanNewKey);
    if (conflict) {
      return res.status(409).json({ error: `License key "${cleanNewKey}" already exists` });
    }
    // Delete old key, will re-insert with new key below
    await deleteLicenseDB(key);
    license.key = cleanNewKey;
    targetKey = cleanNewKey;
    pushConsole('WARN', 'ADMIN', `🔑 License key renamed: "${key}" ➔ "${cleanNewKey}"`);
  }

  if (status) license.status = status;
  if (owner !== undefined) license.owner = String(owner || '').trim().slice(0, 100);
  if (tier !== undefined) license.tier = String(tier || 'STANDARD').trim().toUpperCase().slice(0, 30);
  if (max_servers !== undefined) {
    if (max_servers === null || max_servers === 0 || max_servers === '0' || max_servers === '' || String(max_servers).toLowerCase() === 'unlimited') {
      license.max_servers = null;
    } else {
      const num = parseInt(max_servers, 10);
      license.max_servers = (num > 0) ? num : null;
    }
  }
  if (ip_lock !== undefined) license.ip_lock = Boolean(ip_lock);
  if (bound_ip !== undefined) license.bound_ip = bound_ip ? String(bound_ip).trim().slice(0, 60) : null;
  if (expires_at !== undefined) license.expires_at = expires_at ? new Date(expires_at).toISOString() : null;
  if (note !== undefined) license.note = String(note || '').trim().slice(0, 255);

  license.updated_at = new Date().toISOString();
  await saveLicenseDB(license);

  pushConsole('INFO', 'ADMIN', `✏️ License ${targetKey} updated (Owner: ${license.owner}, Tier: ${license.tier}, Status: ${license.status})`);
  res.json({
    success: true,
    message: 'License updated successfully',
    license
  });
}

app.put('/api/admin/licenses/:key', requireAdmin, handleUpdateLicense);
app.patch('/api/admin/licenses/:key', requireAdmin, handleUpdateLicense);

// Reset IP lock on a key
app.post('/api/admin/licenses/:key/reset-ip', requireAdmin, async (req, res) => {
  const key = req.params.key;
  const license = await getLicense(key);

  if (!license) {
    return res.status(404).json({ error: 'License not found' });
  }

  license.bound_ip = null;
  await saveLicenseDB(license);
  pushConsole('INFO', 'ADMIN', `🔓 IP lock reset for key ${key}`);

  res.json({
    success: true,
    message: `IP lock for ${key} reset. Next connecting server IP will be bound.`
  });
});

// Remove a connected server from a license key
app.delete('/api/admin/licenses/:key/servers/:serverId', requireAdmin, async (req, res) => {
  const { key, serverId } = req.params;
  const license = await getLicense(key);

  if (!license) {
    return res.status(404).json({ error: 'License not found' });
  }

  if (license.servers && license.servers[serverId]) {
    delete license.servers[serverId];
    await saveLicenseDB(license);
    pushConsole('WARN', 'ADMIN', `🔌 Disconnected server node ${serverId} from key ${key}`);
    return res.json({
      success: true,
      message: `Server ${serverId} removed from license ${key}`
    });
  }

  res.status(404).json({ error: 'Server connection not found on this license' });
});

// Delete license permanently
app.delete('/api/admin/licenses/:key', requireAdmin, async (req, res) => {
  const key = req.params.key;
  const license = await getLicense(key);

  if (!license) {
    return res.status(404).json({ error: 'License not found' });
  }

  await deleteLicenseDB(key);
  pushConsole('WARN', 'ADMIN', `🗑️ Permanently deleted license ${key}`);

  res.json({
    success: true,
    message: `License ${key} deleted successfully`
  });
});

// ---------------------- Banned IPs Management ----------------------

// List all banned IPs
app.get('/api/admin/banned-ips', requireAdmin, async (req, res) => {
  const banned = await getBannedIpsDB();
  res.json({
    count: Object.keys(banned).length,
    banned_ips: Object.values(banned)
  });
});

// Ban an IP
app.post('/api/admin/banned-ips', requireAdmin, async (req, res) => {
  const { ip, reason = 'Administrative ban' } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }

  const cleanIp = ip.trim();
  await banIpDB(cleanIp, reason.trim());
  pushConsole('ERROR', 'SECURITY', `⛔ Admin blacklisted IP ${cleanIp} (Reason: ${reason})`);
  res.status(201).json({
    success: true,
    message: `IP ${cleanIp} has been banned.`,
    entry: { ip: cleanIp, reason: reason.trim(), banned_at: new Date().toISOString() }
  });
});

// Unban an IP
app.delete('/api/admin/banned-ips/:ip', requireAdmin, async (req, res) => {
  const cleanIp = req.params.ip.trim();
  const banned = await getBannedIpsDB();

  if (!banned[cleanIp]) {
    return res.status(404).json({ error: 'IP not found in ban list' });
  }

  await unbanIpDB(cleanIp);
  pushConsole('INFO', 'SECURITY', `🟢 Admin unbanned IP ${cleanIp}`);

  res.json({
    success: true,
    message: `IP ${cleanIp} has been unbanned.`
  });
});

// ---------------------- Audit Logs Management ----------------------

// View validation logs
app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  try {
    const logs = await getValidationLogsDB();
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Clear validation logs
app.delete('/api/admin/logs', requireAdmin, async (req, res) => {
  try {
    await clearValidationLogsDB();
    pushConsole('INFO', 'ADMIN', `🧹 Validation audit logs cleared by admin.`);
    res.json({ success: true, message: 'Audit logs cleared successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------- Start Server ----------------------
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`===============================================`);
    console.log(`🚀 RSLogin License Server online on port ${PORT}`);
    console.log(`📡 Health Check: http://localhost:${PORT}/health`);
    console.log(`🔑 Admin Auth: PROTECTED`);
    console.log(`===============================================`);
  });
}).catch((err) => {
  console.error('Fatal initialization error:', err);
  process.exit(1);
});

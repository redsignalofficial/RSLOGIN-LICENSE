const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'rslogin-admin-secret-change-me';
const CLIENT_API_KEY = process.env.CLIENT_API_KEY || 'rslogin-api-key-2026';
const SECRET_SIGN_KEY = process.env.SECRET_SIGN_KEY || 'rslogin-sign-key-2026';
const DATA_FILE = path.join(__dirname, 'data', 'licenses.json');
const LOGS_FILE = path.join(__dirname, 'data', 'logs.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Ensure data folder and files exist
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

function loadLicenses() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const content = fs.readFileSync(DATA_FILE, 'utf8');
      return JSON.parse(content);
    }
  } catch (err) {
    console.error('Error reading licenses file:', err.message);
  }
  // Default seeded licenses if file doesn't exist
  const defaultLicenses = {
    'RS-DEFAULT-PREMIUM-KEY-2026': {
      key: 'RS-DEFAULT-PREMIUM-KEY-2026',
      owner: 'ServerOwner',
      tier: 'PREMIUM',
      status: 'ACTIVE',
      ip_lock: false,
      bound_ip: null,
      max_servers: 5,
      created_at: new Date().toISOString(),
      expires_at: null,
      note: 'Default master key for testing'
    }
  };
  saveLicenses(defaultLicenses);
  return defaultLicenses;
}

function saveLicenses(licenses) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(licenses, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving licenses file:', err.message);
  }
}

function logValidation(entry) {
  try {
    let logs = [];
    if (fs.existsSync(LOGS_FILE)) {
      logs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
    }
    logs.unshift({
      ...entry,
      timestamp: new Date().toISOString()
    });
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
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ---------------------- License Validation Endpoint ----------------------
// Called by Minecraft Paper/Velocity plugins
app.post('/api/license/validate', (req, res) => {
  const { license_key, api_key, product, server_ip, port } = req.body;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || server_ip;

  const providedApiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '').trim() || api_key;
  if (CLIENT_API_KEY && providedApiKey !== CLIENT_API_KEY && providedApiKey !== ADMIN_SECRET) {
    logValidation({ key: license_key || 'UNKNOWN', valid: false, reason: 'Invalid or missing API key', ip: clientIp, product });
    return res.status(401).json({
      valid: false,
      status: 'UNAUTHORIZED_API_KEY',
      message: 'Invalid or missing API key. Set api-key in plugin config.'
    });
  }

  if (!license_key || typeof license_key !== 'string') {
    logValidation({ key: 'EMPTY', valid: false, reason: 'Missing license key', ip: clientIp, product });
    return res.status(400).json({
      valid: false,
      status: 'INVALID',
      message: 'License key is required.'
    });
  }

  const licenses = loadLicenses();
  const license = licenses[license_key.trim()];

  if (!license) {
    logValidation({ key: license_key, valid: false, reason: 'Key not found', ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: 'INVALID',
      message: 'License key does not exist or was revoked.'
    });
  }

  if (license.status !== 'ACTIVE') {
    logValidation({ key: license_key, valid: false, reason: `Status: ${license.status}`, ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: license.status,
      message: `License is currently ${license.status}. Contact administrator.`
    });
  }

  if (license.expires_at && new Date() > new Date(license.expires_at)) {
    logValidation({ key: license_key, valid: false, reason: 'License expired', ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: 'EXPIRED',
      message: 'License has expired.'
    });
  }

  // IP Lock check
  if (license.ip_lock) {
    if (!license.bound_ip && clientIp) {
      // Auto-bind to first IP used
      license.bound_ip = clientIp;
      licenses[license_key.trim()] = license;
      saveLicenses(licenses);
    } else if (license.bound_ip && license.bound_ip !== clientIp && license.bound_ip !== server_ip) {
      logValidation({ key: license_key, valid: false, reason: `IP mismatch (bound: ${license.bound_ip}, got: ${clientIp})`, ip: clientIp, product });
      return res.status(200).json({
        valid: false,
        status: 'IP_MISMATCH',
        message: `License is locked to IP ${license.bound_ip}.`
      });
    }
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = generateSignature(license.key, license.status, timestamp);

  // Track connected server instance for this key
  if (!license.servers) license.servers = {};
  const serverId = `${clientIp}:${port || 25565}`;
  license.servers[serverId] = {
    id: serverId,
    ip: clientIp,
    port: port || 25565,
    product: product || 'rslogin',
    first_seen: license.servers[serverId]?.first_seen || new Date().toISOString(),
    last_seen: new Date().toISOString()
  };
  licenses[license_key.trim()] = license;
  saveLicenses(licenses);

  logValidation({ key: license_key, valid: true, owner: license.owner, ip: clientIp, product });

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

// ---------------------- Admin Authentication Middleware ----------------------
function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (token !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Invalid admin secret' });
  }
  next();
}

// ---------------------- Admin License Management ----------------------

// List all licenses
app.get('/api/admin/licenses', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  res.json({
    count: Object.keys(licenses).length,
    licenses: Object.values(licenses)
  });
});

// Generate a new random license key
app.post('/api/admin/licenses/generate', requireAdmin, (req, res) => {
  const { owner = 'Customer', tier = 'PREMIUM', ip_lock = false, expires_at = null, note = '' } = req.body;
  const key = generateKeyString();
  const licenses = loadLicenses();

  licenses[key] = {
    key,
    owner,
    tier,
    status: 'ACTIVE',
    ip_lock: Boolean(ip_lock),
    bound_ip: null,
    created_at: new Date().toISOString(),
    expires_at,
    note
  };

  saveLicenses(licenses);
  res.status(201).json({
    success: true,
    message: 'License generated successfully',
    license: licenses[key]
  });
});

// Create custom license
app.post('/api/admin/licenses', requireAdmin, (req, res) => {
  const { key, owner = 'Customer', tier = 'STANDARD', ip_lock = false, bound_ip = null, expires_at = null, note = '' } = req.body;
  if (!key) {
    return res.status(400).json({ error: 'key is required' });
  }

  const licenses = loadLicenses();
  if (licenses[key]) {
    return res.status(409).json({ error: 'License key already exists' });
  }

  licenses[key] = {
    key: key.trim(),
    owner,
    tier,
    status: 'ACTIVE',
    ip_lock: Boolean(ip_lock),
    bound_ip,
    created_at: new Date().toISOString(),
    expires_at,
    note
  };

  saveLicenses(licenses);
  res.status(201).json({
    success: true,
    message: 'License created successfully',
    license: licenses[key]
  });
});

// Update license status or settings
app.put('/api/admin/licenses/:key', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  const key = req.params.key;

  if (!licenses[key]) {
    return res.status(404).json({ error: 'License not found' });
  }

  const { status, owner, tier, ip_lock, bound_ip, expires_at, note } = req.body;
  if (status) licenses[key].status = status;
  if (owner) licenses[key].owner = owner;
  if (tier) licenses[key].tier = tier;
  if (ip_lock !== undefined) licenses[key].ip_lock = Boolean(ip_lock);
  if (bound_ip !== undefined) licenses[key].bound_ip = bound_ip;
  if (expires_at !== undefined) licenses[key].expires_at = expires_at;
  if (note !== undefined) licenses[key].note = note;

  licenses[key].updated_at = new Date().toISOString();
  saveLicenses(licenses);

  res.json({
    success: true,
    message: 'License updated successfully',
    license: licenses[key]
  });
});

// Delete license
app.delete('/api/admin/licenses/:key', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  const key = req.params.key;

  if (!licenses[key]) {
    return res.status(404).json({ error: 'License not found' });
  }

  delete licenses[key];
  saveLicenses(licenses);

  res.json({
    success: true,
    message: `License ${key} deleted successfully`
  });
});

// View validation logs
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  try {
    let logs = [];
    if (fs.existsSync(LOGS_FILE)) {
      logs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
    }
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------- Start Server ----------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`🚀 RSLogin License Server running on port ${PORT}`);
  console.log(`📡 Health Check: http://localhost:${PORT}/health`);
  console.log(`🔑 Admin Secret: ${ADMIN_SECRET}`);
  console.log(`===============================================`);
});

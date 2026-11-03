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

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
      max_servers: 10,
      created_at: new Date().toISOString(),
      expires_at: null,
      note: 'Default master key for testing',
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
      logs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
    }
    logs.unshift({
      ...entry,
      timestamp: new Date().toISOString()
    });
    if (logs.length > 300) logs = logs.slice(0, 300);
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
app.post('/api/license/validate', (req, res) => {
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

  // 2. API Key authentication check
  const providedApiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '').trim() || api_key;
  if (!CLIENT_API_KEYS.has(providedApiKey) && providedApiKey !== ADMIN_SECRET) {
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

  // 5. Server Count Limit check
  if (!license.servers) license.servers = {};
  const existingServers = Object.keys(license.servers);
  if (license.max_servers && !license.servers[serverId] && existingServers.length >= license.max_servers) {
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
  if (token !== ADMIN_SECRET) {
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
  const { key, owner = 'Customer', tier = 'STANDARD', max_servers = 3, ip_lock = false, bound_ip = null, expires_at = null, note = '' } = req.body;
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
    max_servers: Number(max_servers) || 3,
    ip_lock: Boolean(ip_lock),
    bound_ip,
    created_at: new Date().toISOString(),
    expires_at,
    note,
    servers: {}
  };

  saveLicenses(licenses);
  pushConsole('SUCCESS', 'ADMIN', `✨ New license created: ${key} for ${owner} [Tier: ${tier}, Max: ${max_servers}]`);
  res.status(201).json({
    success: true,
    message: 'License created successfully',
    license: licenses[key]
  });
});

// Update license
app.put('/api/admin/licenses/:key', requireAdmin, (req, res) => {
  const licenses = loadLicenses();
  const key = req.params.key;

  if (!licenses[key]) {
    return res.status(404).json({ error: 'License not found' });
  }

  const { status, owner, tier, max_servers, ip_lock, bound_ip, expires_at, note } = req.body;
  if (status) licenses[key].status = status;
  if (owner) licenses[key].owner = owner;
  if (tier) licenses[key].tier = tier;
  if (max_servers !== undefined) licenses[key].max_servers = Number(max_servers);
  if (ip_lock !== undefined) licenses[key].ip_lock = Boolean(ip_lock);
  if (bound_ip !== undefined) licenses[key].bound_ip = bound_ip;
  if (expires_at !== undefined) licenses[key].expires_at = expires_at;
  if (note !== undefined) licenses[key].note = note;

  licenses[key].updated_at = new Date().toISOString();
  saveLicenses(licenses);

  pushConsole('INFO', 'ADMIN', `✏️ License ${key} updated (Status: ${licenses[key].status})`);
  res.json({
    success: true,
    message: 'License updated successfully',
    license: licenses[key]
  });
});

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
app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`🚀 RSLogin License Server online on port ${PORT}`);
  console.log(`📡 Health Check: http://localhost:${PORT}/health`);
  console.log(`🔑 Admin Auth: PROTECTED`);
  console.log(`===============================================`);
});

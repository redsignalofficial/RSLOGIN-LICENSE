const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 10000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'rslogin-admin-secret-change-me';
const CLIENT_API_KEY = process.env.CLIENT_API_KEY || 'rslogin-api-key-2026';
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
  try {
    if (fs.existsSync(DATA_FILE)) {
      const content = fs.readFileSync(DATA_FILE, 'utf8');
      return JSON.parse(content);
    }
  } catch (err) {
    console.error('Error reading licenses file:', err.message);
  }
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
      note: 'Default master key for testing',
      servers: {}
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

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = (forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress) || '127.0.0.1';
  return ip.replace(/^.*:/, '');
}

// ---------------------- Remote Minecraft Server Consoles ----------------------
const activeMinecraftServers = new Map();
const adminWsClients = new Set();
const MAX_MC_LOGS = 500;

function pushMinecraftLog(serverId, line) {
  const mc = activeMinecraftServers.get(serverId);
  if (!mc) return;

  const now = new Date();
  const entry = {
    id: Date.now() + Math.random(),
    time: now.toLocaleTimeString(),
    line: String(line)
  };
  mc.logs.push(entry);
  if (mc.logs.length > MAX_MC_LOGS) mc.logs.shift();

  const packet = JSON.stringify({
    type: 'MC_LOG',
    serverId: serverId,
    log: entry
  });

  for (const client of adminWsClients) {
    if (client.readyState === 1 && (!client.subscribedServerId || client.subscribedServerId === serverId)) {
      try { client.send(packet); } catch (e) {}
    }
  }
}

function broadcastMinecraftServersUpdate() {
  const serversList = getMinecraftServersSummary();
  const packet = JSON.stringify({
    type: 'MC_SERVERS_UPDATE',
    servers: serversList
  });
  for (const client of adminWsClients) {
    if (client.readyState === 1) {
      try { client.send(packet); } catch (e) {}
    }
  }
}

function getMinecraftServersSummary() {
  const list = [];
  for (const [id, s] of activeMinecraftServers.entries()) {
    list.push({
      serverId: s.serverId,
      serverName: s.serverName,
      platform: s.platform,
      ip: s.ip,
      port: s.port,
      licenseKey: s.licenseKey,
      connectedAt: s.connectedAt,
      lastSeen: s.lastSeen,
      telemetry: s.telemetry || { tps: 20.0, ramUsed: 0, ramMax: 0, players: 0, maxPlayers: 0 }
    });
  }
  return list;
}

const wss = new WebSocketServer({ noServer: true });

function handlePluginWebSocket(ws, req, url) {
  let serverId = null;
  let licenseKey = null;

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'HANDSHAKE') {
        licenseKey = msg.licenseKey;
        const licenses = loadLicenses();
        const license = licenses[licenseKey];
        if (!license || license.status !== 'ACTIVE') {
          ws.send(JSON.stringify({ type: 'ERROR', message: 'License key is invalid or suspended' }));
          ws.close(4001, 'Invalid License');
          return;
        }

        const clientIp = getClientIp(req);
        const banned = loadBannedIps();
        if (banned[clientIp]) {
          ws.send(JSON.stringify({ type: 'ERROR', message: 'IP is blacklisted' }));
          ws.close(4003, 'IP Blacklisted');
          return;
        }

        serverId = msg.serverId || `mc-${Date.now()}`;
        const serverName = msg.serverName || `${(msg.platform || 'minecraft').toUpperCase()} Server (:${msg.port || 25565})`;

        activeMinecraftServers.set(serverId, {
          serverId,
          serverName,
          platform: msg.platform || 'paper',
          ip: msg.ip || clientIp,
          port: msg.port || 25565,
          licenseKey,
          connectedAt: new Date().toISOString(),
          lastSeen: Date.now(),
          telemetry: { tps: 20.0, ramUsed: 0, ramMax: 0, players: 0, maxPlayers: 0 },
          logs: [],
          ws
        });

        pushConsole('SUCCESS', 'REMOTE', `🟢 Minecraft remote console connected: ${serverName} [${serverId}]`);
        broadcastMinecraftServersUpdate();

        ws.send(JSON.stringify({ type: 'HANDSHAKE_ACK', status: 'CONNECTED', serverId }));
      } else if (msg.type === 'LOG') {
        if (!serverId) return;
        const s = activeMinecraftServers.get(serverId);
        if (s) {
          s.lastSeen = Date.now();
          const content = msg.lines || msg.line || '';
          const lines = content.split('\n');
          for (const line of lines) {
            if (line.trim()) pushMinecraftLog(serverId, line);
          }
        }
      } else if (msg.type === 'TELEMETRY') {
        if (!serverId) return;
        const s = activeMinecraftServers.get(serverId);
        if (s) {
          s.lastSeen = Date.now();
          s.telemetry = {
            tps: typeof msg.tps === 'number' ? msg.tps : 20.0,
            ramUsed: msg.ramUsed || 0,
            ramMax: msg.ramMax || 0,
            players: msg.players || 0,
            maxPlayers: msg.maxPlayers || 0
          };
          broadcastMinecraftServersUpdate();
        }
      } else if (msg.type === 'CMD_ACK') {
        pushConsole('INFO', 'REMOTE', `Command ACK from [${serverId}]: ${msg.cmdId} (${msg.status})`);
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    if (serverId && activeMinecraftServers.has(serverId)) {
      const s = activeMinecraftServers.get(serverId);
      pushConsole('WARN', 'REMOTE', `🔴 Minecraft remote console disconnected: ${s.serverName} [${serverId}]`);
      activeMinecraftServers.delete(serverId);
      broadcastMinecraftServersUpdate();
    }
  });

  ws.on('error', () => {
    if (serverId && activeMinecraftServers.has(serverId)) {
      activeMinecraftServers.delete(serverId);
      broadcastMinecraftServersUpdate();
    }
  });
}

function handleAdminWebSocket(ws, req, url) {
  adminWsClients.add(ws);
  ws.subscribedServerId = url.searchParams.get('serverId') || null;

  try {
    ws.send(JSON.stringify({
      type: 'MC_SERVERS_UPDATE',
      servers: getMinecraftServersSummary()
    }));

    if (ws.subscribedServerId && activeMinecraftServers.has(ws.subscribedServerId)) {
      const s = activeMinecraftServers.get(ws.subscribedServerId);
      ws.send(JSON.stringify({
        type: 'MC_LOG_HISTORY',
        serverId: ws.subscribedServerId,
        logs: s.logs
      }));
    }
  } catch (e) {}

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'SUBSCRIBE') {
        ws.subscribedServerId = msg.serverId;
        if (msg.serverId && activeMinecraftServers.has(msg.serverId)) {
          const s = activeMinecraftServers.get(msg.serverId);
          ws.send(JSON.stringify({
            type: 'MC_LOG_HISTORY',
            serverId: msg.serverId,
            logs: s.logs
          }));
        }
      } else if (msg.type === 'EXEC_COMMAND') {
        const { serverId, command } = msg;
        if (!serverId || !command) return;
        const mc = activeMinecraftServers.get(serverId);
        if (!mc || mc.ws.readyState !== 1) {
          ws.send(JSON.stringify({ type: 'ERROR', message: 'Minecraft server is offline' }));
          return;
        }

        mc.ws.send(JSON.stringify({
          type: 'EXEC_COMMAND',
          cmdId: 'cmd-' + Date.now(),
          command: command.trim()
        }));
        pushMinecraftLog(serverId, `> ${command.trim()}`);
        pushConsole('CMD', 'MINECRAFT', `Admin sent command to [${mc.serverName}]: ${command.trim()}`);
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    adminWsClients.delete(ws);
  });
}

server.on('upgrade', (request, socket, head) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    if (pathname === '/ws/server') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        handlePluginWebSocket(ws, request, url);
      });
    } else if (pathname === '/ws/admin') {
      const token = url.searchParams.get('token') || (request.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      if (token !== ADMIN_SECRET) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      wss.handleUpgrade(request, socket, head, (ws) => {
        handleAdminWebSocket(ws, request, url);
      });
    } else {
      socket.destroy();
    }
  } catch (err) {
    socket.destroy();
  }
});

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
  const { license_key, api_key, product, server_ip, port } = req.body;
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
  if (CLIENT_API_KEY && providedApiKey !== CLIENT_API_KEY && providedApiKey !== ADMIN_SECRET) {
    pushConsole('WARN', 'SECURITY', `⚠️ Unauthorized API key attempt from ${clientIp} (Product: ${product || 'unknown'})`);
    logValidation({ key: license_key || 'UNKNOWN', valid: false, reason: 'Invalid or missing API key', ip: clientIp, product });
    return res.status(401).json({
      valid: false,
      status: 'UNAUTHORIZED_API_KEY',
      message: 'Invalid or missing API key. Set api-key in plugin config.'
    });
  }

  // 3. License key presence
  if (!license_key || typeof license_key !== 'string') {
    pushConsole('WARN', 'LICENSE', `⚠️ Empty license key provided by ${clientIp}`);
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
    pushConsole('WARN', 'LICENSE', `🔴 Key not found in database: "${license_key}" from ${clientIp}`);
    logValidation({ key: license_key, valid: false, reason: 'Key not found', ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: 'INVALID',
      message: 'License key does not exist or was revoked.'
    });
  }

  if (license.status !== 'ACTIVE') {
    pushConsole('WARN', 'LICENSE', `🔴 Denied ${clientIp}: key ${license.key} status is ${license.status}`);
    logValidation({ key: license_key, valid: false, reason: `Status: ${license.status}`, ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: license.status,
      message: `License is currently ${license.status}. Contact administrator.`
    });
  }

  if (license.expires_at && new Date() > new Date(license.expires_at)) {
    pushConsole('WARN', 'LICENSE', `🔴 Denied ${clientIp}: key ${license.key} expired on ${license.expires_at}`);
    logValidation({ key: license_key, valid: false, reason: 'License expired', ip: clientIp, product });
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
      licenses[license_key.trim()] = license;
      saveLicenses(licenses);
      pushConsole('INFO', 'LICENSE', `🔒 Key ${license.key} automatically bound to first IP: ${clientIp}`);
    } else if (license.bound_ip && license.bound_ip !== clientIp && license.bound_ip !== server_ip) {
      pushConsole('WARN', 'SECURITY', `🚫 IP mismatch for ${license.key}: bound=${license.bound_ip}, caller=${clientIp}`);
      logValidation({ key: license_key, valid: false, reason: `IP mismatch (bound: ${license.bound_ip}, got: ${clientIp})`, ip: clientIp, product });
      return res.status(200).json({
        valid: false,
        status: 'IP_MISMATCH',
        message: `License is locked to IP ${license.bound_ip}.`
      });
    }
  }

  // 5. Server Count Limit check
  if (!license.servers) license.servers = {};
  const serverId = `${clientIp}:${port || 25565}`;
  const existingServers = Object.keys(license.servers);
  if (license.max_servers && !license.servers[serverId] && existingServers.length >= license.max_servers) {
    pushConsole('WARN', 'LICENSE', `⚠️ Server limit exceeded for ${license.key}: ${existingServers.length}/${license.max_servers}`);
    logValidation({ key: license_key, valid: false, reason: `Max server limit reached (${existingServers.length}/${license.max_servers})`, ip: clientIp, product });
    return res.status(200).json({
      valid: false,
      status: 'SERVER_LIMIT_REACHED',
      message: `License server limit reached (${license.max_servers} max servers). Remove an unused server from the dashboard first.`
    });
  }

  // 6. Record connected server
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

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = generateSignature(license.key, license.status, timestamp);

  pushConsole('SUCCESS', 'LICENSE', `🟢 Server ${serverId} (${product || 'rslogin'}) validated key ${license.key} [${license.owner}]`);
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
        '  mc list                        - View live connected Minecraft servers (TPS, RAM, Players)',
        '  mc exec <serverId> <command>   - Execute console command on a Minecraft server',
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

    case 'mc':
      const mcSub = args[0] ? args[0].toLowerCase() : 'list';
      if (mcSub === 'list') {
        const mcServers = getMinecraftServersSummary();
        if (mcServers.length === 0) {
          output = 'No Minecraft servers currently connected via remote console.';
        } else {
          output = ['=== Connected Minecraft Servers (' + mcServers.length + ') ===']
            .concat(mcServers.map(s => `• [${s.serverId}] ${s.serverName} | ${s.ip}:${s.port} | TPS: ${s.telemetry.tps} | RAM: ${s.telemetry.ramUsed}/${s.telemetry.ramMax}MB | Players: ${s.telemetry.players}/${s.telemetry.maxPlayers}`))
            .join('\n');
        }
        pushConsole('INFO', 'CLI', output);
      } else if (mcSub === 'exec' || mcSub === 'cmd') {
        const targetId = args[1];
        const mcCmd = args.slice(2).join(' ');
        if (!targetId || !mcCmd) {
          output = 'Usage: mc exec <serverId> <minecraft command>';
          pushConsole('ERROR', 'CLI', output);
        } else {
          const mc = activeMinecraftServers.get(targetId);
          if (!mc || mc.ws.readyState !== 1) {
            output = `Error: Minecraft server "${targetId}" is not connected.`;
            pushConsole('ERROR', 'CLI', output);
          } else {
            mc.ws.send(JSON.stringify({ type: 'EXEC_COMMAND', cmdId: 'cmd-' + Date.now(), command: mcCmd }));
            pushMinecraftLog(targetId, `> ${mcCmd}`);
            output = `Dispatched to [${mc.serverName}]: ${mcCmd}`;
            pushConsole('SUCCESS', 'CLI', output);
          }
        }
      } else {
        output = 'Unknown mc subcommand. Usage: mc list | mc exec <serverId> <command>';
        pushConsole('WARN', 'CLI', output);
      }
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

// ---------------------- Remote Minecraft Consoles REST API ----------------------

// Get live connected Minecraft servers
app.get('/api/admin/minecraft/servers', requireAdmin, (req, res) => {
  res.json({ servers: getMinecraftServersSummary() });
});

// Get buffered logs of a specific Minecraft server
app.get('/api/admin/minecraft/servers/:serverId/logs', requireAdmin, (req, res) => {
  const mc = activeMinecraftServers.get(req.params.serverId);
  if (!mc) {
    return res.status(404).json({ error: 'Server not connected or offline' });
  }
  res.json({
    serverId: mc.serverId,
    serverName: mc.serverName,
    platform: mc.platform,
    telemetry: mc.telemetry,
    logs: mc.logs
  });
});

// Execute command on a specific Minecraft server
app.post('/api/admin/minecraft/servers/:serverId/exec', requireAdmin, (req, res) => {
  const { command } = req.body;
  if (!command || !command.trim()) {
    return res.status(400).json({ error: 'Command cannot be empty' });
  }

  const mc = activeMinecraftServers.get(req.params.serverId);
  if (!mc || mc.ws.readyState !== 1) {
    return res.status(404).json({ error: 'Minecraft server is offline or unreachable' });
  }

  const cmd = command.trim();
  mc.ws.send(JSON.stringify({
    type: 'EXEC_COMMAND',
    cmdId: 'cmd-' + Date.now(),
    command: cmd
  }));

  pushMinecraftLog(mc.serverId, `> ${cmd}`);
  pushConsole('CMD', 'MINECRAFT', `Admin executed on [${mc.serverName}]: ${cmd}`);

  res.json({
    success: true,
    message: `Command "${cmd}" sent to ${mc.serverName}.`
  });
});

// Disconnect a Minecraft server
app.post('/api/admin/minecraft/servers/:serverId/disconnect', requireAdmin, (req, res) => {
  const mc = activeMinecraftServers.get(req.params.serverId);
  if (!mc) {
    return res.status(404).json({ error: 'Minecraft server is not connected' });
  }

  try {
    mc.ws.close(4000, 'Disconnected by Admin');
  } catch (e) {}
  activeMinecraftServers.delete(req.params.serverId);
  broadcastMinecraftServersUpdate();
  pushConsole('WARN', 'REMOTE', `Admin forcefully disconnected [${mc.serverName}]`);

  res.json({
    success: true,
    message: `Server ${mc.serverName} disconnected.`
  });
});

// ---------------------- Start Server ----------------------
server.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`🚀 RSLogin License Server online on port ${PORT}`);
  console.log(`📡 Health Check: http://localhost:${PORT}/health`);
  console.log(`🔑 Admin Auth: PROTECTED`);
  console.log(`🎮 Remote Console WebSocket: ws://localhost:${PORT}/ws/server`);
  console.log(`===============================================`);
});

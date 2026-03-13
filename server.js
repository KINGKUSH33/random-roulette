const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// ── Ensure data directory exists ─────────────
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

// ── Load/save user accounts ──────────────────
let users = {};
if (fs.existsSync(USERS_FILE)) {
  try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { users = {}; }
}
function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ── Password hashing ────────────────────────
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const result = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return result === hash;
}

// ── Generate session token ───────────────────
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}
const sessions = new Map(); // token -> email

// ── Serve static files ──────────────────────
const MIME = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const server = http.createServer((req, res) => {
  const urlPath = req.url.split('?')[0];

  // ── CORS for local dev ─────────────────────
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // ── API Routes ───────────────────────────
  if (urlPath === '/api/signup' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e4) req.destroy(); });
    req.on('end', () => {
      try {
        const { email, password, name, gender } = JSON.parse(body);
        if (!email || !password || !name) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Email, password, and name are required' }));
        }
        const emailLower = String(email).toLowerCase().trim();
        if (users[emailLower]) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Account already exists. Try logging in.' }));
        }
        const { salt, hash } = hashPassword(String(password));
        users[emailLower] = {
          name: String(name).substring(0, 24),
          email: emailLower,
          gender: gender === 'female' ? 'female' : 'male',
          tokens: 0,
          freeSecondsUsed: 0,
          totalSpent: 0,
          createdAt: new Date().toISOString(),
          salt, hash
        };
        saveUsers();
        const token = generateToken();
        sessions.set(token, emailLower);
        const safe = { ...users[emailLower] };
        delete safe.salt; delete safe.hash;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, token, user: safe }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  if (urlPath === '/api/login' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e4) req.destroy(); });
    req.on('end', () => {
      try {
        const { email, password } = JSON.parse(body);
        const emailLower = String(email || '').toLowerCase().trim();
        const account = users[emailLower];
        if (!account || !verifyPassword(String(password), account.salt, account.hash)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Invalid email or password' }));
        }
        const token = generateToken();
        sessions.set(token, emailLower);
        const safe = { ...account };
        delete safe.salt; delete safe.hash;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, token, user: safe }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  if (urlPath === '/api/me' && req.method === 'GET') {
    const authToken = (req.headers['authorization'] || '').replace('Bearer ', '');
    const emailLower = sessions.get(authToken);
    if (!emailLower || !users[emailLower]) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not logged in' }));
    }
    const safe = { ...users[emailLower] };
    delete safe.salt; delete safe.hash;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, user: safe }));
  }

  if (urlPath === '/api/buy-tokens' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e4) req.destroy(); });
    req.on('end', () => {
      try {
        const authToken = (req.headers['authorization'] || '').replace('Bearer ', '');
        const emailLower = sessions.get(authToken);
        if (!emailLower || !users[emailLower]) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Not logged in' }));
        }
        const { amount, price } = JSON.parse(body);
        // In production: verify payment via Stripe/PayPal here before crediting tokens
        const validPacks = { 100: 4.99, 500: 19.99, 1500: 49.99 };
        if (!validPacks[amount]) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Invalid token pack' }));
        }
        users[emailLower].tokens += amount;
        users[emailLower].totalSpent += validPacks[amount];
        saveUsers();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, tokens: users[emailLower].tokens, totalSpent: users[emailLower].totalSpent }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  if (urlPath === '/api/stats' && req.method === 'GET') {
    // Admin stats endpoint — shows total users + revenue
    const totalUsers = Object.keys(users).length;
    const totalRevenue = Object.values(users).reduce((sum, u) => sum + (u.totalSpent || 0), 0);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ totalUsers, totalRevenue: totalRevenue.toFixed(2), onlineNow: allClients.size }));
  }

  // ── Serve static files ──────────────────────
  let filePath;
  if (urlPath === '/' || urlPath === '/index.html') {
    filePath = path.join(__dirname, 'public', 'index.html');
  } else {
    // Sanitize path to prevent directory traversal
    const safePath = path.normalize(urlPath).replace(/^(\.\.[\/\\])+/, '');
    filePath = path.join(__dirname, 'public', safePath);
  }

  // Ensure we're not serving files outside the public directory
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

// ── WebSocket signaling server ───────────────
const wss = new WebSocketServer({ server });

// Waiting queue: users looking for a partner
const waitingQueue = [];
// Active pairs: maps a socket to its partner socket
const pairs = new Map();
// Lobby chat: all connected sockets for broadcast
const allClients = new Set();
// Track user info
const clientInfo = new Map();

wss.on('connection', (ws) => {
  allClients.add(ws);
  
  // Send current online count to new client
  broadcastOnlineCount();

  ws.on('message', (raw) => {
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return;
    }

    switch (data.type) {
      // ── User registers with their name ──
      case 'register': {
        const name = String(data.name || 'Anon').substring(0, 24);
        clientInfo.set(ws, { name });
        break;
      }

      // ── Lobby chat message (broadcast to everyone) ──
      case 'lobby-chat': {
        const info = clientInfo.get(ws) || { name: 'Anon' };
        const text = String(data.text || '').substring(0, 200);
        if (!text) break;
        const payload = JSON.stringify({
          type: 'lobby-chat',
          name: info.name,
          text,
        });
        for (const client of allClients) {
          if (client !== ws && client.readyState === 1) {
            client.send(payload);
          }
        }
        break;
      }

      // ── Find a random partner ──
      case 'find': {
        // Remove from any existing pair
        unpair(ws);
        // Remove if already in queue
        const idx = waitingQueue.indexOf(ws);
        if (idx !== -1) waitingQueue.splice(idx, 1);

        if (waitingQueue.length > 0) {
          // Match with first waiting user
          const partner = waitingQueue.shift();
          if (partner.readyState !== 1) {
            // Partner disconnected, put self in queue
            waitingQueue.push(ws);
            break;
          }
          pairs.set(ws, partner);
          pairs.set(partner, ws);
          // Tell the first user (partner) to create offer — they are the caller
          partner.send(JSON.stringify({ type: 'ready' }));
        } else {
          // No one waiting, join queue
          waitingQueue.push(ws);
        }
        break;
      }

      // ── WebRTC signaling: offer/answer/candidate → forward to partner ──
      case 'offer':
      case 'answer':
      case 'candidate': {
        const partner = pairs.get(ws);
        if (partner && partner.readyState === 1) {
          partner.send(JSON.stringify(data));
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    allClients.delete(ws);
    clientInfo.delete(ws);
    // Remove from waiting queue
    const idx = waitingQueue.indexOf(ws);
    if (idx !== -1) waitingQueue.splice(idx, 1);
    // Notify partner
    unpair(ws);
    broadcastOnlineCount();
  });
});

function unpair(ws) {
  const partner = pairs.get(ws);
  if (partner) {
    pairs.delete(ws);
    pairs.delete(partner);
    if (partner.readyState === 1) {
      partner.send(JSON.stringify({ type: 'partner-left' }));
    }
  }
}

function broadcastOnlineCount() {
  const count = allClients.size;
  const payload = JSON.stringify({ type: 'online-count', count });
  for (const client of allClients) {
    if (client.readyState === 1) {
      client.send(payload);
    }
  }
}

server.listen(PORT, () => {
  console.log(`\n  🚀 Random Roulette server running!`);
  console.log(`  ➜ Local:   http://localhost:${PORT}`);
  console.log(`  ➜ Share your public IP or deploy to go live\n`);
});

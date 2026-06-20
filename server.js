const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_jwt_secret_logdash';
const DB_PATH = path.join(__dirname, 'data.db');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error('CORS: origine non autorisee'));
  },
  credentials: true,
}));

app.set('trust proxy', 1);

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5, message: { error: 'Trop de tentatives.' }, standardHeaders: true, legacyHeaders: false, skipSuccessfulRequests: true });
const ingestLimiter = rateLimit({ windowMs: 60*1000, max: 300, message: { error: 'Trop de requetes.' }, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 15*60*1000, max: 500, message: { error: 'Trop de requetes.' }, standardHeaders: true, legacyHeaders: false });

app.use('/api/', apiLimiter);
app.use('/api/auth/login', loginLimiter);
app.use('/api/ingest', ingestLimiter);

const loginFailures = new Map();
const MAX_FAILURES = 10;
const LOCKOUT_MS = 15 * 60 * 1000;

function checkLockout(ip) {
  const entry = loginFailures.get(ip);
  if (!entry) return false;
  if (Date.now() < entry.unlockedAt) return true;
  loginFailures.delete(ip);
  return false;
}

function recordFailure(ip) {
  const entry = loginFailures.get(ip) || { count: 0, unlockedAt: 0 };
  entry.count++;
  if (entry.count >= MAX_FAILURES) { entry.unlockedAt = Date.now() + LOCKOUT_MS; entry.count = 0; }
  loginFailures.set(ip, entry);
}

function clearFailures(ip) { loginFailures.delete(ip); }

function sanitizeStr(val, maxLen = 1000) {
  if (typeof val !== 'string') return val;
  return val.replace(/<[^>]*>/g, '').slice(0, maxLen);
}

app.use(express.json({ limit: '512kb' }));
app.use(express.static(path.join(__dirname, 'public')));

let db;
let SQL;

async function initDB() {
  SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'viewer', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL, site_name TEXT NOT NULL, site_url TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_used DATETIME, active INTEGER DEFAULT 1)`);
  db.run(`CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, site_name TEXT NOT NULL, level TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL, meta TEXT, source TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_site ON logs(site_name)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)`);
  saveDB();
  console.log('[DB] Base de donnees initialisee');
}

function saveDB() { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); }
function runQuery(sql, params = []) { db.run(sql, params); saveDB(); }
function getQuery(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Non authentifie' });
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide ou expire' }); }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.admin.role !== 'admin') return res.status(403).json({ error: 'Acces refuse' });
    next();
  });
}

// Cles statiques persistantes (env var STATIC_KEYS="NomSite:cle,AutreSite:autrecle")
// Cles hardcodees (persistantes sans env var)
const HARDCODED_KEYS = {
  'boulangerie-zrevents06-key-2024': 'Boulangerie ZREvents06',
};
const STATIC_KEYS = { ...HARDCODED_KEYS };
(process.env.STATIC_KEYS || '').split(',').forEach(pair => {
  const idx = pair.indexOf(':');
  if (idx > 0) {
    const name = pair.slice(0, idx).trim();
    const key  = pair.slice(idx + 1).trim();
    if (name && key) STATIC_KEYS[key] = name;
  }
});
console.log('[STATIC_KEYS] Cles chargees:', Object.keys(STATIC_KEYS).length, '| Noms:', Object.values(STATIC_KEYS).join(', ') || '(aucune)');

function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'Cle API manquante' });
  if (STATIC_KEYS[key]) {
    req.site = { id: null, site_name: STATIC_KEYS[key], site_url: null };
    return next();
  }
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const rows = getQuery('SELECT * FROM api_keys WHERE key_hash = ? AND active = 1', [keyHash]);
  if (rows.length === 0) return res.status(401).json({ error: 'Cle API invalide' });
  req.site = rows[0];
  runQuery('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?', [rows[0].id]);
  next();
}

app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (checkLockout(ip)) return res.status(429).json({ error: 'Compte temporairement bloque.' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Champs invalides' });
  const rows = getQuery('SELECT * FROM admins WHERE username = ?', [username.slice(0, 64)]);
  const dummyHash = '$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
  const hash = rows.length > 0 ? rows[0].password_hash : dummyHash;
  const valid = await bcrypt.compare(password, hash);
  if (rows.length === 0 || !valid) { recordFailure(ip); return res.status(401).json({ error: 'Identifiants incorrects' }); }
  clearFailures(ip);
  const admin = rows[0];
  const token = jwt.sign({ id: admin.id, username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: admin.username, role: admin.role });
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ username: req.admin.username, role: req.admin.role }));

app.post('/api/setup', async (req, res) => {
  const { secret, username, password } = req.body;
  if (!secret || secret !== process.env.SETUP_SECRET) return res.status(403).json({ error: 'Secret invalide' });
  const existing = getQuery('SELECT id FROM admins LIMIT 1');
  if (existing.length > 0) return res.status(400).json({ error: 'Deja configure' });
  if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Nom invalide' });
  if (!password || typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Mot de passe trop court' });
  const hash = await bcrypt.hash(password, 12);
  runQuery('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, 'admin']);
  res.json({ ok: true });
});

app.post('/api/ingest', requireApiKey, (req, res) => {
  const { level = 'info', message, meta, source } = req.body;
  if (!message || typeof message !== 'string') return res.status(400).json({ error: 'message requis' });
  const validLevels = ['debug', 'info', 'warn', 'error', 'critical'];
  const safeLevel = validLevels.includes(level) ? level : 'info';
  const safeMessage = sanitizeStr(message, 2000);
  const safeSource = source ? sanitizeStr(String(source), 200) : null;
  const metaStr = meta ? (typeof meta === 'string' ? meta.slice(0, 5000) : JSON.stringify(meta).slice(0, 5000)) : null;
  runQuery('INSERT INTO logs (site_name, level, message, meta, source) VALUES (?, ?, ?, ?, ?)', [req.site.site_name, safeLevel, safeMessage, metaStr, safeSource]);
  res.json({ ok: true, site: req.site.site_name });
});

app.post('/api/ingest/batch', requireApiKey, (req, res) => {
  const { logs } = req.body;
  if (!Array.isArray(logs)) return res.status(400).json({ error: 'logs doit etre un tableau' });
  const validLevels = ['debug', 'info', 'warn', 'error', 'critical'];
  let inserted = 0;
  for (const log of logs.slice(0, 100)) {
    const { level = 'info', message, meta, source } = log;
    if (!message || typeof message !== 'string') continue;
    const safeLevel = validLevels.includes(level) ? level : 'info';
    const metaStr = meta ? JSON.stringify(meta).slice(0, 5000) : null;
    db.run('INSERT INTO logs (site_name, level, message, meta, source) VALUES (?, ?, ?, ?, ?)', [req.site.site_name, safeLevel, sanitizeStr(message, 2000), metaStr, source ? sanitizeStr(String(source), 200) : null]);
    inserted++;
  }
  saveDB();
  res.json({ ok: true, inserted });
});

app.get('/api/logs', requireAuth, (req, res) => {
  const { site, level, search, from, to, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  let where = [], params = [];
  if (site && site !== 'all') { where.push('site_name = ?'); params.push(site); }
  if (level && level !== 'all') { where.push('level = ?'); params.push(level); }
  if (search) { where.push('(message LIKE ? OR meta LIKE ?)'); params.push(`%${search}%`, `%${search}%`); }
  if (from) { where.push('timestamp >= ?'); params.push(from); }
  if (to) { where.push('timestamp <= ?'); params.push(to); }
  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = getQuery(`SELECT COUNT(*) as total FROM logs ${whereClause}`, params)[0]?.total || 0;
  const rows = getQuery(`SELECT * FROM logs ${whereClause} ORDER BY timestamp DESC LIMIT ? OFFSET ?`, [...params, parseInt(limit), offset]);
  res.json({ logs: rows, total, page: parseInt(page), limit: parseInt(limit) });
});

app.delete('/api/logs/:id', requireAdmin, (req, res) => { runQuery('DELETE FROM logs WHERE id = ?', [req.params.id]); res.json({ ok: true }); });
app.delete('/api/logs', requireAdmin, (req, res) => {
  const { site } = req.query;
  site ? runQuery('DELETE FROM logs WHERE site_name = ?', [site]) : runQuery('DELETE FROM logs');
  res.json({ ok: true });
});

app.get('/api/stats', requireAuth, (req, res) => {
  const total = getQuery('SELECT COUNT(*) as n FROM logs')[0]?.n || 0;
  const byLevel = getQuery('SELECT level, COUNT(*) as n FROM logs GROUP BY level');
  const bySite = getQuery('SELECT site_name, COUNT(*) as n FROM logs GROUP BY site_name ORDER BY n DESC');
  const last24h = getQuery("SELECT COUNT(*) as n FROM logs WHERE timestamp >= datetime('now', '-24 hours')")[0]?.n || 0;
  const last7d = getQuery("SELECT COUNT(*) as n FROM logs WHERE timestamp >= datetime('now', '-7 days')")[0]?.n || 0;
  const logsPerDay = getQuery(`SELECT date(timestamp) as day, COUNT(*) as n FROM logs WHERE timestamp >= datetime('now', '-30 days') GROUP BY day ORDER BY day ASC`);
  res.json({ total, byLevel, bySite, last24h, last7d, logsPerDay });
});

app.get('/api/sites', requireAuth, (req, res) => {
  const rows = getQuery('SELECT id, site_name, site_url, created_at, last_used, active FROM api_keys ORDER BY created_at DESC');
  res.json(rows);
});

app.post('/api/sites', requireAdmin, (req, res) => {
  const name = req.body.name || req.body.site_name;
  const url = req.body.url || req.body.site_url;
  if (!name) return res.status(400).json({ error: 'name requis' });
  const rawKey = crypto.randomBytes(32).toString('hex');
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  runQuery('INSERT INTO api_keys (key_hash, site_name, site_url) VALUES (?, ?, ?)', [keyHash, name, url || null]);
  res.json({ ok: true, api_key: rawKey, site_name: name });
});

app.patch('/api/sites/:id', requireAdmin, (req, res) => { runQuery('UPDATE api_keys SET active = ? WHERE id = ?', [req.body.active ? 1 : 0, req.params.id]); res.json({ ok: true }); });
app.delete('/api/sites/:id', requireAdmin, (req, res) => { runQuery('DELETE FROM api_keys WHERE id = ?', [req.params.id]); res.json({ ok: true }); });

app.get('/api/admins', requireAdmin, (req, res) => res.json(getQuery('SELECT id, username, role, created_at FROM admins ORDER BY created_at ASC')));

app.post('/api/admins', requireAdmin, async (req, res) => {
  const { username, password, role = 'viewer' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (typeof username !== 'string' || username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Nom invalide' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Mot de passe trop court' });
  const safeRole = ['admin', 'viewer'].includes(role) ? role : 'viewer';
  const hash = await bcrypt.hash(password, 12);
  try { runQuery('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, safeRole]); res.json({ ok: true }); }
  catch { res.status(400).json({ error: 'Nom deja utilise' }); }
});

app.delete('/api/admins/:id', requireAdmin, (req, res) => {
  if (parseInt(req.params.id) === req.admin.id) return res.status(400).json({ error: 'Impossible de se supprimer soi-meme' });
  runQuery('DELETE FROM admins WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDB().then(() => {
  app.listen(PORT, () => console.log(`[LOG-DASHBOARD] Serveur demarre sur le port ${PORT}`));
});

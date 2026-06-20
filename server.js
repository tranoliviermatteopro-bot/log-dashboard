const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_jwt_secret_logdash';
const DB_PATH = path.join(__dirname, 'data.db');

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let db;
let SQL;

async function initDB() {
  SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
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

function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function runQuery(sql, params = []) {
  db.run(sql, params);
  saveDB();
}

function getQuery(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) { rows.push(stmt.getAsObject()); }
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

function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'Cle API manquante' });
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const rows = getQuery('SELECT * FROM api_keys WHERE key_hash = ? AND active = 1', [keyHash]);
  if (rows.length === 0) return res.status(401).json({ error: 'Cle API invalide' });
  req.site = rows[0];
  runQuery('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?', [rows[0].id]);
  next();
}

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  const rows = getQuery('SELECT * FROM admins WHERE username = ?', [username]);
  if (rows.length === 0) return res.status(401).json({ error: 'Identifiants incorrects' });
  const admin = rows[0];
  const valid = await bcrypt.compare(password, admin.password_hash);
  if (!valid) return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: admin.id, username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: admin.username, role: admin.role });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ username: req.admin.username, role: req.admin.role });
});

app.post('/api/setup', async (req, res) => {
  const { secret, username, password } = req.body;
  if (secret !== process.env.SETUP_SECRET) return res.status(403).json({ error: 'Secret invalide' });
  const existing = getQuery('SELECT id FROM admins LIMIT 1');
  if (existing.length > 0) return res.status(400).json({ error: 'Deja configure' });
  const hash = await bcrypt.hash(password, 10);
  runQuery('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, 'admin']);
  res.json({ ok: true });
});

app.post('/api/ingest', requireApiKey, (req, res) => {
  const { level = 'info', message, meta, source } = req.body;
  if (!message) return res.status(400).json({ error: 'message requis' });
  const validLevels = ['debug', 'info', 'warn', 'error', 'critical'];
  const safeLevel = validLevels.includes(level) ? level : 'info';
  const metaStr = meta ? (typeof meta === 'string' ? meta : JSON.stringify(meta)) : null;
  runQuery('INSERT INTO logs (site_name, level, message, meta, source) VALUES (?, ?, ?, ?, ?)', [req.site.site_name, safeLevel, message, metaStr, source || null]);
  res.json({ ok: true, site: req.site.site_name });
});

app.post('/api/ingest/batch', requireApiKey, (req, res) => {
  const { logs } = req.body;
  if (!Array.isArray(logs)) return res.status(400).json({ error: 'logs doit etre un tableau' });
  const validLevels = ['debug', 'info', 'warn', 'error', 'critical'];
  let inserted = 0;
  for (const log of logs.slice(0, 100)) {
    const { level = 'info', message, meta, source } = log;
    if (!message) continue;
    const safeLevel = validLevels.includes(level) ? level : 'info';
    const metaStr = meta ? (typeof meta === 'string' ? meta : JSON.stringify(meta)) : null;
    db.run('INSERT INTO logs (site_name, level, message, meta, source) VALUES (?, ?, ?, ?, ?)', [req.site.site_name, safeLevel, message, metaStr, source || null]);
    inserted++;
  }
  saveDB();
  res.json({ ok: true, inserted });
});

app.get('/api/logs', requireAuth, (req, res) => {
  const { site, level, search, from, to, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  let where = []; let params = [];
  if (site && site !== 'all') { where.push('site_name = ?'); params.push(site); }
  if (level && level !== 'all') { where.push('level = ?'); params.push(level); }
  if (search) { where.push('(message LIKE ? OR meta LIKE ?)'); params.push('%'+search+'%', '%'+search+'%'); }
  if (from) { where.push('timestamp >= ?'); params.push(from); }
  if (to) { where.push('timestamp <= ?'); params.push(to); }
  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const countRows = getQuery('SELECT COUNT(*) as total FROM logs ' + whereClause, params);
  const total = countRows[0]?.total || 0;
  const rows = getQuery('SELECT * FROM logs ' + whereClause + ' ORDER BY timestamp DESC LIMIT ? OFFSET ?', [...params, parseInt(limit), offset]);
  res.json({ logs: rows, total, page: parseInt(page), limit: parseInt(limit) });
});

app.delete('/api/logs/:id', requireAdmin, (req, res) => {
  runQuery('DELETE FROM logs WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/logs', requireAdmin, (req, res) => {
  const { site } = req.query;
  if (site) { runQuery('DELETE FROM logs WHERE site_name = ?', [site]); }
  else { runQuery('DELETE FROM logs'); }
  res.json({ ok: true });
});

app.get('/api/stats', requireAuth, (req, res) => {
  const total = getQuery('SELECT COUNT(*) as n FROM logs')[0]?.n || 0;
  const byLevel = getQuery('SELECT level, COUNT(*) as n FROM logs GROUP BY level');
  const bySite = getQuery('SELECT site_name, COUNT(*) as n FROM logs GROUP BY site_name ORDER BY n DESC');
  const last24h = getQuery("SELECT COUNT(*) as n FROM logs WHERE timestamp >= datetime('now', '-24 hours')")[0]?.n || 0;
  const last7d = getQuery("SELECT COUNT(*) as n FROM logs WHERE timestamp >= datetime('now', '-7 days')")[0]?.n || 0;
  const logsPerDay = getQuery("SELECT date(timestamp) as day, COUNT(*) as n FROM logs WHERE timestamp >= datetime('now', '-30 days') GROUP BY day ORDER BY day ASC");
  res.json({ total, byLevel, bySite, last24h, last7d, logsPerDay });
});

app.get('/api/sites', requireAuth, (req, res) => {
  res.json(getQuery('SELECT id, site_name, site_url, created_at, last_used, active FROM api_keys ORDER BY created_at DESC'));
});

app.post('/api/sites', requireAdmin, (req, res) => {
  const { site_name, site_url } = req.body;
  if (!site_name) return res.status(400).json({ error: 'site_name requis' });
  const rawKey = crypto.randomBytes(32).toString('hex');
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  runQuery('INSERT INTO api_keys (key_hash, site_name, site_url) VALUES (?, ?, ?)', [keyHash, site_name, site_url || null]);
  res.json({ ok: true, api_key: rawKey, site_name });
});

app.patch('/api/sites/:id', requireAdmin, (req, res) => {
  runQuery('UPDATE api_keys SET active = ? WHERE id = ?', [req.body.active ? 1 : 0, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/sites/:id', requireAdmin, (req, res) => {
  runQuery('DELETE FROM api_keys WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/admins', requireAdmin, (req, res) => {
  res.json(getQuery('SELECT id, username, role, created_at FROM admins ORDER BY created_at ASC'));
});

app.post('/api/admins', requireAdmin, async (req, res) => {
  const { username, password, role = 'viewer' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  const hash = await bcrypt.hash(password, 10);
  try {
    runQuery('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, role]);
    res.json({ ok: true });
  } catch { res.status(400).json({ error: "Nom d'utilisateur deja utilise" }); }
});

app.delete('/api/admins/:id', requireAdmin, (req, res) => {
  if (parseInt(req.params.id) === req.admin.id) return res.status(400).json({ error: 'Impossible de se supprimer soi-meme' });
  runQuery('DELETE FROM admins WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log('[LOG-DASHBOARD] Serveur demarre sur le port ' + PORT));
});

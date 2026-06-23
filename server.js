const express = require('express');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_jwt_secret_logdash';

// Isoler dans le schéma "logdashboard" via options dans la connection string (évite
// le bug pool.on('connect') qui bloque le premier pool.query en pg 8.x)
const _dbUrl = process.env.DATABASE_URL || '';
const _dbUrlWithSchema = _dbUrl
  ? _dbUrl + (_dbUrl.includes('?') ? '&' : '?') + 'options=-c+search_path%3Dlogdashboard%2Cpublic'
  : '';

const pool = new Pool({
  connectionString: _dbUrlWithSchema || undefined,
  ssl: _dbUrl ? { rejectUnauthorized: false } : false,
});

// ─── SECURITY HEADERS (Helmet) ────────────────────────────────────────────────

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
      scriptSrcAttr: ["'unsafe-inline'"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

// ─── CORS RESTREINT ───────────────────────────────────────────────────────────

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Pas d'origine = requête server-to-server ou curl → autorisé pour /api/ingest
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error('CORS: origine non autorisée'));
  },
  credentials: true,
}));

// ─── TRUST PROXY (Render reverse proxy) ──────────────────────────────────────

app.set('trust proxy', 1);

// ─── RATE LIMITING ────────────────────────────────────────────────────────────

// Login : 5 tentatives / 15 min
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Trop de tentatives. Réessayez dans 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

// Ingest : 300 req / min par IP
const ingestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  message: { error: 'Trop de requêtes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// API générale : 500 req / 15 min par IP
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { error: 'Trop de requêtes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', loginLimiter);
app.use('/api/ingest', ingestLimiter);

// ─── BLOCKLIST LOGIN (verrouillage temporaire en mémoire) ─────────────────────

const loginFailures = new Map(); // ip → { count, unlockedAt }
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
  if (entry.count >= MAX_FAILURES) {
    entry.unlockedAt = Date.now() + LOCKOUT_MS;
    entry.count = 0;
  }
  loginFailures.set(ip, entry);
}

function clearFailures(ip) {
  loginFailures.delete(ip);
}

// ─── INPUT SANITIZATION ───────────────────────────────────────────────────────

function sanitizeStr(val, maxLen = 1000) {
  if (typeof val !== 'string') return val;
  return val.replace(/<[^>]*>/g, '').slice(0, maxLen);
}

app.use(express.json({ limit: '512kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── DATABASE ────────────────────────────────────────────────────────────────

async function initDB() {
  // search_path déjà fixé via la connection string (options=-c+search_path=logdashboard,public)
  await pool.query('CREATE SCHEMA IF NOT EXISTS logdashboard');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'viewer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id SERIAL PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      site_name TEXT NOT NULL,
      site_url TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_used TIMESTAMP,
      active BOOLEAN DEFAULT true
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      site_name TEXT NOT NULL,
      level TEXT NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      meta TEXT,
      source TEXT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_logs_site ON logs(site_name)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)`);

  console.log('[DB] Base de données initialisée');
}

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.admin.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    next();
  });
}

// ─── API KEY MIDDLEWARE ───────────────────────────────────────────────────────

// Clés statiques définies en env vars (format: SITE_NAME=KEY, ex: BOULANGERIE=abc123)
// Syntaxe : STATIC_KEYS=Boulangerie ZREvents06:mykey123,MonAutreSite:otherkey
const STATIC_KEYS = {};
(process.env.STATIC_KEYS || '').split(',').forEach(pair => {
  const idx = pair.indexOf(':');
  if (idx > 0) {
    const name = pair.slice(0, idx).trim();
    const key  = pair.slice(idx + 1).trim();
    if (name && key) STATIC_KEYS[key] = name;
  }
});
console.log('[STATIC_KEYS] Cles chargees:', Object.keys(STATIC_KEYS).length, '| Noms:', Object.values(STATIC_KEYS).join(', ') || '(aucune)');

async function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'Cle API manquante' });

  // Vérifier les clés statiques (persistantes aux redémarrages)
  if (STATIC_KEYS[key]) {
    req.site = { id: null, site_name: STATIC_KEYS[key], site_url: null };
    return next();
  }

  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const { rows } = await pool.query('SELECT * FROM api_keys WHERE key_hash = $1 AND active = true', [keyHash]);
  if (rows.length === 0) return res.status(401).json({ error: 'Cle API invalide' });

  req.site = rows[0];
  await pool.query('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = $1', [rows[0].id]);
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (checkLockout(ip)) {
    return res.status(429).json({ error: 'Compte temporairement bloqué. Réessayez dans 15 minutes.' });
  }

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Champs invalides' });
  }

  const { rows } = await pool.query('SELECT * FROM admins WHERE username = $1', [username.slice(0, 64)]);
  // Toujours faire le compare même si l'user n'existe pas (éviter timing attack)
  const dummyHash = '$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
  const hash = rows.length > 0 ? rows[0].password_hash : dummyHash;
  const valid = await bcrypt.compare(password, hash);

  if (rows.length === 0 || !valid) {
    recordFailure(ip);
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  clearFailures(ip);
  const admin = rows[0];
  const token = jwt.sign(
    { id: admin.id, username: admin.username, role: admin.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
  res.json({ token, username: admin.username, role: admin.role });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ username: req.admin.username, role: req.admin.role });
});

// ─── SETUP INITIAL ADMIN ──────────────────────────────────────────────────────

app.post('/api/setup', async (req, res) => {
  const { secret, username, password } = req.body;
  if (!secret || secret !== process.env.SETUP_SECRET) return res.status(403).json({ error: 'Secret invalide' });

  const { rows: existing } = await pool.query('SELECT id FROM admins LIMIT 1');
  if (existing.length > 0) return res.status(400).json({ error: 'Déjà configuré' });

  if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
    return res.status(400).json({ error: "Nom d'utilisateur invalide (3-32 caractères)" });
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Mot de passe trop court (minimum 8 caractères)' });
  }

  const hash = await bcrypt.hash(password, 12);
  await pool.query('INSERT INTO admins (username, password_hash, role) VALUES ($1, $2, $3)', [username, hash, 'admin']);
  res.json({ ok: true });
});

// ─── LOG INGESTION ────────────────────────────────────────────────────────────

// Envoi d'un seul log
app.post('/api/ingest', requireApiKey, async (req, res) => {
  const { level = 'info', message, meta, source } = req.body;
  if (!message || typeof message !== 'string') return res.status(400).json({ error: 'message requis' });

  const validLevels = ['debug', 'info', 'warn', 'error', 'critical'];
  const safeLevel = validLevels.includes(level) ? level : 'info';
  const safeMessage = sanitizeStr(message, 2000);
  const safeSource = source ? sanitizeStr(String(source), 200) : null;
  const metaStr = meta ? (typeof meta === 'string' ? meta.slice(0, 5000) : JSON.stringify(meta).slice(0, 5000)) : null;

  await pool.query(
    'INSERT INTO logs (site_name, level, message, meta, source) VALUES ($1, $2, $3, $4, $5)',
    [req.site.site_name, safeLevel, safeMessage, metaStr, safeSource]
  );

  res.json({ ok: true, site: req.site.site_name });
});

// Envoi groupé de plusieurs logs
app.post('/api/ingest/batch', requireApiKey, async (req, res) => {
  const { logs } = req.body;
  if (!Array.isArray(logs)) return res.status(400).json({ error: 'logs doit être un tableau' });

  const validLevels = ['debug', 'info', 'warn', 'error', 'critical'];
  let inserted = 0;

  for (const log of logs.slice(0, 100)) {
    const { level = 'info', message, meta, source } = log;
    if (!message || typeof message !== 'string') continue;
    const safeLevel = validLevels.includes(level) ? level : 'info';
    const safeMessage = sanitizeStr(message, 2000);
    const safeSource = source ? sanitizeStr(String(source), 200) : null;
    const metaStr = meta ? (typeof meta === 'string' ? meta.slice(0, 5000) : JSON.stringify(meta).slice(0, 5000)) : null;
    await pool.query(
      'INSERT INTO logs (site_name, level, message, meta, source) VALUES ($1, $2, $3, $4, $5)',
      [req.site.site_name, safeLevel, safeMessage, metaStr, safeSource]
    );
    inserted++;
  }
  res.json({ ok: true, inserted });
});

// ─── LOGS API ─────────────────────────────────────────────────────────────────

app.get('/api/logs', requireAuth, async (req, res) => {
  const { site, level, search, from, to, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let where = [];
  let params = [];

  if (site && site !== 'all') { params.push(site); where.push(`site_name = $${params.length}`); }
  if (level && level !== 'all') { params.push(level); where.push(`level = $${params.length}`); }
  if (search) { params.push(`%${search}%`, `%${search}%`); where.push(`(message LIKE $${params.length - 1} OR meta LIKE $${params.length})`); }
  if (from) { params.push(from); where.push(`timestamp >= $${params.length}`); }
  if (to) { params.push(to); where.push(`timestamp <= $${params.length}`); }

  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const { rows: countRows } = await pool.query(`SELECT COUNT(*) as total FROM logs ${whereClause}`, params);
  const total = parseInt(countRows[0]?.total) || 0;

  const limitParams = [...params];
  limitParams.push(parseInt(limit));
  const limitPlaceholder = limitParams.length;
  limitParams.push(offset);
  const offsetPlaceholder = limitParams.length;

  const { rows } = await pool.query(
    `SELECT * FROM logs ${whereClause} ORDER BY timestamp DESC LIMIT $${limitPlaceholder} OFFSET $${offsetPlaceholder}`,
    limitParams
  );

  res.json({ logs: rows, total, page: parseInt(page), limit: parseInt(limit) });
});

app.delete('/api/logs/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM logs WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/logs', requireAdmin, async (req, res) => {
  const { site } = req.query;
  if (site) {
    await pool.query('DELETE FROM logs WHERE site_name = $1', [site]);
  } else {
    await pool.query('DELETE FROM logs');
  }
  res.json({ ok: true });
});

// ─── STATS ────────────────────────────────────────────────────────────────────

app.get('/api/stats', requireAuth, async (req, res) => {
  const { rows: totalRows } = await pool.query('SELECT COUNT(*) as n FROM logs');
  const total = parseInt(totalRows[0]?.n) || 0;
  const { rows: byLevel } = await pool.query('SELECT level, COUNT(*) as n FROM logs GROUP BY level');
  const { rows: bySite } = await pool.query('SELECT site_name, COUNT(*) as n FROM logs GROUP BY site_name ORDER BY n DESC');
  const { rows: last24hRows } = await pool.query("SELECT COUNT(*) as n FROM logs WHERE timestamp >= NOW() - INTERVAL '24 hours'");
  const last24h = parseInt(last24hRows[0]?.n) || 0;
  const { rows: last7dRows } = await pool.query("SELECT COUNT(*) as n FROM logs WHERE timestamp >= NOW() - INTERVAL '7 days'");
  const last7d = parseInt(last7dRows[0]?.n) || 0;

  const { rows: logsPerDay } = await pool.query(`
    SELECT timestamp::date as day, COUNT(*) as n
    FROM logs WHERE timestamp >= NOW() - INTERVAL '30 days'
    GROUP BY day ORDER BY day ASC
  `);

  res.json({ total, byLevel, bySite, last24h, last7d, logsPerDay });
});

// ─── SITES (API KEYS) ─────────────────────────────────────────────────────────

app.get('/api/sites', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, site_name, site_url, created_at, last_used, active FROM api_keys ORDER BY created_at DESC');
  res.json(rows);
});

app.post('/api/sites', requireAdmin, async (req, res) => {
  const { site_name, site_url } = req.body;
  if (!site_name) return res.status(400).json({ error: 'site_name requis' });

  const rawKey = crypto.randomBytes(32).toString('hex');
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

  await pool.query('INSERT INTO api_keys (key_hash, site_name, site_url) VALUES ($1, $2, $3)', [keyHash, site_name, site_url || null]);
  res.json({ ok: true, api_key: rawKey, site_name });
});

app.patch('/api/sites/:id', requireAdmin, async (req, res) => {
  const { active } = req.body;
  await pool.query('UPDATE api_keys SET active = $1 WHERE id = $2', [active ? true : false, req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/sites/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM api_keys WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ─── ADMINS ───────────────────────────────────────────────────────────────────

app.get('/api/admins', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, role, created_at FROM admins ORDER BY created_at ASC');
  res.json(rows);
});

app.post('/api/admins', requireAdmin, async (req, res) => {
  const { username, password, role = 'viewer' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (typeof username !== 'string' || username.length < 3 || username.length > 32) {
    return res.status(400).json({ error: "Nom d'utilisateur invalide (3-32 caractères)" });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Mot de passe trop court (minimum 8 caractères)' });
  }
  const validRoles = ['admin', 'viewer'];
  const safeRole = validRoles.includes(role) ? role : 'viewer';

  const hash = await bcrypt.hash(password, 12);
  try {
    await pool.query('INSERT INTO admins (username, password_hash, role) VALUES ($1, $2, $3)', [username, hash, safeRole]);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Nom d'utilisateur déjà utilisé" });
  }
});

app.delete('/api/admins/:id', requireAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.admin.id) {
    return res.status(400).json({ error: 'Impossible de se supprimer soi-même' });
  }
  await pool.query('DELETE FROM admins WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ─── FALLBACK SPA ─────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── START ────────────────────────────────────────────────────────────────────

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`[LOG-DASHBOARD] Serveur démarré sur le port ${PORT}`);
  });
});

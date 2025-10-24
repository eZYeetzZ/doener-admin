// server.js
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const CORS_ORIGIN = process.env.CORS_ORIGIN || `http://localhost:${PORT}`;
const isProd = process.env.NODE_ENV === 'production';

// --- Middleware
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(cors({
  origin: (origin, cb) => {
    // Erlaube gleiche Origin oder explizit gesetzte
    if (!origin || origin === CORS_ORIGIN) return cb(null, true);
    return cb(null, false);
  },
  credentials: true
}));

// --- DB Setup
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
const DB_PATH = path.join(DATA_DIR, 'database.sqlite');
const db = new sqlite3.Database(DB_PATH);

function run(sql, params = []) { return new Promise((res, rej) => db.run(sql, params, function(err){ if (err) rej(err); else res(this); })); }
function all(sql, params = []) { return new Promise((res, rej) => db.all(sql, params, (err, rows)=> err? rej(err): res(rows))); }
function get(sql, params = []) { return new Promise((res, rej) => db.get(sql, params, (err, row)=> err? rej(err): res(row))); }

(async function init(){
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await run(`CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_cents INTEGER NOT NULL,
    currency TEXT NOT NULL,
    prefix TEXT,
    position TEXT,
    items_json TEXT NOT NULL
  )`);

  // Admin anlegen/aktualisieren
  const u = process.env.ADMIN_USERNAME || 'admin';
  const p = process.env.ADMIN_PASSWORD || 'admin';
  const hash = await bcrypt.hash(p, 10);
  const exists = await get(`SELECT id FROM users WHERE username=?`, [u]);
  if (exists) {
    await run(`UPDATE users SET password_hash=? WHERE id=?`, [hash, exists.id]);
    console.log(`✔ Admin aktualisiert: ${u}`);
  } else {
    await run(`INSERT INTO users (username, password_hash) VALUES (?,?)`, [u, hash]);
    console.log(`✔ Admin erstellt: ${u}`);
  }
})();

// --- Auth Helpers
function authRequired(req, res, next){
  const token = req.cookies['token'];
  if(!token) return res.status(401).json({ error: 'Not authenticated' });
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; next();
  }catch(e){
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Auth Routes
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if(!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  const row = await get(`SELECT * FROM users WHERE username=?`, [username]);
  if(!row) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, row.password_hash);
  if(!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ uid: row.id, username: row.username }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 7*24*60*60*1000 });
  res.json({ ok: true, username: row.username });
});

app.post('/api/auth/logout', (req, res)=>{ res.clearCookie('token'); res.json({ ok:true }); });
app.get('/api/auth/me', authRequired, (req, res)=>{ res.json({ ok:true, user: req.user }); });

// --- Sales ingest (öffentlich)
app.post('/api/sales', async (req, res) => {
  try{
    const { total_cents, currency='USD', prefix='', position='', items=[] } = req.body || {};
    if (!Number.isInteger(total_cents) || total_cents < 0) return res.status(400).json({ error: 'total_cents invalid' });
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'items required' });
    const items_json = JSON.stringify(items);
    await run(`INSERT INTO sales (total_cents, currency, prefix, position, items_json) VALUES (?,?,?,?,?)`, [total_cents, currency, prefix, position, items_json]);
    res.json({ ok:true });
  }catch(e){
    console.error(e); res.status(500).json({ error: 'server_error' });
  }
});

// --- Helpers für Zeitbereiche
function rangeToSQL(range){
  // nutzt SQLite datetime-Funktionen (UTC)
  switch(range){
    case 'day': return `datetime(created_at) >= datetime('now', 'start of day')`;
    case 'week': return `datetime(created_at) >= datetime('now', 'weekday 0', '-6 days')`; // letzte 7 Tage inkl. heute
    case 'month': return `datetime(created_at) >= datetime('now', 'start of month')`;
    case 'all':
    default: return '1=1';
  }
}

// --- Stats
app.get('/api/stats/summary', authRequired, async (req, res) => {
  const range = (req.query.range || 'day');
  const where = rangeToSQL(range);
  const row = await get(`SELECT COUNT(*) as count, COALESCE(SUM(total_cents),0) as sum_cents, COALESCE(AVG(total_cents),0) as avg_cents FROM sales WHERE ${where}`);
  res.json({ range, count: row.count, sum_cents: row.sum_cents, avg_cents: Math.round(row.avg_cents) });
});

app.get('/api/stats/timeseries', authRequired, async (req, res) => {
  const range = (req.query.range || 'day');
  const where = rangeToSQL(range);
  const rows = await all(`
    SELECT date(created_at) as day, COALESCE(SUM(total_cents),0) as sum_cents, COUNT(*) as count
    FROM sales
    WHERE ${where}
    GROUP BY day
    ORDER BY day ASC
  `);
  res.json({ range, rows });
});

app.get('/api/sales', authRequired, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '100', 10), 1000);
  const offset = parseInt(req.query.offset || '0', 10);
  const rows = await all(`SELECT id, created_at, total_cents, currency, prefix, position, items_json FROM sales ORDER BY created_at DESC LIMIT ? OFFSET ?`, [limit, offset]);
  res.json({ rows });
});

// --- Static
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, ()=> console.log(`✔ Server läuft auf http://localhost:${PORT}`));

require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'curavio_dev_secret_2024';

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== DATENBANK SETUP =====
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'angehoeriger',
        patient_ids TEXT DEFAULT '[]',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS patients (
        id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        address TEXT DEFAULT '',
        care_level INTEGER DEFAULT 1,
        betreuer_id VARCHAR(50),
        angehoerige_ids TEXT DEFAULT '[]',
        notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS visits (
        id VARCHAR(50) PRIMARY KEY,
        patient_id VARCHAR(50) NOT NULL,
        betreuer_id VARCHAR(50) NOT NULL,
        scheduled_at TIMESTAMP NOT NULL,
        duration INTEGER DEFAULT 60,
        status VARCHAR(50) DEFAULT 'geplant',
        notes TEXT DEFAULT '',
        services TEXT DEFAULT '[]',
        location TEXT DEFAULT '',
        actual_start TIMESTAMP,
        actual_end TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS actual_start TIMESTAMP;
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS actual_end TIMESTAMP;
      CREATE TABLE IF NOT EXISTS reports (
        id VARCHAR(50) PRIMARY KEY,
        visit_id VARCHAR(50),
        patient_id VARCHAR(50) NOT NULL,
        betreuer_id VARCHAR(50) NOT NULL,
        content TEXT NOT NULL,
        ai_summary TEXT DEFAULT '',
        mood VARCHAR(50) DEFAULT 'gut',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS messages (
        id VARCHAR(50) PRIMARY KEY,
        room_id VARCHAR(255) NOT NULL,
        sender_id VARCHAR(50) NOT NULL,
        sender_name VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    const { rows } = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(rows[0].count) === 0) {
      await seedDemoData(client);
    }
  } finally {
    client.release();
  }
}

async function seedDemoData(client) {
  const pw = await bcrypt.hash('curavio123', 10);
  await client.query(`
    INSERT INTO users (id, name, email, password, role, patient_ids) VALUES
    ('u1', 'Thomas Mueller', 'thomas@demo.de', $1, 'angehoeriger', '["p1"]'),
    ('u2', 'Maria Kovacs', 'maria@demo.de', $1, 'betreuer', '["p1"]'),
    ('u3', 'Admin Curavio', 'admin@curavio.de', $1, 'admin', '[]')
  `, [pw]);

  await client.query(`
    INSERT INTO patients (id, name, address, care_level, betreuer_id, angehoerige_ids) VALUES
    ('p1', 'Elisabeth Mueller', 'Hauptstrasse 12, 80333 München', 3, 'u2', '["u1"]')
  `);

  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(10, 0, 0, 0);
  await client.query(`
    INSERT INTO visits (id, patient_id, betreuer_id, scheduled_at, duration, status, services) VALUES
    ('v1', 'p1', 'u2', $1, 90, 'geplant', '["Körperpflege","Medikamente","Gespräch"]')
  `, [tomorrow]);

  console.log('[DB] Demo-Daten angelegt');
}

// ===== AUTH MIDDLEWARE =====
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Kein Token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Ungültiger Token' });
  }
}

// ===== AUTH ROUTEN =====
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = rows[0];
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    }
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, E-Mail und Passwort erforderlich' });
  try {
    const id = 'u_' + uuidv4().replace(/-/g, '').substring(0, 12);
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (id, name, email, password, role) VALUES ($1,$2,$3,$4,$5)',
      [id, name, email.toLowerCase(), hashed, role || 'angehoeriger']
    );
    res.json({ success: true, message: 'Registrierung erfolgreich' });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'E-Mail bereits registriert' });
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, email, role FROM users WHERE id = $1', [req.user.id]);
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// ===== PATIENTEN =====
app.get('/api/patients', auth, async (req, res) => {
  try {
    let query, params;
    if (req.user.role === 'admin') {
      query = 'SELECT * FROM patients ORDER BY name'; params = [];
    } else if (req.user.role === 'betreuer') {
      query = 'SELECT * FROM patients WHERE betreuer_id = $1 ORDER BY name'; params = [req.user.id];
    } else {
      query = "SELECT * FROM patients WHERE angehoerige_ids LIKE $1 ORDER BY name";
      params = [`%"${req.user.id}"%`];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows.map(p => ({ ...p, angehoerige_ids: JSON.parse(p.angehoerige_ids || '[]') })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients', auth, async (req, res) => {
  if (!['admin', 'betreuer'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  const { name, address, care_level, betreuer_id, notes, angehoerige_ids } = req.body;
  try {
    const id = 'p_' + uuidv4().replace(/-/g, '').substring(0, 12);
    const { rows } = await pool.query(
      'INSERT INTO patients (id, name, address, care_level, betreuer_id, notes, angehoerige_ids) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [id, name, address || '', care_level || 1, betreuer_id || req.user.id, notes || '', JSON.stringify(angehoerige_ids || [])]
    );
    res.json({ ...rows[0], angehoerige_ids: JSON.parse(rows[0].angehoerige_ids || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/patients/:id', auth, async (req, res) => {
  if (!['admin', 'betreuer'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  const { name, address, care_level, notes, angehoerige_ids } = req.body;
  try {
    const { rows } = await pool.query(
      'UPDATE patients SET name=COALESCE($1,name), address=COALESCE($2,address), care_level=COALESCE($3,care_level), notes=COALESCE($4,notes), angehoerige_ids=COALESCE($5,angehoerige_ids) WHERE id=$6 RETURNING *',
      [name, address, care_level, notes, angehoerige_ids ? JSON.stringify(angehoerige_ids) : null, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    res.json({ ...rows[0], angehoerige_ids: JSON.parse(rows[0].angehoerige_ids || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BESUCHE =====
app.get('/api/visits', auth, async (req, res) => {
  try {
    let query, params;
    if (req.user.role === 'admin') {
      query = `SELECT v.*, p.name as patient_name, u.name as betreuer_name FROM visits v
               LEFT JOIN patients p ON v.patient_id = p.id LEFT JOIN users u ON v.betreuer_id = u.id
               ORDER BY v.scheduled_at DESC`;
      params = [];
    } else if (req.user.role === 'betreuer') {
      query = `SELECT v.*, p.name as patient_name FROM visits v
               LEFT JOIN patients p ON v.patient_id = p.id
               WHERE v.betreuer_id = $1 ORDER BY v.scheduled_at DESC`;
      params = [req.user.id];
    } else {
      query = `SELECT v.*, p.name as patient_name, u.name as betreuer_name FROM visits v
               LEFT JOIN patients p ON v.patient_id = p.id LEFT JOIN users u ON v.betreuer_id = u.id
               WHERE p.angehoerige_ids LIKE $1 ORDER BY v.scheduled_at DESC`;
      params = [`%"${req.user.id}"%`];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows.map(v => ({ ...v, services: JSON.parse(v.services || '[]') })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/visits', auth, async (req, res) => {
  const { patient_id, scheduled_at, duration, notes, services, location } = req.body;
  if (!patient_id || !scheduled_at) return res.status(400).json({ error: 'Patient und Datum erforderlich' });
  try {
    const id = 'v_' + uuidv4().replace(/-/g, '').substring(0, 12);
    const { rows } = await pool.query(
      'INSERT INTO visits (id, patient_id, betreuer_id, scheduled_at, duration, notes, services, location) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [id, patient_id, req.user.id, scheduled_at, duration || 60, notes || '', JSON.stringify(services || []), location || '']
    );
    res.json({ ...rows[0], services: JSON.parse(rows[0].services || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/visits/:id/status', auth, async (req, res) => {
  const { status, notes } = req.body;
  try {
    const { rows } = await pool.query(
      'UPDATE visits SET status=$1, notes=COALESCE($2,notes) WHERE id=$3 RETURNING *',
      [status, notes, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    res.json({ ...rows[0], services: JSON.parse(rows[0].services || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BERICHTE =====
app.get('/api/reports', auth, async (req, res) => {
  try {
    let query, params;
    if (req.user.role === 'admin') {
      query = `SELECT r.*, p.name as patient_name, u.name as betreuer_name FROM reports r
               LEFT JOIN patients p ON r.patient_id = p.id LEFT JOIN users u ON r.betreuer_id = u.id
               ORDER BY r.created_at DESC`;
      params = [];
    } else if (req.user.role === 'betreuer') {
      query = `SELECT r.*, p.name as patient_name FROM reports r LEFT JOIN patients p ON r.patient_id = p.id
               WHERE r.betreuer_id = $1 ORDER BY r.created_at DESC`;
      params = [req.user.id];
    } else {
      query = `SELECT r.*, p.name as patient_name, u.name as betreuer_name FROM reports r
               LEFT JOIN patients p ON r.patient_id = p.id LEFT JOIN users u ON r.betreuer_id = u.id
               WHERE p.angehoerige_ids LIKE $1 ORDER BY r.created_at DESC`;
      params = [`%"${req.user.id}"%`];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reports', auth, async (req, res) => {
  const { patient_id, visit_id, content, mood } = req.body;
  if (!patient_id || !content) return res.status(400).json({ error: 'Patient und Inhalt erforderlich' });
  try {
    const id = 'r_' + uuidv4().replace(/-/g, '').substring(0, 12);
    let ai_summary = '';

    if (process.env.ANTHROPIC_API_KEY) {
      try {
        const https = require('https');
        const aiData = JSON.stringify({
          model: 'claude-haiku-4-5-20251001', max_tokens: 200,
          messages: [{ role: 'user', content: `Fasse diesen Pflegebericht in 2-3 Sätzen zusammen: ${content}` }]
        });
        ai_summary = await new Promise((resolve) => {
          const r = https.request({
            hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
            headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json', 'content-length': Buffer.byteLength(aiData) }
          }, (res2) => {
            let body = '';
            res2.on('data', d => body += d);
            res2.on('end', () => { try { resolve(JSON.parse(body).content[0].text); } catch { resolve(''); } });
          });
          r.on('error', () => resolve(''));
          r.write(aiData); r.end();
        });
      } catch { ai_summary = ''; }
    }

    const { rows } = await pool.query(
      'INSERT INTO reports (id, patient_id, betreuer_id, visit_id, content, ai_summary, mood) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [id, patient_id, req.user.id, visit_id || null, content, ai_summary, mood || 'gut']
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== NACHRICHTEN =====
app.get('/api/messages/:room_id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM messages WHERE room_id = $1 ORDER BY created_at ASC LIMIT 100',
      [req.params.room_id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BETREUER – Alle eigenen Besuche =====
app.get('/api/betreuer/visits', auth, async (req, res) => {
  if (!['betreuer','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  try {
    const bid = req.user.role === 'admin' ? (req.query.betreuer_id || req.user.id) : req.user.id;
    // Auch Anfragen (status = 'anfrage' oder 'offen') ohne betreuer_id anzeigen
    const { rows } = await pool.query(`
      SELECT v.*, p.name as patient_name, p.address as patient_address,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id
      WHERE v.betreuer_id = $1
         OR (v.status IN ('anfrage','offen') AND v.betreuer_id IS NULL)
      ORDER BY v.scheduled_at ASC
    `, [bid]);
    res.json(rows.map(r => ({ ...r, services: JSON.parse(r.services || '[]') })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BETREUER CLOCKIN / CLOCKOUT / ARBEITSZEITEN =====
app.patch('/api/visits/:id/clockin', auth, async (req, res) => {
  if (req.user.role !== 'betreuer') return res.status(403).json({ error: 'Nur Betreuer' });
  try {
    const { rows } = await pool.query(
      'UPDATE visits SET actual_start = NOW(), status = $1 WHERE id = $2 AND betreuer_id = $3 RETURNING *',
      ['unterwegs', req.params.id, req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Besuch nicht gefunden' });
    res.json({ ...rows[0], services: JSON.parse(rows[0].services || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/visits/:id/clockout', auth, async (req, res) => {
  if (req.user.role !== 'betreuer') return res.status(403).json({ error: 'Nur Betreuer' });
  try {
    const { rows } = await pool.query(
      'UPDATE visits SET actual_end = NOW(), status = $1 WHERE id = $2 AND betreuer_id = $3 RETURNING *',
      ['abgeschlossen', req.params.id, req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Besuch nicht gefunden' });
    res.json({ ...rows[0], services: JSON.parse(rows[0].services || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/betreuer/arbeitszeiten', auth, async (req, res) => {
  if (!['betreuer','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  const bid = req.user.role === 'admin' ? (req.query.betreuer_id || req.user.id) : req.user.id;
  try {
    const { rows } = await pool.query(`
      SELECT v.*, p.name as patient_name,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id
      WHERE v.betreuer_id = $1 AND v.actual_start IS NOT NULL
      ORDER BY v.actual_start DESC LIMIT 50
    `, [bid]);
    res.json(rows.map(r => ({ ...r, services: JSON.parse(r.services || '[]') })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Anfrage annehmen / ablehnen
app.patch('/api/visits/:id/accept', auth, async (req, res) => {
  if (!['betreuer','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  try {
    const { rows } = await pool.query(
      'UPDATE visits SET status = $1, betreuer_id = $2 WHERE id = $3 RETURNING *',
      ['geplant', req.user.id, req.params.id]
    );
    res.json(rows[0] ? { ...rows[0], services: JSON.parse(rows[0].services || '[]') } : { error: 'Nicht gefunden' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/visits/:id/decline', auth, async (req, res) => {
  if (!['betreuer','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  try {
    const { rows } = await pool.query(
      "UPDATE visits SET status = 'abgelehnt' WHERE id = $1 RETURNING *", [req.params.id]
    );
    res.json(rows[0] ? { ...rows[0], services: JSON.parse(rows[0].services || '[]') } : { error: 'Nicht gefunden' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== ADMIN =====
app.get('/api/admin/stats', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Keine Berechtigung' });
  try {
    const [u, p, v, r] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM patients'),
      pool.query('SELECT COUNT(*) FROM visits'),
      pool.query('SELECT COUNT(*) FROM reports')
    ]);
    res.json({ users: +u.rows[0].count, patients: +p.rows[0].count, visits: +v.rows[0].count, reports: +r.rows[0].count });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Keine Berechtigung' });
  try {
    const { rows } = await pool.query('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/users/:id/role', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Keine Berechtigung' });
  const { role } = req.body;
  try {
    const { rows } = await pool.query('UPDATE users SET role=$1 WHERE id=$2 RETURNING id,name,email,role', [role, req.params.id]);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== START =====
async function start() {
  console.log('='.repeat(50));
  console.log(' CURAVIO startet...');

  try {
    await initDB();
    console.log('[DB] Bereit!');
  } catch (e) {
    console.error('[DB] FEHLER - kein DATABASE_URL gesetzt?', e.message);
    process.exit(1);
  }

  const server = app.listen(PORT, () => {
    console.log('[Server] Port', PORT);
    console.log('[KI]', process.env.ANTHROPIC_API_KEY ? 'Aktiv' : 'Inaktiv');
    console.log('Demo: thomas@demo.de / curavio123');
    console.log('='.repeat(50));
  });

  const wss = new WebSocketServer({ server });
  const rooms = {};

  wss.on('connection', (ws) => {
    ws.on('message', async (data) => {
      try {
        const msg = JSON.parse(data);
        if (msg.type === 'join') {
          ws.roomId = msg.roomId; ws.userId = msg.userId; ws.userName = msg.userName;
          if (!rooms[msg.roomId]) rooms[msg.roomId] = new Set();
          rooms[msg.roomId].add(ws);
        } else if (msg.type === 'message' && ws.roomId) {
          const message = { id: uuidv4(), room_id: ws.roomId, sender_id: ws.userId, sender_name: ws.userName, content: msg.content, created_at: new Date().toISOString() };
          try {
            await pool.query('INSERT INTO messages (id, room_id, sender_id, sender_name, content) VALUES ($1,$2,$3,$4,$5)',
              [message.id, message.room_id, message.sender_id, message.sender_name, message.content]);
          } catch { /* ignore */ }
          if (rooms[ws.roomId]) rooms[ws.roomId].forEach(c => { if (c.readyState === 1) c.send(JSON.stringify({ type: 'message', message })); });
        }
      } catch { /* ignore */ }
    });
    ws.on('close', () => { if (ws.roomId && rooms[ws.roomId]) rooms[ws.roomId].delete(ws); });
  });
}

start();

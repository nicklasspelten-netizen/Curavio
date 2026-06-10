require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { Pool } = require('pg');
const PDFDocument = require('pdfkit');

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

const gid = (p) => p + '_' + uuidv4().replace(/-/g, '').substring(0, 12);
const num = (x) => parseFloat(x || 0) || 0;

// Pflegegeld pro Monat nach Pflegegrad (Richtwerte, in Einstellungen/Freibeträgen anpassbar)
const PFLEGEGELD = { 1: 0, 2: 347, 3: 599, 4: 800, 5: 990 };

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
        betreuer_id VARCHAR(50),
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

      -- ===== Migrationen (DB läuft live: nur ADD COLUMN IF NOT EXISTS, nie DROP) =====
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS actual_start TIMESTAMP;
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS actual_end TIMESTAMP;
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS service TEXT DEFAULT '';
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS duration_min INTEGER DEFAULT 60;
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS address TEXT DEFAULT '';
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS hourly_rate DECIMAL(8,2) DEFAULT 0;
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS rating INTEGER;
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS rating_comment TEXT DEFAULT '';
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS gps_start TEXT DEFAULT '';
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS gps_end TEXT DEFAULT '';
      ALTER TABLE visits ALTER COLUMN betreuer_id DROP NOT NULL;

      ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS hourly_rate DECIMAL(8,2) DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS qualifications TEXT DEFAULT '[]';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT true;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS iban VARCHAR(50) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS tax_id VARCHAR(50) DEFAULT '';

      ALTER TABLE patients ADD COLUMN IF NOT EXISTS pflegegrad INTEGER DEFAULT 1;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS birth_date DATE;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS phone VARCHAR(50) DEFAULT '';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS insurance VARCHAR(255) DEFAULT '';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS insurance_number VARCHAR(100) DEFAULT '';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS emergency_contact TEXT DEFAULT '';

      ALTER TABLE reports ADD COLUMN IF NOT EXISTS tasks_done TEXT DEFAULT '[]';

      -- ===== Neue Tabellen: Buchhaltung =====
      CREATE TABLE IF NOT EXISTS invoices (
        id VARCHAR(50) PRIMARY KEY,
        invoice_number VARCHAR(50) UNIQUE NOT NULL,
        type VARCHAR(50) NOT NULL,
        recipient_id VARCHAR(50) NOT NULL,
        recipient_name VARCHAR(255),
        period_from DATE NOT NULL,
        period_to DATE NOT NULL,
        line_items TEXT DEFAULT '[]',
        subtotal DECIMAL(10,2) DEFAULT 0,
        freibetrag_35a DECIMAL(10,2) DEFAULT 0,
        pflegegeld_abzug DECIMAL(10,2) DEFAULT 0,
        betreuungsgeld_abzug DECIMAL(10,2) DEFAULT 0,
        sonstige_abzuege DECIMAL(10,2) DEFAULT 0,
        total_abzuege DECIMAL(10,2) DEFAULT 0,
        total_netto DECIMAL(10,2) DEFAULT 0,
        mwst_satz DECIMAL(4,2) DEFAULT 0,
        mwst_betrag DECIMAL(10,2) DEFAULT 0,
        total_brutto DECIMAL(10,2) DEFAULT 0,
        status VARCHAR(50) DEFAULT 'entwurf',
        due_date DATE,
        paid_at TIMESTAMP,
        payment_method VARCHAR(50) DEFAULT '',
        payment_reference VARCHAR(255) DEFAULT '',
        notes TEXT DEFAULT '',
        created_by VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS payments (
        id VARCHAR(50) PRIMARY KEY,
        invoice_id VARCHAR(50) REFERENCES invoices(id),
        amount DECIMAL(10,2) NOT NULL,
        payment_date DATE NOT NULL,
        method VARCHAR(50) DEFAULT 'überweisung',
        reference VARCHAR(255) DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS freibetraege (
        id VARCHAR(50) PRIMARY KEY,
        patient_id VARCHAR(50) NOT NULL,
        year INTEGER NOT NULL,
        freibetrag_35a_max DECIMAL(10,2) DEFAULT 4000.00,
        freibetrag_35a_used DECIMAL(10,2) DEFAULT 0,
        pflegegeld_monatlich DECIMAL(10,2) DEFAULT 0,
        verhinderungspflege_budget DECIMAL(10,2) DEFAULT 1612.00,
        verhinderungspflege_used DECIMAL(10,2) DEFAULT 0,
        entlastungsbetrag DECIMAL(10,2) DEFAULT 125.00,
        entlastungsbetrag_used DECIMAL(10,2) DEFAULT 0,
        notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(patient_id, year)
      );
      CREATE TABLE IF NOT EXISTS expense_categories (
        id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) DEFAULT 'ausgabe',
        tax_relevant BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS expenses (
        id VARCHAR(50) PRIMARY KEY,
        category_id VARCHAR(50),
        description TEXT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        date DATE NOT NULL,
        betreuer_id VARCHAR(50),
        invoice_id VARCHAR(50),
        receipt_url TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS availability (
        id VARCHAR(50) PRIMARY KEY,
        betreuer_id VARCHAR(50) NOT NULL,
        date DATE NOT NULL,
        available BOOLEAN DEFAULT true,
        note TEXT DEFAULT '',
        UNIQUE(betreuer_id, date)
      );
      CREATE TABLE IF NOT EXISTS settings (
        key VARCHAR(100) PRIMARY KEY,
        value TEXT DEFAULT ''
      );
    `);

    // Bestehende Besuche: duration_min aus altem duration-Feld übernehmen
    await client.query(`UPDATE visits SET duration_min = COALESCE(duration, 60) WHERE duration_min IS NULL`);

    // Standard-Einstellungen
    const defaults = {
      firma_name: 'Curavio GmbH',
      firma_adresse: 'Musterstraße 1, 10115 Berlin',
      firma_telefon: '+49 30 1234567',
      firma_email: 'info@curavio.de',
      firma_iban: 'DE12 3456 7890 1234 5678 90',
      firma_bank: 'Musterbank Berlin',
      firma_steuernummer: '12/345/67890',
      default_hourly_rate: '25.00',
      mwst_satz: '0',
      mwst_hinweis: 'Umsatzsteuerfrei gemäß §4 Nr.16 UStG (soziale Dienstleistung)',
      zahlungsziel_tage: '14'
    };
    for (const [k, v] of Object.entries(defaults)) {
      await client.query('INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', [k, v]);
    }
    for (const c of [['ec_personal','Personalkosten'],['ec_fahrt','Fahrtkosten'],['ec_material','Material & Verbrauch'],['ec_buero','Büro & Verwaltung'],['ec_versicherung','Versicherungen'],['ec_sonstiges','Sonstiges']]) {
      await client.query("INSERT INTO expense_categories (id, name, type) VALUES ($1,$2,'ausgabe') ON CONFLICT (id) DO NOTHING", c);
    }

    const { rows } = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(rows[0].count) === 0) {
      await seedDemoData(client);
    }
  } finally {
    client.release();
  }
}

// Idempotente Demo-Daten (Seed + POST /api/admin/demo)
async function seedDemoData(client) {
  const pw = await bcrypt.hash('curavio123', 10);
  const pwDemo = await bcrypt.hash('demo123', 10);
  const pwAdmin = await bcrypt.hash('admin123', 10);
  await client.query(`
    INSERT INTO users (id, name, email, password, role, patient_ids, hourly_rate, phone) VALUES
    ('u1', 'Thomas Mueller', 'thomas@demo.de', $1, 'angehoeriger', '["p1"]', 0, ''),
    ('u2', 'Maria Kovacs', 'maria@demo.de', $1, 'betreuer', '["p1"]', 25.00, '+49 170 1111111'),
    ('u3', 'Admin Curavio', 'admin@curavio.de', $3, 'admin', '[]', 0, ''),
    ('u4', 'Demo Angehöriger', 'demo@curavio.de', $2, 'angehoeriger', '["p1"]', 0, ''),
    ('u5', 'Demo Betreuer', 'betreuer@curavio.de', $2, 'betreuer', '["p1"]', 25.00, '+49 170 2222222')
    ON CONFLICT DO NOTHING
  `, [pw, pwDemo, pwAdmin]);

  await client.query(`
    INSERT INTO patients (id, name, address, care_level, pflegegrad, betreuer_id, angehoerige_ids, insurance, phone) VALUES
    ('p1', 'Elisabeth Mueller', 'Hauptstrasse 12, 80333 München', 3, 3, 'u2', '["u1","u4"]', 'AOK Bayern', '+49 89 555555')
    ON CONFLICT (id) DO NOTHING
  `);

  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(10, 0, 0, 0);
  await client.query(`
    INSERT INTO visits (id, patient_id, betreuer_id, scheduled_at, duration, duration_min, status, services, service, hourly_rate) VALUES
    ('v1', 'p1', 'u2', $1, 90, 90, 'geplant', '["Körperpflege","Medikamente","Gespräch"]', 'Alltagsbegleitung', 25.00)
    ON CONFLICT (id) DO NOTHING
  `, [tomorrow]);

  await client.query(`
    INSERT INTO freibetraege (id, patient_id, year, pflegegeld_monatlich) VALUES
    ('fb_p1', 'p1', $1, $2) ON CONFLICT (patient_id, year) DO NOTHING
  `, [new Date().getFullYear(), PFLEGEGELD[3]]);

  console.log('[DB] Demo-Daten angelegt/aktualisiert');
}

// ===== SETTINGS HELPER =====
async function getSettings() {
  const { rows } = await pool.query('SELECT key, value FROM settings');
  const s = {};
  rows.forEach(r => s[r.key] = r.value);
  return s;
}

// ===== FREIBETRAG HELPER =====
async function getOrCreateFreibetrag(patientId, year) {
  let { rows } = await pool.query('SELECT * FROM freibetraege WHERE patient_id=$1 AND year=$2', [patientId, year]);
  if (!rows[0]) {
    const p = await pool.query('SELECT pflegegrad, care_level FROM patients WHERE id=$1', [patientId]);
    const pg = p.rows[0] ? (p.rows[0].pflegegrad || p.rows[0].care_level || 1) : 1;
    const vp = pg >= 2 ? 1612 : 0;
    await pool.query(
      `INSERT INTO freibetraege (id, patient_id, year, pflegegeld_monatlich, verhinderungspflege_budget)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT (patient_id, year) DO NOTHING`,
      [gid('fb'), patientId, year, PFLEGEGELD[pg] || 0, vp]
    );
    rows = (await pool.query('SELECT * FROM freibetraege WHERE patient_id=$1 AND year=$2', [patientId, year])).rows;
  }
  return rows[0];
}

function freibetragSummary(fb) {
  const monthly = num(fb.entlastungsbetrag);
  return {
    ...fb,
    entlastungsbetrag_jahr: monthly * 12,
    entlastungsbetrag_rest: Math.max(0, monthly * 12 - num(fb.entlastungsbetrag_used)),
    verhinderungspflege_rest: Math.max(0, num(fb.verhinderungspflege_budget) - num(fb.verhinderungspflege_used)),
    freibetrag_35a_rest: Math.max(0, num(fb.freibetrag_35a_max) - num(fb.freibetrag_35a_used))
  };
}

// ===== AUTH MIDDLEWARE =====
function auth(req, res, next) {
  // Token aus Header oder ?token= (für PDF-Downloads per Link)
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Kein Token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Ungültiger Token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
    next();
  };
}
const adminOnly = requireRole('admin');

// Hat der eingeloggte Angehörige Zugriff auf diesen Patienten?
async function isAngehoerigerOf(userId, patientId) {
  const { rows } = await pool.query('SELECT angehoerige_ids FROM patients WHERE id=$1', [patientId]);
  if (!rows[0]) return false;
  try { return JSON.parse(rows[0].angehoerige_ids || '[]').includes(userId); } catch { return false; }
}

// ===== WEBSOCKET BROADCAST (wird nach Serverstart befüllt) =====
let wsClients = new Set();
function wsBroadcast(obj, filter) {
  const data = JSON.stringify(obj);
  wsClients.forEach(ws => {
    if (ws.readyState !== 1) return;
    if (filter && !filter(ws)) return;
    try { ws.send(data); } catch { /* ignore */ }
  });
}
const notifyVisitUpdate = (visitId) => wsBroadcast({ type: 'visit_update', visit_id: visitId });
const notifyNewAssignment = (visit) => wsBroadcast(
  { type: 'new_assignment', visit_id: visit.id },
  ws => ws.userRole === 'betreuer' && (!visit.betreuer_id || ws.userId === visit.betreuer_id) || ws.userRole === 'admin'
);

// ===== AUTH ROUTEN =====
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = rows[0];
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    }
    if (user.active === false) return res.status(403).json({ error: 'Konto deaktiviert' });
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, E-Mail und Passwort erforderlich' });
  // Keine Selbst-Registrierung als Admin
  const safeRole = ['angehoeriger', 'betreuer'].includes(role) ? role : 'angehoeriger';
  try {
    const id = gid('u');
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (id, name, email, password, role) VALUES ($1,$2,$3,$4,$5)',
      [id, name, email.toLowerCase(), hashed, safeRole]
    );
    res.json({ success: true, message: 'Registrierung erfolgreich' });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'E-Mail bereits registriert' });
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, email, role, phone, hourly_rate, iban FROM users WHERE id = $1', [req.user.id]);
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
  const { name, address, care_level, pflegegrad, betreuer_id, notes, angehoerige_ids, phone, insurance, insurance_number, emergency_contact, birth_date } = req.body;
  try {
    const id = gid('p');
    const pg = pflegegrad || care_level || 1;
    const { rows } = await pool.query(
      `INSERT INTO patients (id, name, address, care_level, pflegegrad, betreuer_id, notes, angehoerige_ids, phone, insurance, insurance_number, emergency_contact, birth_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [id, name, address || '', pg, pg, betreuer_id || (req.user.role === 'betreuer' ? req.user.id : null), notes || '',
       JSON.stringify(angehoerige_ids || []), phone || '', insurance || '', insurance_number || '', emergency_contact || '', birth_date || null]
    );
    await getOrCreateFreibetrag(id, new Date().getFullYear());
    res.json({ ...rows[0], angehoerige_ids: JSON.parse(rows[0].angehoerige_ids || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/patients/:id', auth, async (req, res) => {
  if (!['admin', 'betreuer'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  const { name, address, care_level, pflegegrad, notes, angehoerige_ids, phone, insurance, insurance_number, emergency_contact, betreuer_id, birth_date } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE patients SET name=COALESCE($1,name), address=COALESCE($2,address), care_level=COALESCE($3,care_level),
       pflegegrad=COALESCE($4,pflegegrad), notes=COALESCE($5,notes), angehoerige_ids=COALESCE($6,angehoerige_ids),
       phone=COALESCE($7,phone), insurance=COALESCE($8,insurance), insurance_number=COALESCE($9,insurance_number),
       emergency_contact=COALESCE($10,emergency_contact), betreuer_id=COALESCE($11,betreuer_id), birth_date=COALESCE($12,birth_date)
       WHERE id=$13 RETURNING *`,
      [name, address, care_level, pflegegrad, notes, angehoerige_ids ? JSON.stringify(angehoerige_ids) : null,
       phone, insurance, insurance_number, emergency_contact, betreuer_id, birth_date, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    res.json({ ...rows[0], angehoerige_ids: JSON.parse(rows[0].angehoerige_ids || '[]') });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BESUCHE =====
const parseVisit = (v) => ({ ...v, services: (() => { try { return JSON.parse(v.services || '[]'); } catch { return []; } })() });

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
    res.json(rows.map(parseVisit));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/visits', auth, async (req, res) => {
  const { patient_id, scheduled_at, duration, duration_min, notes, services, service, location, address, betreuer_id } = req.body;
  if (!patient_id || !scheduled_at) return res.status(400).json({ error: 'Patient und Datum erforderlich' });
  try {
    // Berechtigungs-Check: Angehörige nur für eigene Patienten
    if (req.user.role === 'angehoeriger' && !await isAngehoerigerOf(req.user.id, patient_id)) {
      return res.status(403).json({ error: 'Keine Berechtigung für diesen Patienten' });
    }
    const pat = (await pool.query('SELECT * FROM patients WHERE id=$1', [patient_id])).rows[0];
    if (!pat) return res.status(404).json({ error: 'Patient nicht gefunden' });

    const id = gid('v');
    const dur = duration_min || duration || 60;
    const svc = service || (Array.isArray(services) && services[0]) || '';
    // Admin kann direkt zuweisen (status geplant) oder bewusst offen lassen (betreuer_id: null im Body)
    const assignedBetreuer = req.user.role === 'admin'
      ? (betreuer_id !== undefined ? (betreuer_id || null) : (pat.betreuer_id || null))
      : (pat.betreuer_id || null);
    const status = (req.user.role === 'admin' && assignedBetreuer) ? 'geplant' : 'anfrage';

    const { rows } = await pool.query(
      `INSERT INTO visits (id, patient_id, betreuer_id, scheduled_at, duration, duration_min, notes, services, service, location, address, status)
       VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [id, patient_id, assignedBetreuer, scheduled_at, dur, notes || '',
       JSON.stringify(services && services.length ? services : (svc ? [svc] : [])), svc, location || '', address || pat.address || '', status]
    );
    notifyNewAssignment(rows[0]);
    notifyVisitUpdate(id);
    res.json(parseVisit(rows[0]));
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
    notifyVisitUpdate(req.params.id);
    res.json(parseVisit(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bewertung nach Besuch (Angehörige)
app.post('/api/visits/:id/rating', auth, async (req, res) => {
  const { rating, comment } = req.body;
  const r = parseInt(rating);
  if (!r || r < 1 || r > 5) return res.status(400).json({ error: 'Bewertung 1-5 erforderlich' });
  try {
    const visit = (await pool.query('SELECT * FROM visits WHERE id=$1', [req.params.id])).rows[0];
    if (!visit) return res.status(404).json({ error: 'Nicht gefunden' });
    if (req.user.role === 'angehoeriger' && !await isAngehoerigerOf(req.user.id, visit.patient_id)) {
      return res.status(403).json({ error: 'Keine Berechtigung' });
    }
    const { rows } = await pool.query(
      'UPDATE visits SET rating=$1, rating_comment=$2 WHERE id=$3 RETURNING *',
      [r, comment || '', req.params.id]
    );
    res.json(parseVisit(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BETREUER – Aufträge inkl. offener Anfragen =====
app.get('/api/betreuer/visits', auth, requireRole('betreuer', 'admin'), async (req, res) => {
  try {
    const bid = req.user.role === 'admin' ? (req.query.betreuer_id || req.user.id) : req.user.id;
    const { rows } = await pool.query(`
      SELECT v.*, p.name as patient_name, p.address as patient_address, p.pflegegrad, p.phone as patient_phone, p.notes as patient_notes,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id
      WHERE v.betreuer_id = $1
         OR (v.status IN ('anfrage','offen') AND (v.betreuer_id IS NULL OR v.betreuer_id = $1))
      ORDER BY v.scheduled_at ASC
    `, [bid]);
    res.json(rows.map(parseVisit));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BETREUER – Stempeluhr =====
app.patch('/api/visits/:id/clockin', auth, requireRole('betreuer'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'UPDATE visits SET actual_start = NOW(), status = $1, gps_start = COALESCE($4, gps_start) WHERE id = $2 AND betreuer_id = $3 RETURNING *',
      ['unterwegs', req.params.id, req.user.id, req.body?.gps || null]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Besuch nicht gefunden' });
    notifyVisitUpdate(req.params.id);
    res.json(parseVisit(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/visits/:id/clockout', auth, requireRole('betreuer'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE visits SET actual_end = NOW(), status = $1, gps_end = COALESCE($4, gps_end) WHERE id = $2 AND betreuer_id = $3
       RETURNING *, ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden`,
      ['abgeschlossen', req.params.id, req.user.id, req.body?.gps || null]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Besuch nicht gefunden' });
    notifyVisitUpdate(req.params.id);
    res.json(parseVisit(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/betreuer/arbeitszeiten', auth, requireRole('betreuer', 'admin'), async (req, res) => {
  const bid = req.user.role === 'admin' ? (req.query.betreuer_id || req.user.id) : req.user.id;
  try {
    const { rows } = await pool.query(`
      SELECT v.*, p.name as patient_name,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id
      WHERE v.betreuer_id = $1 AND v.actual_start IS NOT NULL
      ORDER BY v.actual_start DESC LIMIT 100
    `, [bid]);
    res.json(rows.map(parseVisit));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Monatsabrechnung des Betreuers: Stunden × Satz = Auszahlung
app.get('/api/betreuer/abrechnung', auth, requireRole('betreuer', 'admin'), async (req, res) => {
  const bid = req.user.role === 'admin' ? (req.query.betreuer_id || req.user.id) : req.user.id;
  const monat = req.query.monat || new Date().toISOString().substring(0, 7); // YYYY-MM
  try {
    const user = (await pool.query('SELECT id, name, hourly_rate, iban FROM users WHERE id=$1', [bid])).rows[0];
    const settings = await getSettings();
    const rate = num(user?.hourly_rate) || num(settings.default_hourly_rate);
    const { rows } = await pool.query(`
      SELECT v.id, v.scheduled_at, v.actual_start, v.actual_end, v.service, v.services, p.name as patient_name,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id
      WHERE v.betreuer_id = $1 AND v.actual_end IS NOT NULL AND to_char(v.actual_end, 'YYYY-MM') = $2
      ORDER BY v.actual_start ASC
    `, [bid, monat]);
    const stunden = rows.reduce((s, r) => s + num(r.stunden), 0);
    res.json({
      monat, betreuer: user?.name, hourly_rate: rate, stunden: Math.round(stunden * 100) / 100,
      auszahlung: Math.round(stunden * rate * 100) / 100,
      eintraege: rows.map(parseVisit)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Anfrage annehmen / ablehnen
app.patch('/api/visits/:id/accept', auth, requireRole('betreuer', 'admin'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'UPDATE visits SET status = $1, betreuer_id = $2 WHERE id = $3 RETURNING *',
      ['geplant', req.user.id, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    notifyVisitUpdate(req.params.id);
    res.json(parseVisit(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/visits/:id/decline', auth, requireRole('betreuer', 'admin'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      "UPDATE visits SET status = 'abgelehnt' WHERE id = $1 RETURNING *", [req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    notifyVisitUpdate(req.params.id);
    res.json(parseVisit(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== BETREUER – Verfügbarkeit =====
app.get('/api/betreuer/availability', auth, requireRole('betreuer', 'admin'), async (req, res) => {
  const bid = req.user.role === 'admin' ? (req.query.betreuer_id || req.user.id) : req.user.id;
  try {
    const { rows } = await pool.query(
      'SELECT * FROM availability WHERE betreuer_id=$1 AND date >= CURRENT_DATE - 7 ORDER BY date', [bid]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/betreuer/availability', auth, requireRole('betreuer', 'admin'), async (req, res) => {
  const { date, available, note, betreuer_id } = req.body;
  const bid = req.user.role === 'admin' ? (betreuer_id || req.user.id) : req.user.id;
  if (!date) return res.status(400).json({ error: 'Datum erforderlich' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO availability (id, betreuer_id, date, available, note) VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (betreuer_id, date) DO UPDATE SET available=$4, note=$5 RETURNING *
    `, [gid('av'), bid, date, available !== false, note || '']);
    res.json(rows[0]);
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
    res.json(rows.map(r => ({ ...r, tasks_done: (() => { try { return JSON.parse(r.tasks_done || '[]'); } catch { return []; } })() })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reports', auth, async (req, res) => {
  const { patient_id, visit_id, content, mood, tasks_done } = req.body;
  if (!patient_id || !content) return res.status(400).json({ error: 'Patient und Inhalt erforderlich' });
  try {
    const id = gid('r');
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
      'INSERT INTO reports (id, patient_id, betreuer_id, visit_id, content, ai_summary, mood, tasks_done) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [id, patient_id, req.user.id, visit_id || null, content, ai_summary, mood || 'gut', JSON.stringify(tasks_done || [])]
    );
    wsBroadcast({ type: 'new_report', report_id: id });
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

// ═══════════════════════════════════════════════════════════════
//  FREIBETRÄGE
// ═══════════════════════════════════════════════════════════════

async function canSeeFreibetrag(user, patientId) {
  if (user.role === 'admin') return true;
  if (user.role === 'angehoeriger') return isAngehoerigerOf(user.id, patientId);
  if (user.role === 'betreuer') {
    const { rows } = await pool.query('SELECT 1 FROM patients WHERE id=$1 AND betreuer_id=$2', [patientId, user.id]);
    return !!rows[0];
  }
  return false;
}

app.get('/api/freibetraege/:patient_id/:year', auth, async (req, res) => {
  try {
    if (!await canSeeFreibetrag(req.user, req.params.patient_id)) return res.status(403).json({ error: 'Keine Berechtigung' });
    const fb = await getOrCreateFreibetrag(req.params.patient_id, parseInt(req.params.year));
    res.json(freibetragSummary(fb));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Wichtig: /check VOR /:year registrieren, sonst matcht :year='check'
app.get('/api/admin/freibetraege/:patient_id/check', auth, adminOnly, async (req, res) => {
  try {
    const fb = await getOrCreateFreibetrag(req.params.patient_id, new Date().getFullYear());
    res.json(freibetragSummary(fb));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/freibetraege/:patient_id/:year', auth, adminOnly, async (req, res) => {
  try {
    const fb = await getOrCreateFreibetrag(req.params.patient_id, parseInt(req.params.year));
    res.json(freibetragSummary(fb));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/freibetraege/:patient_id/:year', auth, adminOnly, async (req, res) => {
  const { freibetrag_35a_max, freibetrag_35a_used, pflegegeld_monatlich, verhinderungspflege_budget,
          verhinderungspflege_used, entlastungsbetrag, entlastungsbetrag_used, notes } = req.body;
  try {
    await getOrCreateFreibetrag(req.params.patient_id, parseInt(req.params.year));
    const { rows } = await pool.query(`
      UPDATE freibetraege SET
        freibetrag_35a_max=COALESCE($1,freibetrag_35a_max), freibetrag_35a_used=COALESCE($2,freibetrag_35a_used),
        pflegegeld_monatlich=COALESCE($3,pflegegeld_monatlich), verhinderungspflege_budget=COALESCE($4,verhinderungspflege_budget),
        verhinderungspflege_used=COALESCE($5,verhinderungspflege_used), entlastungsbetrag=COALESCE($6,entlastungsbetrag),
        entlastungsbetrag_used=COALESCE($7,entlastungsbetrag_used), notes=COALESCE($8,notes)
      WHERE patient_id=$9 AND year=$10 RETURNING *
    `, [freibetrag_35a_max, freibetrag_35a_used, pflegegeld_monatlich, verhinderungspflege_budget,
        verhinderungspflege_used, entlastungsbetrag, entlastungsbetrag_used, notes,
        req.params.patient_id, parseInt(req.params.year)]);
    res.json(freibetragSummary(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
//  RECHNUNGEN
// ═══════════════════════════════════════════════════════════════

async function nextInvoiceNumber() {
  const year = new Date().getFullYear();
  const { rows } = await pool.query(
    "SELECT invoice_number FROM invoices WHERE invoice_number LIKE $1 ORDER BY invoice_number DESC LIMIT 1",
    [`CUR-${year}-%`]
  );
  let n = 1;
  if (rows[0]) n = parseInt(rows[0].invoice_number.split('-')[2]) + 1;
  return `CUR-${year}-${String(n).padStart(3, '0')}`;
}

const parseInvoice = (inv) => ({
  ...inv,
  line_items: (() => { try { return JSON.parse(inv.line_items || '[]'); } catch { return []; } })(),
  // überfällig dynamisch berechnen
  status: (inv.status === 'versendet' && inv.due_date && new Date(inv.due_date) < new Date()) ? 'überfällig' : inv.status
});

// Eigene Rechnungen (Betreuer: eigene Gutschriften; Angehörige: Rechnungen ihrer Patienten)
app.get('/api/invoices', auth, async (req, res) => {
  try {
    let rows;
    if (req.user.role === 'admin') {
      rows = (await pool.query('SELECT * FROM invoices ORDER BY created_at DESC')).rows;
    } else if (req.user.role === 'betreuer') {
      rows = (await pool.query("SELECT * FROM invoices WHERE type='betreuer' AND recipient_id=$1 ORDER BY created_at DESC", [req.user.id])).rows;
    } else {
      rows = (await pool.query(`
        SELECT i.* FROM invoices i JOIN patients p ON i.recipient_id = p.id
        WHERE i.type='kunde' AND p.angehoerige_ids LIKE $1 ORDER BY i.created_at DESC
      `, [`%"${req.user.id}"%`])).rows;
    }
    res.json(rows.map(parseInvoice));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/invoices', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM invoices ORDER BY created_at DESC');
    res.json(rows.map(parseInvoice));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Rechnung automatisch aus Arbeitszeiten erzeugen — Kernstück der Abrechnung
app.post('/api/admin/invoices/generate', auth, adminOnly, async (req, res) => {
  const { recipient_id, type, period_from, period_to,
          apply_entlastung = true, apply_verhinderung = false, sonstige_abzuege = 0, notes } = req.body;
  if (!recipient_id || !type || !period_from || !period_to) {
    return res.status(400).json({ error: 'recipient_id, type, period_from, period_to erforderlich' });
  }
  try {
    const settings = await getSettings();
    const defaultRate = num(settings.default_hourly_rate);
    const mwstSatz = num(settings.mwst_satz);
    let recipientName, lineItems = [], subtotal = 0;
    let abz = { fb35a: 0, vp: 0, entl: 0, sonst: 0 };

    if (type === 'kunde') {
      const pat = (await pool.query('SELECT * FROM patients WHERE id=$1', [recipient_id])).rows[0];
      if (!pat) return res.status(404).json({ error: 'Patient nicht gefunden' });
      recipientName = pat.name;

      const { rows: visits } = await pool.query(`
        SELECT v.*, u.hourly_rate as betreuer_rate,
          ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
        FROM visits v LEFT JOIN users u ON v.betreuer_id = u.id
        WHERE v.patient_id = $1 AND v.actual_end IS NOT NULL
          AND v.actual_end::date >= $2::date AND v.actual_end::date <= $3::date
        ORDER BY v.actual_end ASC
      `, [recipient_id, period_from, period_to]);
      if (!visits.length) return res.status(400).json({ error: 'Keine abgeschlossenen Besuche im Zeitraum' });

      lineItems = visits.map(v => {
        const rate = num(v.hourly_rate) || num(v.betreuer_rate) || defaultRate;
        const hours = num(v.stunden);
        const amount = Math.round(hours * rate * 100) / 100;
        subtotal += amount;
        return {
          date: v.actual_end.toISOString().split('T')[0],
          service: v.service || (() => { try { return JSON.parse(v.services || '[]')[0]; } catch { return ''; } })() || 'Alltagsbegleitung',
          hours, rate, amount, visit_id: v.id
        };
      });
      subtotal = Math.round(subtotal * 100) / 100;

      // Freibeträge automatisch abziehen
      const year = parseInt(period_from.substring(0, 4));
      const fb = await getOrCreateFreibetrag(recipient_id, year);
      const monthly = num(fb.entlastungsbetrag);

      // Entlastungsbetrag §45b: Monate im Zeitraum × Monatsbetrag, gedeckelt durch Jahresrest
      const from = new Date(period_from), to = new Date(period_to);
      const months = (to.getFullYear() - from.getFullYear()) * 12 + (to.getMonth() - from.getMonth()) + 1;
      const entlJahresRest = Math.max(0, monthly * 12 - num(fb.entlastungsbetrag_used));
      if (apply_entlastung) {
        abz.entl = Math.min(subtotal, months * monthly, entlJahresRest);
      }
      // Verhinderungspflege §39 (optional, Pflegegrad 2-5)
      if (apply_verhinderung) {
        const vpRest = Math.max(0, num(fb.verhinderungspflege_budget) - num(fb.verhinderungspflege_used));
        abz.vp = Math.min(subtotal - abz.entl, vpRest);
      }
      abz.sonst = Math.min(Math.max(0, num(sonstige_abzuege)), subtotal - abz.entl - abz.vp);

      const totalAbz = Math.round((abz.entl + abz.vp + abz.sonst) * 100) / 100;
      const netto = Math.round((subtotal - totalAbz) * 100) / 100;
      const mwst = Math.round(netto * mwstSatz) / 100;
      const brutto = Math.round((netto + mwst) * 100) / 100;

      // §35a EStG: 20% der verbleibenden Aufwendungen, gedeckelt durch Jahresmaximum (Hinweis, kein Abzug)
      const rest35a = Math.max(0, num(fb.freibetrag_35a_max) - num(fb.freibetrag_35a_used));
      abz.fb35a = Math.min(Math.round(netto * 20) / 100, rest35a);

      // Budgets fortschreiben
      await pool.query(`
        UPDATE freibetraege SET entlastungsbetrag_used = entlastungsbetrag_used + $1,
          verhinderungspflege_used = verhinderungspflege_used + $2,
          freibetrag_35a_used = freibetrag_35a_used + $3
        WHERE patient_id=$4 AND year=$5
      `, [abz.entl, abz.vp, abz.fb35a, recipient_id, year]);

      const id = gid('inv');
      const invNum = await nextInvoiceNumber();
      const dueDate = new Date(); dueDate.setDate(dueDate.getDate() + (parseInt(settings.zahlungsziel_tage) || 14));
      const { rows } = await pool.query(`
        INSERT INTO invoices (id, invoice_number, type, recipient_id, recipient_name, period_from, period_to,
          line_items, subtotal, freibetrag_35a, pflegegeld_abzug, betreuungsgeld_abzug, sonstige_abzuege,
          total_abzuege, total_netto, mwst_satz, mwst_betrag, total_brutto, status, due_date, notes, created_by)
        VALUES ($1,$2,'kunde',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'entwurf',$18,$19,$20) RETURNING *
      `, [id, invNum, recipient_id, recipientName, period_from, period_to,
          JSON.stringify(lineItems), subtotal, abz.fb35a, abz.vp, abz.entl, abz.sonst,
          totalAbz, netto, mwstSatz, mwst, brutto, dueDate, notes || '', req.user.id]);
      return res.json({ ...parseInvoice(rows[0]), warnung: entlJahresRest <= 0 && apply_entlastung ? 'Entlastungsbetrag-Budget erschöpft!' : null });
    }

    if (type === 'betreuer') {
      const betr = (await pool.query('SELECT * FROM users WHERE id=$1', [recipient_id])).rows[0];
      if (!betr) return res.status(404).json({ error: 'Betreuer nicht gefunden' });
      recipientName = betr.name;
      const rate = num(betr.hourly_rate) || defaultRate;

      const { rows: visits } = await pool.query(`
        SELECT v.*, p.name as patient_name,
          ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
        FROM visits v LEFT JOIN patients p ON v.patient_id = p.id
        WHERE v.betreuer_id = $1 AND v.actual_end IS NOT NULL
          AND v.actual_end::date >= $2::date AND v.actual_end::date <= $3::date
        ORDER BY v.actual_end ASC
      `, [recipient_id, period_from, period_to]);
      if (!visits.length) return res.status(400).json({ error: 'Keine abgeschlossenen Besuche im Zeitraum' });

      lineItems = visits.map(v => {
        const hours = num(v.stunden);
        const amount = Math.round(hours * rate * 100) / 100;
        subtotal += amount;
        return { date: v.actual_end.toISOString().split('T')[0], service: (v.service || 'Einsatz') + ' – ' + (v.patient_name || ''), hours, rate, amount, visit_id: v.id };
      });
      subtotal = Math.round(subtotal * 100) / 100;

      const id = gid('inv');
      const invNum = await nextInvoiceNumber();
      const dueDate = new Date(); dueDate.setDate(dueDate.getDate() + (parseInt(settings.zahlungsziel_tage) || 14));
      const { rows } = await pool.query(`
        INSERT INTO invoices (id, invoice_number, type, recipient_id, recipient_name, period_from, period_to,
          line_items, subtotal, total_netto, total_brutto, status, due_date, notes, created_by)
        VALUES ($1,$2,'betreuer',$3,$4,$5,$6,$7,$8,$8,$8,'entwurf',$9,$10,$11) RETURNING *
      `, [id, invNum, recipient_id, recipientName, period_from, period_to,
          JSON.stringify(lineItems), subtotal, dueDate, notes || '', req.user.id]);
      return res.json(parseInvoice(rows[0]));
    }

    res.status(400).json({ error: "type muss 'kunde' oder 'betreuer' sein" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/invoices/:id/status', auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!['entwurf', 'versendet', 'bezahlt', 'überfällig', 'storniert'].includes(status)) {
    return res.status(400).json({ error: 'Ungültiger Status' });
  }
  try {
    const inv = (await pool.query('SELECT * FROM invoices WHERE id=$1', [req.params.id])).rows[0];
    if (!inv) return res.status(404).json({ error: 'Nicht gefunden' });

    // Bei Stornierung: Freibeträge zurückbuchen
    if (status === 'storniert' && inv.status !== 'storniert' && inv.type === 'kunde') {
      const year = new Date(inv.period_from).getFullYear();
      await pool.query(`
        UPDATE freibetraege SET
          entlastungsbetrag_used = GREATEST(0, entlastungsbetrag_used - $1),
          verhinderungspflege_used = GREATEST(0, verhinderungspflege_used - $2),
          freibetrag_35a_used = GREATEST(0, freibetrag_35a_used - $3)
        WHERE patient_id=$4 AND year=$5
      `, [num(inv.betreuungsgeld_abzug), num(inv.pflegegeld_abzug), num(inv.freibetrag_35a), inv.recipient_id, year]);
    }

    const { rows } = await pool.query(
      `UPDATE invoices SET status=$1, paid_at = CASE WHEN $1='bezahlt' THEN NOW() ELSE paid_at END WHERE id=$2 RETURNING *`,
      [status, req.params.id]
    );
    res.json(parseInvoice(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Zahlung auf Rechnung erfassen
app.post('/api/admin/invoices/:id/payment', auth, adminOnly, async (req, res) => {
  const { amount, payment_date, method, reference, notes } = req.body;
  if (!amount) return res.status(400).json({ error: 'Betrag erforderlich' });
  try {
    const inv = (await pool.query('SELECT * FROM invoices WHERE id=$1', [req.params.id])).rows[0];
    if (!inv) return res.status(404).json({ error: 'Rechnung nicht gefunden' });

    const { rows } = await pool.query(`
      INSERT INTO payments (id, invoice_id, amount, payment_date, method, reference, notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *
    `, [gid('pay'), req.params.id, num(amount), payment_date || new Date().toISOString().split('T')[0],
        method || 'überweisung', reference || '', notes || '']);

    // Rechnung als bezahlt markieren, wenn Summe erreicht
    const sum = (await pool.query('SELECT COALESCE(SUM(amount),0) as s FROM payments WHERE invoice_id=$1', [req.params.id])).rows[0];
    if (num(sum.s) >= num(inv.total_brutto) - 0.005) {
      await pool.query(
        `UPDATE invoices SET status='bezahlt', paid_at=NOW(), payment_method=$1, payment_reference=$2 WHERE id=$3`,
        [method || 'überweisung', reference || '', req.params.id]
      );
    }
    res.json({ payment: rows[0], invoice_paid: num(sum.s) >= num(inv.total_brutto) - 0.005 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== ZAHLUNGEN =====
app.get('/api/admin/payments', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT pay.*, i.invoice_number, i.recipient_name, i.type FROM payments pay
      LEFT JOIN invoices i ON pay.invoice_id = i.id ORDER BY pay.payment_date DESC, pay.created_at DESC
    `);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/payments', auth, adminOnly, async (req, res) => {
  const { invoice_id, amount, payment_date, method, reference, notes } = req.body;
  if (!amount) return res.status(400).json({ error: 'Betrag erforderlich' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO payments (id, invoice_id, amount, payment_date, method, reference, notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *
    `, [gid('pay'), invoice_id || null, num(amount), payment_date || new Date().toISOString().split('T')[0],
        method || 'überweisung', reference || '', notes || '']);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/payments/offen', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT i.*, COALESCE(p.paid, 0) as paid_amount
      FROM invoices i
      LEFT JOIN (SELECT invoice_id, SUM(amount) as paid FROM payments GROUP BY invoice_id) p ON p.invoice_id = i.id
      WHERE i.status NOT IN ('bezahlt','storniert','entwurf')
      ORDER BY i.due_date ASC NULLS LAST
    `);
    res.json(rows.map(r => ({ ...parseInvoice(r), offen: Math.max(0, num(r.total_brutto) - num(r.paid_amount)) })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
//  PDF – Rechnung & Leistungsnachweis (pdfkit)
// ═══════════════════════════════════════════════════════════════

const eur = (n) => num(n).toFixed(2).replace('.', ',') + ' €';
const deDate = (d) => d ? new Date(d).toLocaleDateString('de-DE') : '–';

function pdfInvoice(doc, inv, settings, recipientAddress) {
  const items = typeof inv.line_items === 'string' ? JSON.parse(inv.line_items || '[]') : (inv.line_items || []);
  const M = 50, W = 495;
  const isGutschrift = inv.type === 'betreuer';

  // Kopf
  doc.fillColor('#1C3A2A').fontSize(22).font('Helvetica-Bold').text('Curavio', M, 50);
  doc.fontSize(8).font('Helvetica').fillColor('#666')
     .text('Entlastung. Alltag. Vertrauen.', M, 75);
  doc.fontSize(9).fillColor('#333')
     .text(settings.firma_name || '', 350, 50, { width: 195, align: 'right' })
     .text(settings.firma_adresse || '', 350, 62, { width: 195, align: 'right' })
     .text(settings.firma_telefon || '', 350, 74, { width: 195, align: 'right' })
     .text(settings.firma_email || '', 350, 86, { width: 195, align: 'right' });

  doc.moveTo(M, 105).lineTo(M + W, 105).strokeColor('#C47B3A').lineWidth(1.5).stroke();

  // Empfänger + Metadaten
  doc.fontSize(8).fillColor('#999').text((settings.firma_name || '') + ' · ' + (settings.firma_adresse || ''), M, 120);
  doc.fontSize(11).fillColor('#000').font('Helvetica-Bold').text('AN:', M, 140);
  doc.font('Helvetica').text(inv.recipient_name || '', M, 155);
  if (recipientAddress) doc.fontSize(10).fillColor('#333').text(recipientAddress, M, 170, { width: 250 });

  const metaY = 140;
  doc.fontSize(10).fillColor('#333')
     .text(`${isGutschrift ? 'Gutschriftsnummer' : 'Rechnungsnummer'}: ${inv.invoice_number}`, 320, metaY, { width: 225, align: 'right' })
     .text(`Datum: ${deDate(inv.created_at || new Date())}`, 320, metaY + 14, { width: 225, align: 'right' })
     .text(`Fällig bis: ${deDate(inv.due_date)}`, 320, metaY + 28, { width: 225, align: 'right' })
     .text(`Zeitraum: ${deDate(inv.period_from)} – ${deDate(inv.period_to)}`, 320, metaY + 42, { width: 225, align: 'right' });

  // Titel
  let y = 225;
  doc.fontSize(14).font('Helvetica-Bold').fillColor('#1C3A2A')
     .text(isGutschrift ? 'GUTSCHRIFT / HONORARABRECHNUNG' : 'RECHNUNG / LEISTUNGSNACHWEIS', M, y);
  y += 28;

  // Tabellenkopf
  doc.fontSize(9).font('Helvetica-Bold').fillColor('#333');
  doc.text('Datum', M, y).text('Leistung', M + 75, y, { width: 215 })
     .text('Std.', M + 300, y, { width: 50, align: 'right' })
     .text('Satz', M + 355, y, { width: 60, align: 'right' })
     .text('Betrag', M + 420, y, { width: 75, align: 'right' });
  y += 14;
  doc.moveTo(M, y).lineTo(M + W, y).strokeColor('#ccc').lineWidth(0.5).stroke();
  y += 8;

  doc.font('Helvetica').fillColor('#000');
  items.forEach(it => {
    if (y > 700) { doc.addPage(); y = 60; }
    doc.text(deDate(it.date), M, y)
       .text(String(it.service || '').substring(0, 55), M + 75, y, { width: 215 })
       .text(num(it.hours).toFixed(2).replace('.', ','), M + 300, y, { width: 50, align: 'right' })
       .text(eur(it.rate), M + 355, y, { width: 60, align: 'right' })
       .text(eur(it.amount), M + 420, y, { width: 75, align: 'right' });
    y += 16;
  });

  y += 4;
  doc.moveTo(M, y).lineTo(M + W, y).strokeColor('#ccc').lineWidth(0.5).stroke();
  y += 10;

  const sumLine = (label, val, bold = false, color = '#000') => {
    if (y > 720) { doc.addPage(); y = 60; }
    doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fillColor(color)
       .text(label, M + 150, y, { width: 260, align: 'right' })
       .text(val, M + 420, y, { width: 75, align: 'right' });
    y += 16;
  };

  sumLine('Zwischensumme:', eur(inv.subtotal));

  if (!isGutschrift) {
    if (num(inv.betreuungsgeld_abzug) > 0) sumLine('– Entlastungsbetrag §45b SGB XI:', '-' + eur(inv.betreuungsgeld_abzug), false, '#2D6A4F');
    if (num(inv.pflegegeld_abzug) > 0) sumLine('– Verhinderungspflege §39 SGB XI:', '-' + eur(inv.pflegegeld_abzug), false, '#2D6A4F');
    if (num(inv.sonstige_abzuege) > 0) sumLine('– Sonstige Abzüge:', '-' + eur(inv.sonstige_abzuege), false, '#2D6A4F');
    doc.moveTo(M + 150, y).lineTo(M + W, y).strokeColor('#ccc').lineWidth(0.5).stroke(); y += 8;
    sumLine('Rechnungsbetrag (netto):', eur(inv.total_netto), true);
    sumLine(`MwSt. ${num(inv.mwst_satz).toFixed(0)}% ${num(inv.mwst_satz) === 0 ? '(§4 Nr.16 UStG)' : ''}:`, eur(inv.mwst_betrag));
  }

  doc.moveTo(M + 150, y).lineTo(M + W, y).strokeColor('#1C3A2A').lineWidth(1.5).stroke(); y += 8;
  sumLine(isGutschrift ? 'AUSZAHLUNGSBETRAG:' : 'GESAMT:', eur(inv.total_brutto), true, '#1C3A2A');
  y += 10;

  // §35a-Hinweis
  if (!isGutschrift && num(inv.freibetrag_35a) > 0) {
    if (y > 680) { doc.addPage(); y = 60; }
    doc.rect(M, y, W, 44).fillColor('#FBF0E4').fill();
    doc.fontSize(9).fillColor('#A8652E').font('Helvetica')
       .text('Hinweis: Diese Rechnung ist gemäß §35a EStG als haushaltsnahe Dienstleistung steuerlich absetzbar.', M + 10, y + 8, { width: W - 20 })
       .text(`Mögliche Steuerermäßigung: 20% von ${eur(inv.total_netto)} = ${eur(inv.freibetrag_35a)}`, M + 10, y + 24, { width: W - 20 });
    y += 56;
  }

  // Fuß: Bankverbindung
  if (y > 700) { doc.addPage(); y = 60; }
  doc.fontSize(9).fillColor('#333').font('Helvetica')
     .text(`Bankverbindung: ${settings.firma_bank || ''} · IBAN ${settings.firma_iban || ''}`, M, y + 10)
     .text(`Verwendungszweck: ${inv.invoice_number} / ${inv.recipient_name || ''}`, M, y + 24)
     .text(`Steuernummer: ${settings.firma_steuernummer || ''}`, M, y + 38);
  if (num(inv.mwst_satz) === 0 && !isGutschrift) {
    doc.fontSize(8).fillColor('#999').text(settings.mwst_hinweis || '', M, y + 54);
  }
}

async function sendInvoicePdf(req, res, requireAdmin) {
  try {
    const inv = (await pool.query('SELECT * FROM invoices WHERE id=$1', [req.params.id])).rows[0];
    if (!inv) return res.status(404).json({ error: 'Nicht gefunden' });

    // Zugriff: Admin immer; Betreuer eigene Gutschrift; Angehörige Rechnung ihrer Patienten
    if (req.user.role !== 'admin') {
      if (requireAdmin) return res.status(403).json({ error: 'Keine Berechtigung' });
      if (inv.type === 'betreuer' && inv.recipient_id !== req.user.id) return res.status(403).json({ error: 'Keine Berechtigung' });
      if (inv.type === 'kunde' && !await isAngehoerigerOf(req.user.id, inv.recipient_id)) return res.status(403).json({ error: 'Keine Berechtigung' });
    }

    const settings = await getSettings();
    let addr = '';
    if (inv.type === 'kunde') {
      const p = (await pool.query('SELECT address FROM patients WHERE id=$1', [inv.recipient_id])).rows[0];
      addr = p?.address || '';
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${inv.invoice_number}.pdf"`);
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    doc.pipe(res);
    pdfInvoice(doc, inv, settings, addr);
    doc.end();
  } catch (e) { res.status(500).json({ error: e.message }); }
}

app.get('/api/admin/invoices/:id/pdf', auth, adminOnly, (req, res) => sendInvoicePdf(req, res, true));
app.get('/api/invoices/:id/pdf', auth, (req, res) => sendInvoicePdf(req, res, false));

// Leistungsnachweis für Pflegekasse (pro Besuch)
app.get('/api/admin/leistungsnachweis/:visit_id', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.*, p.name as patient_name, p.address as patient_address, p.pflegegrad, p.insurance, p.insurance_number,
        u.name as betreuer_name,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id LEFT JOIN users u ON v.betreuer_id = u.id
      WHERE v.id = $1
    `, [req.params.visit_id]);
    const v = rows[0];
    if (!v) return res.status(404).json({ error: 'Besuch nicht gefunden' });
    const settings = await getSettings();

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="Leistungsnachweis_${v.id}.pdf"`);
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    doc.pipe(res);

    doc.fillColor('#1C3A2A').fontSize(20).font('Helvetica-Bold').text('Leistungsnachweis', 50, 50);
    doc.fontSize(9).font('Helvetica').fillColor('#666').text(settings.firma_name + ' · ' + settings.firma_adresse, 50, 75);
    doc.moveTo(50, 95).lineTo(545, 95).strokeColor('#C47B3A').lineWidth(1.5).stroke();

    let y = 115;
    const row = (l, v2) => {
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#333').text(l, 50, y, { width: 180 });
      doc.font('Helvetica').fillColor('#000').text(v2 || '–', 230, y, { width: 315 });
      y += 20;
    };
    row('Pflegebedürftige/r:', v.patient_name);
    row('Anschrift:', v.patient_address);
    row('Pflegegrad:', String(v.pflegegrad || v.care_level || '–'));
    row('Pflegekasse:', v.insurance || '–');
    row('Versichertennummer:', v.insurance_number || '–');
    y += 10;
    row('Leistungserbringer/in:', v.betreuer_name || '–');
    row('Datum:', deDate(v.actual_start || v.scheduled_at));
    row('Beginn:', v.actual_start ? new Date(v.actual_start).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) + ' Uhr' : '–');
    row('Ende:', v.actual_end ? new Date(v.actual_end).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) + ' Uhr' : '–');
    row('Dauer:', v.stunden ? num(v.stunden).toFixed(2).replace('.', ',') + ' Stunden' : '–');
    let services = [];
    try { services = JSON.parse(v.services || '[]'); } catch { }
    row('Erbrachte Leistungen:', (v.service ? [v.service] : []).concat(services).filter((s, i, a) => s && a.indexOf(s) === i).join(', ') || 'Alltagsbegleitung');
    row('Rechtsgrundlage:', 'Entlastungsleistungen nach §45b SGB XI');

    y += 30;
    doc.fontSize(9).fillColor('#666').text('Die o.g. Leistungen wurden ordnungsgemäß erbracht:', 50, y);
    y += 50;
    doc.moveTo(50, y).lineTo(250, y).strokeColor('#999').lineWidth(0.5).stroke();
    doc.moveTo(320, y).lineTo(520, y).stroke();
    doc.fontSize(8).text('Unterschrift Leistungserbringer/in', 50, y + 5);
    doc.text('Unterschrift Pflegebedürftige/r bzw. Angehörige/r', 320, y + 5);

    doc.end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
//  BUCHHALTUNG / REPORTS
// ═══════════════════════════════════════════════════════════════

// Monatsabschluss: Einnahmen, Ausgaben, Ergebnis
app.get('/api/admin/buchhaltung/monat/:monat', auth, adminOnly, async (req, res) => {
  const monat = req.params.monat; // YYYY-MM
  try {
    const [einnahmen, ausgabenInv, ausgabenExp, rechnungen] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(pay.amount),0) as s FROM payments pay
                  LEFT JOIN invoices i ON pay.invoice_id = i.id
                  WHERE to_char(pay.payment_date,'YYYY-MM') = $1 AND (i.type IS NULL OR i.type='kunde')`, [monat]),
      pool.query(`SELECT COALESCE(SUM(total_brutto),0) as s FROM invoices
                  WHERE type='betreuer' AND status='bezahlt' AND to_char(paid_at,'YYYY-MM') = $1`, [monat]),
      pool.query(`SELECT COALESCE(SUM(amount),0) as s FROM expenses WHERE to_char(date,'YYYY-MM') = $1`, [monat]),
      pool.query(`SELECT COUNT(*) as n, COALESCE(SUM(total_brutto),0) as s FROM invoices
                  WHERE type='kunde' AND to_char(created_at,'YYYY-MM') = $1 AND status != 'storniert'`, [monat])
    ]);
    const ein = num(einnahmen.rows[0].s);
    const aus = num(ausgabenInv.rows[0].s) + num(ausgabenExp.rows[0].s);
    res.json({
      monat,
      einnahmen: ein,
      ausgaben_betreuer: num(ausgabenInv.rows[0].s),
      ausgaben_sonstige: num(ausgabenExp.rows[0].s),
      ausgaben: aus,
      ergebnis: Math.round((ein - aus) * 100) / 100,
      rechnungen_anzahl: parseInt(rechnungen.rows[0].n),
      rechnungen_volumen: num(rechnungen.rows[0].s)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Betreuer-Abrechnung (Admin-Sicht)
app.get('/api/admin/buchhaltung/betreuer/:id', auth, adminOnly, async (req, res) => {
  const monat = req.query.monat || new Date().toISOString().substring(0, 7);
  try {
    const user = (await pool.query('SELECT id, name, hourly_rate, iban FROM users WHERE id=$1', [req.params.id])).rows[0];
    if (!user) return res.status(404).json({ error: 'Betreuer nicht gefunden' });
    const settings = await getSettings();
    const rate = num(user.hourly_rate) || num(settings.default_hourly_rate);
    const { rows } = await pool.query(`
      SELECT v.id, v.actual_start, v.actual_end, v.service, p.name as patient_name,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id
      WHERE v.betreuer_id = $1 AND v.actual_end IS NOT NULL AND to_char(v.actual_end,'YYYY-MM') = $2
      ORDER BY v.actual_start
    `, [req.params.id, monat]);
    const stunden = rows.reduce((s, r) => s + num(r.stunden), 0);
    res.json({
      betreuer: user, monat, hourly_rate: rate,
      stunden: Math.round(stunden * 100) / 100,
      auszahlung: Math.round(stunden * rate * 100) / 100,
      eintraege: rows
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// CSV-Export für Steuerberater
app.get('/api/admin/buchhaltung/export/csv', auth, adminOnly, async (req, res) => {
  const { von, bis } = req.query;
  try {
    const params = [von || '2000-01-01', bis || '2099-12-31'];
    const [invs, exps, pays] = await Promise.all([
      pool.query(`SELECT * FROM invoices WHERE created_at::date BETWEEN $1::date AND $2::date ORDER BY created_at`, params),
      pool.query(`SELECT e.*, c.name as category FROM expenses e LEFT JOIN expense_categories c ON e.category_id=c.id
                  WHERE e.date BETWEEN $1::date AND $2::date ORDER BY e.date`, params),
      pool.query(`SELECT pay.*, i.invoice_number FROM payments pay LEFT JOIN invoices i ON pay.invoice_id=i.id
                  WHERE pay.payment_date BETWEEN $1::date AND $2::date ORDER BY pay.payment_date`, params)
    ]);
    const csvEsc = (s) => '"' + String(s == null ? '' : s).replace(/"/g, '""') + '"';
    const lines = ['Typ;Datum;Belegnummer;Empfänger/Beschreibung;Netto;MwSt;Brutto;Status'];
    invs.rows.forEach(i => lines.push([
      i.type === 'betreuer' ? 'Gutschrift' : 'Rechnung', deDate(i.created_at), csvEsc(i.invoice_number), csvEsc(i.recipient_name),
      num(i.total_netto).toFixed(2).replace('.', ','), num(i.mwst_betrag).toFixed(2).replace('.', ','),
      num(i.total_brutto).toFixed(2).replace('.', ','), i.status
    ].join(';')));
    pays.rows.forEach(p => lines.push([
      'Zahlungseingang', deDate(p.payment_date), csvEsc(p.invoice_number || p.reference), csvEsc(p.method),
      '', '', num(p.amount).toFixed(2).replace('.', ','), 'gebucht'
    ].join(';')));
    exps.rows.forEach(e => lines.push([
      'Ausgabe', deDate(e.date), csvEsc(e.id), csvEsc((e.category || '') + ': ' + e.description),
      '', '', '-' + num(e.amount).toFixed(2).replace('.', ','), 'gebucht'
    ].join(';')));

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="curavio_buchhaltung.csv"');
    res.send('﻿' + lines.join('\r\n'));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DATEV-ähnlicher Export (vereinfachtes Buchungsstapel-Format)
app.get('/api/admin/buchhaltung/export/datev', auth, adminOnly, async (req, res) => {
  const { von, bis } = req.query;
  try {
    const params = [von || '2000-01-01', bis || '2099-12-31'];
    const { rows } = await pool.query(
      `SELECT * FROM invoices WHERE status != 'storniert' AND created_at::date BETWEEN $1::date AND $2::date ORDER BY created_at`, params);
    const lines = ['Umsatz (ohne Soll/Haben-Kz);Soll/Haben-Kennzeichen;Konto;Gegenkonto (ohne BU-Schlüssel);Belegdatum;Belegfeld 1;Buchungstext'];
    rows.forEach(i => {
      const betrag = num(i.total_brutto).toFixed(2).replace('.', ',');
      const datum = new Date(i.created_at);
      const dd = String(datum.getDate()).padStart(2, '0') + String(datum.getMonth() + 1).padStart(2, '0');
      if (i.type === 'kunde') {
        lines.push(`${betrag};S;10000;8125;${dd};${i.invoice_number};"Erlöse ${i.recipient_name || ''}"`);
      } else {
        lines.push(`${betrag};H;70000;4120;${dd};${i.invoice_number};"Honorar ${i.recipient_name || ''}"`);
      }
    });
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="curavio_datev.csv"');
    res.send('﻿' + lines.join('\r\n'));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== AUSGABEN =====
app.get('/api/admin/expenses', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT e.*, c.name as category_name FROM expenses e
      LEFT JOIN expense_categories c ON e.category_id = c.id ORDER BY e.date DESC LIMIT 200
    `);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/expenses', auth, adminOnly, async (req, res) => {
  const { category_id, description, amount, date, betreuer_id, notes } = req.body;
  if (!description || !amount) return res.status(400).json({ error: 'Beschreibung und Betrag erforderlich' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO expenses (id, category_id, description, amount, date, betreuer_id, notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *
    `, [gid('exp'), category_id || null, description, num(amount), date || new Date().toISOString().split('T')[0], betreuer_id || null, notes || '']);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/expense-categories', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM expense_categories ORDER BY name');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
//  ADMIN / DISPONENT
// ═══════════════════════════════════════════════════════════════

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
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

// KPI-Dashboard für Disponenten
app.get('/api/admin/dashboard', auth, adminOnly, async (req, res) => {
  try {
    const monat = new Date().toISOString().substring(0, 7);
    const heute = new Date().toISOString().substring(0, 10);
    const [umsatzHeute, umsatzMonat, offen, imEinsatz, anfragen, besucheHeute, betreuerAktiv] = await Promise.all([
      pool.query(`SELECT COALESCE(SUM(pay.amount),0) as s FROM payments pay LEFT JOIN invoices i ON pay.invoice_id=i.id
                  WHERE pay.payment_date = $1::date AND (i.type IS NULL OR i.type='kunde')`, [heute]),
      pool.query(`SELECT COALESCE(SUM(pay.amount),0) as s FROM payments pay LEFT JOIN invoices i ON pay.invoice_id=i.id
                  WHERE to_char(pay.payment_date,'YYYY-MM') = $1 AND (i.type IS NULL OR i.type='kunde')`, [monat]),
      pool.query(`SELECT COUNT(*) as n, COALESCE(SUM(total_brutto),0) as s FROM invoices
                  WHERE type='kunde' AND status NOT IN ('bezahlt','storniert','entwurf')`),
      pool.query(`SELECT COUNT(*) as n FROM visits WHERE status='unterwegs'`),
      pool.query(`SELECT COUNT(*) as n FROM visits WHERE status IN ('anfrage','offen')`),
      pool.query(`SELECT COUNT(*) as n FROM visits WHERE scheduled_at::date = $1::date`, [heute]),
      pool.query(`SELECT COUNT(*) as n FROM users WHERE role='betreuer' AND active IS NOT FALSE`)
    ]);
    res.json({
      umsatz_heute: num(umsatzHeute.rows[0].s),
      umsatz_monat: num(umsatzMonat.rows[0].s),
      offene_rechnungen: parseInt(offen.rows[0].n),
      offene_rechnungen_summe: num(offen.rows[0].s),
      betreuer_im_einsatz: parseInt(imEinsatz.rows[0].n),
      offene_anfragen: parseInt(anfragen.rows[0].n),
      besuche_heute: parseInt(besucheHeute.rows[0].n),
      betreuer_aktiv: parseInt(betreuerAktiv.rows[0].n)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Alle Betreuer mit Auslastung
app.get('/api/admin/betreuer', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.name, u.email, u.phone, u.hourly_rate, u.qualifications, u.active, u.iban, u.tax_id,
        COALESCE(w.stunden, 0) as stunden_woche,
        COALESCE(o.offene, 0) as offene_besuche
      FROM users u
      LEFT JOIN (
        SELECT betreuer_id, ROUND(SUM(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0)::numeric, 1) as stunden
        FROM visits WHERE actual_end IS NOT NULL AND actual_end >= date_trunc('week', NOW())
        GROUP BY betreuer_id
      ) w ON w.betreuer_id = u.id
      LEFT JOIN (
        SELECT betreuer_id, COUNT(*) as offene FROM visits
        WHERE status IN ('geplant','bestätigt','unterwegs') GROUP BY betreuer_id
      ) o ON o.betreuer_id = u.id
      WHERE u.role = 'betreuer'
      ORDER BY u.name
    `);
    res.json(rows.map(r => ({
      ...r,
      qualifications: (() => { try { return JSON.parse(r.qualifications || '[]'); } catch { return []; } })(),
      auslastung: Math.min(100, Math.round(num(r.stunden_woche) / 40 * 100))
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Betreuer-Profil bearbeiten (Stundensatz, Qualifikationen, IBAN ...)
app.patch('/api/admin/betreuer/:id', auth, adminOnly, async (req, res) => {
  const { name, phone, hourly_rate, qualifications, active, iban, tax_id } = req.body;
  try {
    const { rows } = await pool.query(`
      UPDATE users SET name=COALESCE($1,name), phone=COALESCE($2,phone), hourly_rate=COALESCE($3,hourly_rate),
        qualifications=COALESCE($4,qualifications), active=COALESCE($5,active), iban=COALESCE($6,iban), tax_id=COALESCE($7,tax_id)
      WHERE id=$8 AND role='betreuer' RETURNING id, name, email, phone, hourly_rate, qualifications, active, iban, tax_id
    `, [name, phone, hourly_rate, qualifications ? JSON.stringify(qualifications) : null, active, iban, tax_id, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Betreuer nicht gefunden' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Betreuer zuweisen (Disponent)
app.patch('/api/admin/visits/:id/assign', auth, adminOnly, async (req, res) => {
  const { betreuer_id } = req.body;
  if (!betreuer_id) return res.status(400).json({ error: 'betreuer_id erforderlich' });
  try {
    const { rows } = await pool.query(
      "UPDATE visits SET betreuer_id=$1, status=CASE WHEN status IN ('anfrage','offen') THEN 'geplant' ELSE status END WHERE id=$2 RETURNING *",
      [betreuer_id, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    notifyNewAssignment(rows[0]);
    notifyVisitUpdate(req.params.id);
    res.json(parseVisit(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Alle Besuche, filterbar
const allVisitsHandler = async (req, res) => {
  const { status, betreuer_id, patient_id, von, bis } = req.query;
  try {
    const conds = [], params = [];
    if (status) { params.push(status); conds.push(`v.status = $${params.length}`); }
    if (betreuer_id) { params.push(betreuer_id); conds.push(`v.betreuer_id = $${params.length}`); }
    if (patient_id) { params.push(patient_id); conds.push(`v.patient_id = $${params.length}`); }
    if (von) { params.push(von); conds.push(`v.scheduled_at >= $${params.length}::date`); }
    if (bis) { params.push(bis); conds.push(`v.scheduled_at < ($${params.length}::date + 1)`); }
    const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT v.*, p.name as patient_name, p.address as patient_address, p.pflegegrad, u.name as betreuer_name,
        ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
      FROM visits v LEFT JOIN patients p ON v.patient_id = p.id LEFT JOIN users u ON v.betreuer_id = u.id
      ${where} ORDER BY v.scheduled_at DESC LIMIT 500
    `, params);
    res.json(rows.map(parseVisit));
  } catch (e) { res.status(500).json({ error: e.message }); }
};
app.get('/api/admin/visits/all', auth, adminOnly, allVisitsHandler);
app.get('/api/admin/visits', auth, adminOnly, allVisitsHandler);

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, email, role, phone, hourly_rate, active, created_at FROM users ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { name, email, password, role, phone, hourly_rate } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, E-Mail, Passwort erforderlich' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (id, name, email, password, role, phone, hourly_rate) VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, name, email, role, phone, hourly_rate`,
      [gid('u'), name, email.toLowerCase(), hashed, role || 'angehoeriger', phone || '', num(hourly_rate)]
    );
    res.json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'E-Mail bereits registriert' });
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/admin/users/:id/role', auth, adminOnly, async (req, res) => {
  const { role } = req.body;
  try {
    const { rows } = await pool.query('UPDATE users SET role=$1 WHERE id=$2 RETURNING id,name,email,role', [role, req.params.id]);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Demo-Daten generieren (idempotent)
app.post('/api/admin/demo', auth, adminOnly, async (req, res) => {
  const client = await pool.connect();
  try {
    await seedDemoData(client);
    res.json({ success: true, message: 'Demo-Daten angelegt (bestehende Datensätze unverändert)' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// ===== EINSTELLUNGEN =====
app.get('/api/admin/settings', auth, adminOnly, async (req, res) => {
  try { res.json(await getSettings()); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/settings', auth, adminOnly, async (req, res) => {
  try {
    for (const [k, v] of Object.entries(req.body || {})) {
      await pool.query('INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', [k, String(v)]);
    }
    res.json(await getSettings());
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== STATIC / SPA =====
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Unbekannte API-Routen nicht an die SPA weiterreichen
app.use('/api', (req, res) => res.status(404).json({ error: 'Route nicht gefunden' }));

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
    console.log('[Admin] http://localhost:' + PORT + '/admin');
    console.log('Demo: thomas@demo.de / curavio123 · admin@curavio.de / admin123');
    console.log('='.repeat(50));
  });

  const wss = new WebSocketServer({ server });
  const rooms = {};

  wss.on('connection', (ws) => {
    wsClients.add(ws);
    ws.authed = false;

    ws.on('message', async (data) => {
      try {
        const msg = JSON.parse(data);

        // Token-Validierung VOR allen anderen Aktionen
        if (msg.type === 'auth') {
          try {
            const u = jwt.verify(msg.token, JWT_SECRET);
            ws.authed = true;
            ws.userId = u.id; ws.userName = u.name; ws.userRole = u.role;
            ws.send(JSON.stringify({ type: 'auth_ok', user_id: u.id }));
          } catch {
            ws.send(JSON.stringify({ type: 'auth_error', error: 'Ungültiger Token' }));
            ws.close();
          }
          return;
        }

        if (!ws.authed) {
          ws.send(JSON.stringify({ type: 'error', error: 'Nicht authentifiziert' }));
          return;
        }

        if (msg.type === 'join') {
          const roomId = msg.roomId || msg.room_id;
          if (!roomId) return;
          ws.roomId = roomId;
          if (!rooms[roomId]) rooms[roomId] = new Set();
          rooms[roomId].add(ws);
          return;
        }

        // 'chat' (neues Format) und 'message' (alt) unterstützen
        if ((msg.type === 'chat' || msg.type === 'message') && msg.content) {
          const roomId = msg.room_id || msg.roomId || ws.roomId;
          if (!roomId) return;
          const message = {
            id: uuidv4(), room_id: roomId, sender_id: ws.userId,
            sender_name: ws.userName, content: String(msg.content).substring(0, 2000),
            created_at: new Date().toISOString()
          };
          try {
            await pool.query('INSERT INTO messages (id, room_id, sender_id, sender_name, content) VALUES ($1,$2,$3,$4,$5)',
              [message.id, message.room_id, message.sender_id, message.sender_name, message.content]);
          } catch { /* ignore */ }
          const payload = JSON.stringify({ type: 'chat', message });
          if (rooms[roomId]) rooms[roomId].forEach(c => { if (c.readyState === 1) c.send(payload); });
        }
      } catch { /* ignore */ }
    });

    ws.on('close', () => {
      wsClients.delete(ws);
      if (ws.roomId && rooms[ws.roomId]) rooms[ws.roomId].delete(ws);
    });
  });
}

start();

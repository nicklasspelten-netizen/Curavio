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
const crypto = require('crypto');
const https = require('https');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'curavio_dev_secret_2024';
const JWT_EXPIRY = '8h'; // DSGVO-TOM: kurze Token-Laufzeit

// ===== DSGVO: Feld-Verschlüsselung AES-256-CBC =====
// Key aus ENCRYPTION_KEY (32-Byte hex); Fallback: aus JWT_SECRET abgeleitet,
// damit Bestandsumgebungen ohne neue Env-Variable nicht brechen.
const ENC_KEY = process.env.ENCRYPTION_KEY && /^[0-9a-f]{64}$/i.test(process.env.ENCRYPTION_KEY)
  ? Buffer.from(process.env.ENCRYPTION_KEY, 'hex')
  : crypto.createHash('sha256').update('curavio_field_enc:' + JWT_SECRET).digest();
if (!process.env.ENCRYPTION_KEY) console.warn('[DSGVO] ENCRYPTION_KEY nicht gesetzt – Fallback-Key aus JWT_SECRET abgeleitet.');

function encryptField(value) {
  if (value == null || value === '') return value || '';
  const s = String(value);
  if (s.startsWith('enc:v1:')) return s; // bereits verschlüsselt
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(s, 'utf8'), cipher.final()]);
  return `enc:v1:${iv.toString('hex')}:${enc.toString('hex')}`;
}

function decryptField(value) {
  if (value == null || value === '') return value || '';
  const s = String(value);
  if (!s.startsWith('enc:v1:')) return s; // Altbestand unverschlüsselt
  try {
    const [, , ivHex, dataHex] = s.split(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, Buffer.from(ivHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
  } catch { return '[Entschlüsselung fehlgeschlagen]'; }
}

const maskIban = (iban) => {
  const v = decryptField(iban);
  return v && v.length > 4 ? '••••' + v.slice(-4) : v || '';
};

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.set('trust proxy', 1); // Render-Proxy: echte Client-IP für Audit-Log & Rate-Limit
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Signatur-PNGs + Personalakten-Dokumente (Base64, max 5 MB/Datei)
app.use(express.static(path.join(__dirname, 'public')));

// ===== DSGVO: Rate-Limiting =====
app.use('/api/', rateLimit({
  windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Zu viele Anfragen – bitte kurz warten.' }
}));
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Zu viele Login-Versuche – bitte 1 Minute warten.' }
});

// ===== DSGVO: Audit-Log =====
async function audit(req, action, resourceType, resourceId) {
  try {
    await pool.query(
      'INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address, user_agent) VALUES ($1,$2,$3,$4,$5,$6)',
      [req.user?.id || null, action, resourceType || '', resourceId != null ? String(resourceId) : '',
       req.ip || '', (req.headers['user-agent'] || '').substring(0, 250)]
    );
  } catch { /* Audit darf den Request nie blockieren */ }
}

const gid = (p) => p + '_' + uuidv4().replace(/-/g, '').substring(0, 12);
const num = (x) => parseFloat(x || 0) || 0;
const escapeHtml = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// ═══════════════════════════════════════════════════════════════
//  E-MAIL-VERSAND (nodemailer) — Konfig aus ENV oder Admin-Einstellungen
// ═══════════════════════════════════════════════════════════════
const APP_URL = process.env.APP_URL || 'https://curavio.onrender.com';
let _mailCache = { key: null, transport: null };

// SMTP-Konfiguration: ENV hat Vorrang, sonst aus settings-Tabelle (Passwort verschlüsselt)
async function getMailConfig() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    return {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: String(process.env.SMTP_SECURE) === 'true' || parseInt(process.env.SMTP_PORT) === 465,
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS || '',
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      source: 'env'
    };
  }
  const s = await getSettings();
  if (s.smtp_host && s.smtp_user) {
    return {
      host: s.smtp_host,
      port: parseInt(s.smtp_port) || 587,
      secure: s.smtp_secure === 'true' || parseInt(s.smtp_port) === 465,
      user: s.smtp_user,
      pass: decryptField(s.smtp_pass || ''),
      from: s.smtp_from || s.firma_email || s.smtp_user,
      source: 'settings'
    };
  }
  return null;
}

async function getTransport() {
  const cfg = await getMailConfig();
  if (!cfg) return null;
  const key = `${cfg.host}:${cfg.port}:${cfg.user}:${cfg.secure}`;
  if (_mailCache.key !== key) {
    _mailCache = {
      key,
      transport: nodemailer.createTransport({
        host: cfg.host, port: cfg.port, secure: cfg.secure,
        auth: { user: cfg.user, pass: cfg.pass }
      }),
      from: cfg.from
    };
  }
  return _mailCache;
}

// HTML-Rahmen im Curavio-Look
function mailLayout(title, bodyHtml, settings) {
  const firma = settings?.firma_name || 'Curavio';
  return `<!DOCTYPE html><html><body style="margin:0;background:#F7F2E4;font-family:Arial,Helvetica,sans-serif;color:#1A2A1E">
  <div style="max-width:560px;margin:0 auto;padding:24px">
    <div style="background:#1C3A2A;border-radius:16px 16px 0 0;padding:22px 26px">
      <div style="color:#F2C98A;font-size:24px;font-weight:bold">Curavio</div>
      <div style="color:rgba(255,255,255,.6);font-size:12px;margin-top:2px">Entlastung. Alltag. Vertrauen.</div>
    </div>
    <div style="background:#FDFAF2;border:1px solid #E0D9C8;border-top:none;border-radius:0 0 16px 16px;padding:26px">
      <h2 style="margin:0 0 14px;font-size:19px;color:#1C3A2A">${escapeHtml(title)}</h2>
      ${bodyHtml}
      <div style="margin-top:22px;padding-top:16px;border-top:1px solid #E0D9C8;font-size:12px;color:#6E7B72">
        ${escapeHtml(firma)}${settings?.firma_adresse ? ' · ' + escapeHtml(settings.firma_adresse) : ''}<br>
        Diese E-Mail wurde automatisch von Curavio gesendet.
      </div>
    </div>
  </div></body></html>`;
}

// Zentrale Versandfunktion. Ohne Konfiguration: kein Fehler, nur Log (graceful).
async function sendMail({ to, subject, html, text }) {
  if (!to) return { skipped: true, reason: 'kein Empfänger' };
  try {
    const t = await getTransport();
    if (!t || !t.transport) {
      console.log(`[EMAIL – nicht konfiguriert] an ${to}: ${subject}`);
      return { skipped: true, reason: 'SMTP nicht konfiguriert' };
    }
    const info = await t.transport.sendMail({
      from: t.from, to, subject,
      text: text || subject,
      html: html || `<p>${escapeHtml(text || subject)}</p>`
    });
    console.log(`[EMAIL gesendet] an ${to}: ${subject} (${info.messageId})`);
    return { sent: true, messageId: info.messageId };
  } catch (e) {
    console.error(`[EMAIL Fehler] an ${to}: ${e.message}`);
    return { error: e.message };
  }
}

// E-Mail-Adressen der Angehörigen eines Patienten
async function emailsForPatient(patientId) {
  try {
    const p = (await pool.query('SELECT angehoerige_ids FROM patients WHERE id=$1', [patientId])).rows[0];
    if (!p) return [];
    const ids = JSON.parse(p.angehoerige_ids || '[]');
    if (!ids.length) return [];
    const { rows } = await pool.query(
      `SELECT email FROM users WHERE id = ANY($1::varchar[]) AND active IS NOT FALSE AND email NOT LIKE 'deleted_%'`, [ids]);
    return rows.map(r => r.email).filter(Boolean);
  } catch { return []; }
}
async function emailForUser(userId) {
  try {
    const { rows } = await pool.query("SELECT email FROM users WHERE id=$1 AND email NOT LIKE 'deleted_%'", [userId]);
    return rows[0]?.email || null;
  } catch { return null; }
}

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
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS cancelled_by VARCHAR(50) DEFAULT '';
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS cancelled_reason TEXT DEFAULT '';
      ALTER TABLE visits ALTER COLUMN betreuer_id DROP NOT NULL;

      ALTER TABLE visits ADD COLUMN IF NOT EXISTS ai_dispatch_note TEXT DEFAULT '';
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS ai_dispatch_confidence DECIMAL(4,2);
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS ai_dispatched_at TIMESTAMP;
      ALTER TABLE visits ADD COLUMN IF NOT EXISTS dispatch_overridden BOOLEAN DEFAULT false;

      ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS hourly_rate DECIMAL(8,2) DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS qualifications TEXT DEFAULT '[]';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT true;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS iban TEXT DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS tax_id VARCHAR(50) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS home_lat DECIMAL(10,7);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS home_lng DECIMAL(10,7);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS shift_start TIME DEFAULT '08:00';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS max_hours_per_day INTEGER DEFAULT 8;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS consent_accepted BOOLEAN DEFAULT false;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS consent_accepted_at TIMESTAMP;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;
      -- HR-Stammdaten (Personalakte Betreuer)
      ALTER TABLE users ADD COLUMN IF NOT EXISTS birth_date DATE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS hired_at DATE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS employment_type VARCHAR(50) DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS hr_notes TEXT DEFAULT '';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT DEFAULT '';
      ALTER TABLE users ALTER COLUMN tax_id TYPE TEXT;

      ALTER TABLE patients ADD COLUMN IF NOT EXISTS pflegegrad INTEGER DEFAULT 1;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS birth_date DATE;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT '';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS insurance VARCHAR(255) DEFAULT '';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS insurance_number TEXT DEFAULT '';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS emergency_contact TEXT DEFAULT '';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS lat DECIMAL(10,7);
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS lng DECIMAL(10,7);
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS address_geocoded BOOLEAN DEFAULT false;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS preferred_time_from TIME;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS preferred_time_to TIME;

      ALTER TABLE reports ADD COLUMN IF NOT EXISTS tasks_done TEXT DEFAULT '[]';

      -- ===== DSGVO-Tabellen =====
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50),
        action VARCHAR(255),
        resource_type VARCHAR(50),
        resource_id VARCHAR(50),
        ip_address VARCHAR(50),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS consents (
        id VARCHAR(50) PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        type VARCHAR(100) NOT NULL,
        version VARCHAR(20),
        accepted BOOLEAN DEFAULT false,
        accepted_at TIMESTAMP,
        ip_address VARCHAR(50),
        revoked_at TIMESTAMP
      );

      -- ===== Leistungsnachweise (digital signiert) =====
      CREATE TABLE IF NOT EXISTS leistungsnachweise (
        id VARCHAR(50) PRIMARY KEY,
        patient_id VARCHAR(50) NOT NULL,
        betreuer_id VARCHAR(50) NOT NULL,
        visit_id VARCHAR(50),
        invoice_id VARCHAR(50),
        ln_number VARCHAR(50) UNIQUE,
        period_from DATE NOT NULL,
        period_to DATE NOT NULL,
        leistungen TEXT DEFAULT '[]',
        signature_client TEXT,
        signed_by_client VARCHAR(255),
        signed_at_client TIMESTAMP,
        signed_ip_client VARCHAR(50),
        signature_betreuer TEXT,
        signed_by_betreuer VARCHAR(255),
        signed_at_betreuer TIMESTAMP,
        status VARCHAR(50) DEFAULT 'ausstehend',
        pdf_url TEXT,
        krankenkasse VARCHAR(255) DEFAULT '',
        eingereicht_at TIMESTAMP,
        notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
      );
      ALTER TABLE leistungsnachweise ADD COLUMN IF NOT EXISTS leistungsart VARCHAR(20) DEFAULT '45b';

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
      -- invoices-Migrationen NACH dem CREATE (sonst Fehler auf frischer DB)
      ALTER TABLE invoices ADD COLUMN IF NOT EXISTS entlastungsbetrag_abzug DECIMAL(10,2) DEFAULT 0;
      ALTER TABLE invoices ADD COLUMN IF NOT EXISTS verhinderungspflege_abzug DECIMAL(10,2) DEFAULT 0;
      ALTER TABLE invoices ADD COLUMN IF NOT EXISTS leistungsnachweis_id VARCHAR(50);
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

      -- Personalakte: Dokumente (Zeugnisse, Führungszeugnis, Nachweise) — in DB,
      -- da das Render-Dateisystem bei jedem Deploy geleert wird
      CREATE TABLE IF NOT EXISTS documents (
        id VARCHAR(50) PRIMARY KEY,
        user_id VARCHAR(50),
        patient_id VARCHAR(50),
        name VARCHAR(255) NOT NULL,
        doc_type VARCHAR(100) DEFAULT 'sonstiges',
        mime VARCHAR(100) DEFAULT 'application/octet-stream',
        data TEXT,
        size_kb INTEGER DEFAULT 0,
        valid_until DATE,
        uploaded_by VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW()
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
      firma_ik_nummer: '',
      firma_anerkennung: '',
      default_hourly_rate: '25.00',
      mwst_satz: '0',
      mwst_hinweis: 'Umsatzsteuerfrei gemäß §4 Nr.16 UStG (soziale Dienstleistung)',
      zahlungsziel_tage: '14',
      datenschutz_hinweis_absage: 'Bei kurzfristiger Absage (< 24 Stunden vor Termin) wird eine Ausfallgebühr gemäß unserer AGB erhoben. Die Verarbeitung Ihrer Buchungsdaten zur Rechnungsstellung erfolgt auf Basis von Art. 6 Abs. 1 lit. b DSGVO (Vertragserfüllung).',
      // E-Mail-Versand (leer = inaktiv; alternativ via ENV SMTP_HOST/SMTP_USER/SMTP_PASS)
      smtp_host: '', smtp_port: '587', smtp_user: '', smtp_pass: '', smtp_from: '', smtp_secure: 'false',
      mail_notifications: 'true'
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
const sendToUser = (userId, obj) => wsBroadcast(obj, ws => ws.userId === userId);
const notifyNewAssignment = (visit) => wsBroadcast(
  { type: 'new_assignment', visit_id: visit.id },
  ws => ws.userRole === 'betreuer' && (!visit.betreuer_id || ws.userId === visit.betreuer_id) || ws.userRole === 'admin'
);

// ===== AUTH ROUTEN =====
const CONSENT_VERSION = '2026-06';

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = rows[0];

    // Konto-Sperre nach 5 Fehlversuchen (15 Min.)
    if (user?.locked_until && new Date(user.locked_until) > new Date()) {
      await audit(req, 'login_blocked_locked', 'user', user.id);
      return res.status(429).json({ error: 'Konto vorübergehend gesperrt. Bitte in 15 Minuten erneut versuchen.' });
    }

    if (!user || !await bcrypt.compare(password, user.password)) {
      if (user) {
        const fails = (user.failed_logins || 0) + 1;
        await pool.query(
          'UPDATE users SET failed_logins=$1, locked_until = CASE WHEN $1 >= 5 THEN NOW() + INTERVAL \'15 minutes\' ELSE locked_until END WHERE id=$2',
          [fails, user.id]
        );
        await audit(req, 'login_failed', 'user', user.id);
      } else {
        await audit(req, 'login_failed_unknown_email', 'user', '');
      }
      return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    }
    if (user.active === false) return res.status(403).json({ error: 'Konto deaktiviert' });

    await pool.query('UPDATE users SET failed_logins=0, locked_until=NULL, last_login=NOW() WHERE id=$1', [user.id]);
    req.user = { id: user.id }; // für Audit-Log (req.ip bleibt erhalten)
    await audit(req, 'login', 'user', user.id);

    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, email: user.email },
      consent_required: user.consent_accepted !== true,
      consent_version: CONSENT_VERSION
    });
  } catch (e) {
    res.status(500).json({ error: 'Server Fehler' });
  }
});

app.post('/api/auth/logout', auth, async (req, res) => {
  await audit(req, 'logout', 'user', req.user.id);
  res.json({ success: true });
});

app.post('/api/auth/register', loginLimiter, async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, E-Mail und Passwort erforderlich' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Passwort: mindestens 8 Zeichen' });
  // Keine Selbst-Registrierung als Admin
  const safeRole = ['angehoeriger', 'betreuer'].includes(role) ? role : 'angehoeriger';
  try {
    const id = gid('u');
    const hashed = await bcrypt.hash(password, 12);
    await pool.query(
      'INSERT INTO users (id, name, email, password, role) VALUES ($1,$2,$3,$4,$5)',
      [id, name, email.toLowerCase(), hashed, safeRole]
    );
    await audit(req, 'user_registered', 'user', id);
    // Willkommens-E-Mail (asynchron, blockiert die Antwort nicht)
    setImmediate(async () => {
      const settings = await getSettings();
      await sendMail({
        to: email.toLowerCase(),
        subject: 'Willkommen bei Curavio',
        html: mailLayout(`Willkommen, ${escapeHtml(name)}!`,
          `<p>Ihr Curavio-Konto wurde erfolgreich erstellt.</p>
           <p>Sie können sich ab sofort anmelden und Termine verwalten, Berichte einsehen und mit Ihrer Betreuungskraft kommunizieren.</p>
           <p style="margin-top:18px"><a href="${APP_URL}" style="background:#C47B3A;color:#fff;text-decoration:none;padding:11px 22px;border-radius:10px;font-weight:bold;display:inline-block">Zur App →</a></p>`,
          settings)
      });
    });
    res.json({ success: true, message: 'Registrierung erfolgreich' });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'E-Mail bereits registriert' });
    res.status(500).json({ error: 'Server Fehler' });
  }
});

// ===== DSGVO: Einwilligungen =====
app.get('/api/me/consents', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM consents WHERE user_id=$1 ORDER BY accepted_at DESC NULLS LAST', [req.user.id]);
    res.json({ consent_version: CONSENT_VERSION, consents: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/me/consent', auth, async (req, res) => {
  const { type, accepted } = req.body;
  const t = type || 'datenschutz';
  try {
    await pool.query(
      'INSERT INTO consents (id, user_id, type, version, accepted, accepted_at, ip_address) VALUES ($1,$2,$3,$4,$5,NOW(),$6)',
      [gid('c'), req.user.id, t, CONSENT_VERSION, accepted !== false, req.ip || '']
    );
    if (t === 'datenschutz' && accepted !== false) {
      await pool.query('UPDATE users SET consent_accepted=true, consent_accepted_at=NOW() WHERE id=$1', [req.user.id]);
    }
    await audit(req, 'consent_' + (accepted !== false ? 'accepted' : 'declined'), 'consent', t);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/me/consent/revoke', auth, async (req, res) => {
  const { type } = req.body;
  try {
    await pool.query(
      'UPDATE consents SET revoked_at=NOW() WHERE user_id=$1 AND type=$2 AND revoked_at IS NULL',
      [req.user.id, type || 'datenschutz']
    );
    if ((type || 'datenschutz') === 'datenschutz') {
      await pool.query('UPDATE users SET consent_accepted=false WHERE id=$1', [req.user.id]);
    }
    await audit(req, 'consent_revoked', 'consent', type || 'datenschutz');
    res.json({ success: true, message: 'Einwilligung widerrufen. Der Zugriff auf die App ist bis zur erneuten Einwilligung gesperrt.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, email, role, phone, address, hourly_rate, iban, consent_accepted, last_login FROM users WHERE id = $1', [req.user.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    res.json({ ...rows[0], iban: maskIban(rows[0].iban) });
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
    await audit(req, 'view_patients', 'patient', rows.length + ' Datensätze');
    res.json(rows.map(p => ({
      ...p,
      angehoerige_ids: JSON.parse(p.angehoerige_ids || '[]'),
      phone: decryptField(p.phone),
      insurance_number: decryptField(p.insurance_number)
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients', auth, async (req, res) => {
  if (!['admin', 'betreuer'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  const { name, address, care_level, pflegegrad, betreuer_id, notes, angehoerige_ids, phone, insurance,
          insurance_number, emergency_contact, birth_date, preferred_time_from, preferred_time_to, lat, lng } = req.body;
  if (!name) return res.status(400).json({ error: 'Name erforderlich' });
  try {
    const id = gid('p');
    const pg = pflegegrad || care_level || 1;
    const hasGeo = lat != null && lng != null && !isNaN(parseFloat(lat));
    const { rows } = await pool.query(
      `INSERT INTO patients (id, name, address, care_level, pflegegrad, betreuer_id, notes, angehoerige_ids,
         phone, insurance, insurance_number, emergency_contact, birth_date, preferred_time_from, preferred_time_to)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
      [id, name, address || '', pg, pg, betreuer_id || (req.user.role === 'betreuer' ? req.user.id : null), notes || '',
       JSON.stringify(angehoerige_ids || []), encryptField(phone || ''), insurance || '', encryptField(insurance_number || ''),
       emergency_contact || '', birth_date || null, preferred_time_from || null, preferred_time_to || null]
    );
    await getOrCreateFreibetrag(id, new Date().getFullYear());
    await audit(req, 'create_patient', 'patient', id);
    // Koordinaten: direkt aus Autocomplete übernehmen, sonst asynchron geocodieren
    if (hasGeo) {
      await pool.query('UPDATE patients SET lat=$1, lng=$2, address_geocoded=true WHERE id=$3', [parseFloat(lat), parseFloat(lng), id]);
    } else if (address) {
      setImmediate(async () => {
        const c = await geocodeAddress(address);
        if (c) await pool.query('UPDATE patients SET lat=$1, lng=$2, address_geocoded=true WHERE id=$3', [c.lat, c.lng, id]).catch(() => {});
      });
    }
    res.json({ ...rows[0], angehoerige_ids: JSON.parse(rows[0].angehoerige_ids || '[]'), phone: phone || '', insurance_number: insurance_number || '' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/patients/:id', auth, async (req, res) => {
  if (!['admin', 'betreuer'].includes(req.user.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  const { name, address, care_level, pflegegrad, notes, angehoerige_ids, phone, insurance, insurance_number,
          emergency_contact, betreuer_id, birth_date, preferred_time_from, preferred_time_to } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE patients SET name=COALESCE($1,name), address=COALESCE($2,address), care_level=COALESCE($3,care_level),
       pflegegrad=COALESCE($4,pflegegrad), notes=COALESCE($5,notes), angehoerige_ids=COALESCE($6,angehoerige_ids),
       phone=COALESCE($7,phone), insurance=COALESCE($8,insurance), insurance_number=COALESCE($9,insurance_number),
       emergency_contact=COALESCE($10,emergency_contact), betreuer_id=COALESCE($11,betreuer_id), birth_date=COALESCE($12,birth_date),
       preferred_time_from=COALESCE($13,preferred_time_from), preferred_time_to=COALESCE($14,preferred_time_to),
       address_geocoded = CASE WHEN $2 IS NOT NULL AND $2 != address THEN false ELSE address_geocoded END
       WHERE id=$15 RETURNING *`,
      [name, address, care_level, pflegegrad, notes, angehoerige_ids ? JSON.stringify(angehoerige_ids) : null,
       phone != null ? encryptField(phone) : null, insurance, insurance_number != null ? encryptField(insurance_number) : null,
       emergency_contact, betreuer_id, birth_date, preferred_time_from, preferred_time_to, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    await audit(req, 'update_patient', 'patient', req.params.id);
    res.json({ ...rows[0], angehoerige_ids: JSON.parse(rows[0].angehoerige_ids || '[]'),
               phone: decryptField(rows[0].phone), insurance_number: decryptField(rows[0].insurance_number) });
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

    // Doppelbelegungs-Schutz (DB-Ebene): überlappende Termine blocken
    const startDt = new Date(scheduled_at);
    const endDt = new Date(startDt.getTime() + dur * 60000);
    if (assignedBetreuer) {
      const { rows: clash } = await pool.query(`
        SELECT id FROM visits
        WHERE betreuer_id = $1
          AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen','storniert')
          AND scheduled_at < $3
          AND (scheduled_at + (COALESCE(duration_min, 60) || ' minutes')::interval) > $2
      `, [assignedBetreuer, startDt.toISOString(), endDt.toISOString()]);
      if (clash.length) return res.status(409).json({
        error: 'Betreuer ist zu dieser Zeit bereits verplant.',
        conflict_visit_id: clash[0].id
      });
    }
    const { rows: patClash } = await pool.query(`
      SELECT id FROM visits
      WHERE patient_id = $1
        AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen','storniert')
        AND scheduled_at < $3
        AND (scheduled_at + (COALESCE(duration_min, 60) || ' minutes')::interval) > $2
    `, [patient_id, startDt.toISOString(), endDt.toISOString()]);
    if (patClash.length) return res.status(409).json({
      error: 'Dieser Patient hat bereits einen Termin zu dieser Zeit.'
    });

    const { rows } = await pool.query(
      `INSERT INTO visits (id, patient_id, betreuer_id, scheduled_at, duration, duration_min, notes, services, service, location, address, status)
       VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [id, patient_id, assignedBetreuer, scheduled_at, dur, notes || '',
       JSON.stringify(services && services.length ? services : (svc ? [svc] : [])), svc, location || '', address || pat.address || '', status]
    );
    notifyNewAssignment(rows[0]);
    notifyVisitUpdate(id);

    // Buchungsbestätigung per E-Mail an die Angehörigen (asynchron)
    setImmediate(async () => {
      const settings = await getSettings();
      const emails = await emailsForPatient(patient_id);
      if (!emails.length) return;
      const dt = new Date(scheduled_at);
      const when = dt.toLocaleDateString('de-DE', { weekday: 'long', day: '2-digit', month: 'long', year: 'numeric' }) +
                   ' um ' + dt.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) + ' Uhr';
      await sendMail({
        to: emails.join(','),
        subject: `Terminbestätigung – ${pat.name}`,
        html: mailLayout('Ihr Termin ist eingegangen',
          `<p>Für <b>${escapeHtml(pat.name)}</b> wurde folgender Besuch ${status === 'anfrage' ? 'angefragt' : 'geplant'}:</p>
           <table style="font-size:14px;margin:12px 0">
             <tr><td style="padding:3px 12px 3px 0;color:#6E7B72">Leistung</td><td><b>${escapeHtml(svc || 'Alltagsbegleitung')}</b></td></tr>
             <tr><td style="padding:3px 12px 3px 0;color:#6E7B72">Termin</td><td><b>${escapeHtml(when)}</b></td></tr>
             <tr><td style="padding:3px 12px 3px 0;color:#6E7B72">Dauer</td><td>${dur} Minuten</td></tr>
             <tr><td style="padding:3px 12px 3px 0;color:#6E7B72">Status</td><td>${status === 'anfrage' ? 'Wird disponiert – Sie erhalten die Bestätigung der Betreuungskraft.' : 'Geplant'}</td></tr>
           </table>
           <p style="margin-top:16px"><a href="${APP_URL}" style="background:#1C3A2A;color:#fff;text-decoration:none;padding:10px 20px;border-radius:10px;font-weight:bold;display:inline-block">Termin in der App ansehen →</a></p>`,
          settings)
      });
    });

    // KI-Disposition: offene Anfragen vollautomatisch zuweisen (asynchron, blockiert Antwort nicht)
    if (status === 'anfrage') {
      setImmediate(() => aiDispatchVisit(id).catch(e => console.error('[KI-Dispatch]', e.message)));
    }

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

// ═══ Terminabsage (alle Rollen) + Ausfallrechnung bei kurzfristiger Absage ═══
app.patch('/api/visits/:id/cancel', auth, async (req, res) => {
  const { reason = '' } = req.body || {};
  try {
    const visit = (await pool.query('SELECT * FROM visits WHERE id=$1', [req.params.id])).rows[0];
    if (!visit) return res.status(404).json({ error: 'Nicht gefunden' });
    if (['abgeschlossen', 'abgesagt', 'storniert'].includes(visit.status)) {
      return res.status(400).json({ error: 'Besuch kann nicht mehr abgesagt werden (Status: ' + visit.status + ')' });
    }

    // Berechtigungsprüfung
    const role = req.user.role, uid = req.user.id;
    if (role === 'angehoeriger') {
      if (!await isAngehoerigerOf(uid, visit.patient_id)) return res.status(403).json({ error: 'Kein Zugriff' });
    } else if (role === 'betreuer') {
      if (visit.betreuer_id !== uid) return res.status(403).json({ error: 'Kein Zugriff' });
    } else if (role !== 'admin') {
      return res.status(403).json({ error: 'Kein Zugriff' });
    }

    // Kurzfristige Absage < 24h? Ausfallgebühr nur bei Absage durch Angehörige
    // (Betreuer-/Admin-Absagen gehen nicht zu Lasten des Kunden)
    const hoursUntil = (new Date(visit.scheduled_at) - new Date()) / 36e5;
    const isLateCancel = role === 'angehoeriger' && hoursUntil < 24 && hoursUntil > 0;

    await pool.query(
      `UPDATE visits SET status='abgesagt', cancelled_by=$1, cancelled_reason=$2,
        notes = COALESCE(notes,'') || $3::text WHERE id=$4`,
      [`${role}:${uid}`, String(reason).substring(0, 500),
       `\n[Absage ${new Date().toLocaleString('de-DE')} durch ${role}: ${reason}]`, req.params.id]
    );

    // Ausfallrechnung
    let ausfallInvoiceId = null, ausfallInvoiceNr = null;
    if (isLateCancel) {
      const settings = await getSettings();
      const betr = visit.betreuer_id ? (await pool.query('SELECT hourly_rate FROM users WHERE id=$1', [visit.betreuer_id])).rows[0] : null;
      const rate = num(visit.hourly_rate) || num(betr?.hourly_rate) || num(settings.default_hourly_rate) || 35;
      const durationH = (visit.duration_min || 60) / 60;
      const cancelFee = Math.round(rate * durationH * 100) / 100;
      const pat = (await pool.query('SELECT name FROM patients WHERE id=$1', [visit.patient_id])).rows[0];

      ausfallInvoiceId = gid('inv');
      ausfallInvoiceNr = 'AUS-' + new Date().getFullYear() + '-' + ausfallInvoiceId.slice(-6).toUpperCase();
      const dueDate = new Date(); dueDate.setDate(dueDate.getDate() + (parseInt(settings.zahlungsziel_tage) || 14));
      await pool.query(`
        INSERT INTO invoices (id, invoice_number, type, recipient_id, recipient_name,
          period_from, period_to, line_items, subtotal, total_netto, total_brutto,
          status, due_date, notes, created_by)
        VALUES ($1,$2,'kunde',$3,$4,$5,$5,$6,$7,$7,$7,'entwurf',$8,$9,$10)
      `, [ausfallInvoiceId, ausfallInvoiceNr, visit.patient_id, pat?.name || 'Klient',
          visit.scheduled_at,
          JSON.stringify([{
            date: new Date(visit.scheduled_at).toISOString().split('T')[0],
            service: `Ausfallgebühr – kurzfristige Absage (< 24h) am ${new Date(visit.scheduled_at).toLocaleDateString('de-DE')}`,
            hours: durationH, rate, amount: cancelFee
          }]),
          cancelFee, dueDate,
          `Automatisch erstellt: Kurzfristige Absage durch ${role}. Gemäß AGB und Datenschutzerklärung (Ausfallgebühren, Art. 6 Abs. 1 lit. b DSGVO).`,
          uid]);
    }

    await audit(req, 'visit_cancelled' + (isLateCancel ? '_late' : ''), 'visit', req.params.id);
    wsBroadcast({
      type: 'visit_cancelled', visit_id: req.params.id, cancelled_by: role, reason,
      is_late_cancel: isLateCancel, ausfall_invoice_id: ausfallInvoiceId
    });
    notifyVisitUpdate(req.params.id);

    // Absage-Benachrichtigung per E-Mail an Angehörige + zugewiesene Betreuungskraft
    setImmediate(async () => {
      const settings = await getSettings();
      const dt = new Date(visit.scheduled_at);
      const when = dt.toLocaleDateString('de-DE', { weekday: 'long', day: '2-digit', month: 'long' }) +
                   ' um ' + dt.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) + ' Uhr';
      const recips = new Set(await emailsForPatient(visit.patient_id));
      if (visit.betreuer_id) { const be = await emailForUser(visit.betreuer_id); if (be) recips.add(be); }
      if (!recips.size) return;
      await sendMail({
        to: [...recips].join(','),
        subject: `Termin abgesagt – ${when}`,
        html: mailLayout('Ein Termin wurde abgesagt',
          `<p>Der Besuch am <b>${escapeHtml(when)}</b> wurde abgesagt${reason ? ` (Grund: ${escapeHtml(reason)})` : ''}.</p>
           ${isLateCancel ? `<p style="background:#FEF3C7;border-radius:8px;padding:12px;color:#B45309">⚠️ Da die Absage kurzfristig (weniger als 24 Stunden vorher) erfolgte, wird gemäß AGB eine Ausfallgebühr berechnet (Rechnung ${escapeHtml(ausfallInvoiceNr)}).</p>` : ''}
           <p style="margin-top:16px"><a href="${APP_URL}" style="background:#1C3A2A;color:#fff;text-decoration:none;padding:10px 20px;border-radius:10px;font-weight:bold;display:inline-block">Zur App →</a></p>`,
          settings)
      });
    });

    res.json({ ok: true, is_late_cancel: isLateCancel, ausfall_invoice_id: ausfallInvoiceId, ausfall_invoice_nr: ausfallInvoiceNr });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ Smart Scheduling: Verfügbarkeit prüfen + Alternativvorschläge ═══
const OVERLAP_SQL = `
  SELECT id, scheduled_at, duration_min, patient_id FROM visits
  WHERE betreuer_id = $1
    AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen','storniert')
    AND scheduled_at < $3
    AND (scheduled_at + (COALESCE(duration_min, 60) || ' minutes')::interval) > $2`;

app.get('/api/availability/check', auth, async (req, res) => {
  const { betreuer_id, date, time } = req.query;
  const duration_min = parseInt(req.query.duration_min) || 60;
  if (!betreuer_id || !date || !time) return res.status(400).json({ error: 'betreuer_id, date, time erforderlich' });
  try {
    const start = new Date(`${date}T${time}:00`);
    if (isNaN(start)) return res.status(400).json({ error: 'Ungültiges Datum/Zeit' });
    const end = new Date(start.getTime() + duration_min * 60000);

    const { rows: conflicts } = await pool.query(OVERLAP_SQL, [betreuer_id, start.toISOString(), end.toISOString()]);
    if (!conflicts.length) return res.json({ available: true });

    // Alternativen: ±2h-Fenster beim gleichen Betreuer
    const alternatives = [];
    for (const delta of [-120, -60, 60, 120, 180, 240]) {
      const altStart = new Date(start.getTime() + delta * 60000);
      if (altStart < new Date()) continue; // keine Vorschläge in der Vergangenheit
      const altEnd = new Date(altStart.getTime() + duration_min * 60000);
      const { rows: c2 } = await pool.query(OVERLAP_SQL, [betreuer_id, altStart.toISOString(), altEnd.toISOString()]);
      if (!c2.length) {
        alternatives.push({
          type: 'same_betreuer', betreuer_id, time: altStart.toISOString(),
          label: `${altStart.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })} Uhr (${delta > 0 ? '+' : ''}${delta / 60}h)`
        });
        if (alternatives.length >= 3) break;
      }
    }
    // Fallback: andere aktive Betreuer zur Wunschzeit
    if (!alternatives.length) {
      const { rows: betreuer } = await pool.query(
        "SELECT id, name FROM users WHERE role='betreuer' AND active IS NOT FALSE AND id != $1", [betreuer_id]);
      for (const b of betreuer) {
        const { rows: c3 } = await pool.query(OVERLAP_SQL, [b.id, start.toISOString(), end.toISOString()]);
        if (!c3.length) {
          alternatives.push({ type: 'alt_betreuer', betreuer_id: b.id, betreuer_name: b.name,
                              time: start.toISOString(), label: `Gleiche Zeit mit ${b.name}` });
          if (alternatives.length >= 3) break;
        }
      }
    }
    res.json({ available: false, conflicts: conflicts.length, alternatives });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ Betreuer-Profil (LinkedIn-Style) — für alle eingeloggten Rollen ═══
app.get('/api/betreuer/:id/profil', auth, async (req, res) => {
  try {
    const u = (await pool.query(
      "SELECT id, name, qualifications, hourly_rate, active, avatar_url, phone, created_at FROM users WHERE id=$1 AND role='betreuer'",
      [req.params.id])).rows[0];
    if (!u) return res.status(404).json({ error: 'Betreuer nicht gefunden' });
    const [stats, ratings] = await Promise.all([
      pool.query(`SELECT COUNT(*) FILTER (WHERE status='abgeschlossen') as done, ROUND(AVG(rating)::numeric, 2) as avg
                  FROM visits WHERE betreuer_id=$1`, [req.params.id]),
      pool.query(`SELECT rating, rating_comment, COALESCE(actual_end, scheduled_at) as date
                  FROM visits WHERE betreuer_id=$1 AND rating IS NOT NULL
                  ORDER BY COALESCE(actual_end, scheduled_at) DESC LIMIT 10`, [req.params.id])
    ]);
    res.json({
      id: u.id, name: u.name,
      qualifications: (() => { try { return JSON.parse(u.qualifications || '[]'); } catch { return []; } })(),
      hourly_rate: num(u.hourly_rate), aktiv: u.active !== false,
      avatar_url: u.avatar_url || '',
      phone: (req.user.role === 'admin' || req.user.id === u.id) ? u.phone : undefined,
      member_since: u.created_at,
      visits_count: parseInt(stats.rows[0].done),
      avg_rating: stats.rows[0].avg,
      bewertungen: ratings.rows.map(r => ({ rating: r.rating, comment: r.rating_comment || '', date: r.date }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ Dispo: Eingehende Buchungen (Queue, letzte 7 Tage) ═══
app.get('/api/admin/bookings/eingang', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.id, v.created_at, v.scheduled_at, v.service, v.services, v.status, v.duration_min,
             v.betreuer_id, v.ai_dispatch_note, v.ai_dispatch_confidence, v.dispatch_overridden,
             p.name as patient_name,
             (SELECT name FROM users WHERE id = (NULLIF(p.angehoerige_ids,'')::json->>0)) as angehoerige_name,
             u.name as betreuer_name
      FROM visits v
      LEFT JOIN patients p ON v.patient_id = p.id
      LEFT JOIN users u ON v.betreuer_id = u.id
      WHERE v.created_at > NOW() - INTERVAL '7 days'
      ORDER BY v.created_at DESC LIMIT 100
    `);
    res.json(rows.map(r => ({
      ...parseVisit(r),
      ai_dispatch_note: (() => { try { return JSON.parse(r.ai_dispatch_note || '{}'); } catch { return {}; } })()
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ Eigene Daten bearbeiten (alle Rollen) + Patientendaten (Angehörige) ═══
app.patch('/api/me/profile', auth, async (req, res) => {
  const { name, phone, address, password, old_password } = req.body;
  try {
    if (password) {
      if (String(password).length < 8) return res.status(400).json({ error: 'Neues Passwort: mindestens 8 Zeichen' });
      const me = (await pool.query('SELECT password FROM users WHERE id=$1', [req.user.id])).rows[0];
      if (!old_password || !await bcrypt.compare(old_password, me.password)) {
        return res.status(403).json({ error: 'Altes Passwort ist falsch' });
      }
      await pool.query('UPDATE users SET password=$1 WHERE id=$2', [await bcrypt.hash(password, 12), req.user.id]);
      await audit(req, 'password_changed', 'user', req.user.id);
    }
    const { rows } = await pool.query(
      `UPDATE users SET name=COALESCE($1,name), phone=COALESCE($2,phone), address=COALESCE($3,address)
       WHERE id=$4 RETURNING id, name, email, role, phone, address`,
      [name, phone, address, req.user.id]
    );
    await audit(req, 'profile_updated', 'user', req.user.id);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/me/patient/:patient_id', auth, async (req, res) => {
  if (req.user.role !== 'angehoeriger' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Keine Berechtigung' });
  }
  try {
    if (req.user.role === 'angehoeriger' && !await isAngehoerigerOf(req.user.id, req.params.patient_id)) {
      return res.status(403).json({ error: 'Kein Zugriff auf diesen Patienten' });
    }
    const { name, address, phone, insurance, insurance_number, notes, pflegegrad } = req.body;
    if (pflegegrad != null && (parseInt(pflegegrad) < 1 || parseInt(pflegegrad) > 5)) {
      return res.status(400).json({ error: 'Pflegegrad muss zwischen 1 und 5 liegen' });
    }
    const { rows } = await pool.query(
      `UPDATE patients SET name=COALESCE($1,name), address=COALESCE($2,address), phone=COALESCE($3,phone),
        insurance=COALESCE($4,insurance), insurance_number=COALESCE($5,insurance_number),
        notes=COALESCE($6,notes), pflegegrad=COALESCE($7,pflegegrad),
        address_geocoded = CASE WHEN $2 IS NOT NULL AND $2 != address THEN false ELSE address_geocoded END
       WHERE id=$8 RETURNING *`,
      [name, address, phone != null ? encryptField(phone) : null,
       insurance, insurance_number != null ? encryptField(insurance_number) : null,
       notes, pflegegrad != null ? parseInt(pflegegrad) : null, req.params.patient_id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    await audit(req, 'patient_data_updated', 'patient', req.params.patient_id);
    if (address) {
      setImmediate(async () => {
        const c = await geocodeAddress(address);
        if (c) await pool.query('UPDATE patients SET lat=$1, lng=$2, address_geocoded=true WHERE id=$3', [c.lat, c.lng, req.params.patient_id]).catch(() => {});
      });
    }
    res.json({ ...rows[0], angehoerige_ids: JSON.parse(rows[0].angehoerige_ids || '[]'),
               phone: decryptField(rows[0].phone), insurance_number: decryptField(rows[0].insurance_number) });
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
    // Dispo informieren: Betreuer hat selbst angenommen
    wsBroadcast({ type: 'assignment_accepted', visit_id: req.params.id, betreuer_id: req.user.id, betreuer_name: req.user.name },
      ws => ws.userRole === 'admin');
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
          apply_entlastung = true, apply_verhinderung = false, apply_35a = true,
          sonstige_abzuege = 0, notes } = req.body;
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
      abz.fb35a = apply_35a ? Math.min(Math.round(netto * 20) / 100, rest35a) : 0;

      // Budgets fortschreiben
      await pool.query(`
        UPDATE freibetraege SET entlastungsbetrag_used = entlastungsbetrag_used + $1,
          verhinderungspflege_used = verhinderungspflege_used + $2,
          freibetrag_35a_used = freibetrag_35a_used + $3
        WHERE patient_id=$4 AND year=$5
      `, [abz.entl, abz.vp, abz.fb35a, recipient_id, year]);

      // Passenden Leistungsnachweis verknüpfen (gleicher Klient + Zeitraum)
      const matchLn = (await pool.query(
        'SELECT id FROM leistungsnachweise WHERE patient_id=$1 AND period_from=$2::date AND period_to=$3::date LIMIT 1',
        [recipient_id, period_from, period_to])).rows[0];

      const id = gid('inv');
      const invNum = await nextInvoiceNumber();
      const dueDate = new Date(); dueDate.setDate(dueDate.getDate() + (parseInt(settings.zahlungsziel_tage) || 14));
      const { rows } = await pool.query(`
        INSERT INTO invoices (id, invoice_number, type, recipient_id, recipient_name, period_from, period_to,
          line_items, subtotal, freibetrag_35a, pflegegeld_abzug, betreuungsgeld_abzug,
          verhinderungspflege_abzug, entlastungsbetrag_abzug, sonstige_abzuege,
          total_abzuege, total_netto, mwst_satz, mwst_betrag, total_brutto, status, due_date, notes, created_by, leistungsnachweis_id)
        VALUES ($1,$2,'kunde',$3,$4,$5,$6,$7,$8,$9,$10,$11,$10,$11,$12,$13,$14,$15,$16,$17,'entwurf',$18,$19,$20,$21) RETURNING *
      `, [id, invNum, recipient_id, recipientName, period_from, period_to,
          JSON.stringify(lineItems), subtotal, abz.fb35a, abz.vp, abz.entl, abz.sonst,
          totalAbz, netto, mwstSatz, mwst, brutto, dueDate, notes || '', req.user.id, matchLn?.id || null]);
      if (matchLn) await pool.query('UPDATE leistungsnachweise SET invoice_id=$1 WHERE id=$2', [id, matchLn.id]);
      await audit(req, 'invoice_generated', 'invoice', invNum);
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
    // Beim Versenden: Rechnung per E-Mail an den Kunden (Angehörige)
    if (status === 'versendet' && inv.status !== 'versendet' && inv.type === 'kunde') {
      setImmediate(async () => {
        const settings = await getSettings();
        const emails = await emailsForPatient(inv.recipient_id);
        if (!emails.length) return;
        await sendMail({
          to: emails.join(','),
          subject: `Ihre Rechnung ${inv.invoice_number}`,
          html: mailLayout(`Rechnung ${escapeHtml(inv.invoice_number)}`,
            `<p>Im Anhang Ihrer Curavio-App finden Sie Ihre Rechnung über <b>${eur(inv.total_brutto)}</b>.</p>
             <p>Fällig bis: <b>${deDate(inv.due_date)}</b></p>
             ${num(inv.freibetrag_35a) > 0 ? `<p style="font-size:13px;color:#A8652E">Hinweis: Diese Leistung ist gemäß §35a EStG steuerlich absetzbar (mögliche Ermäßigung ${eur(inv.freibetrag_35a)}).</p>` : ''}
             <p style="margin-top:16px"><a href="${APP_URL}" style="background:#1C3A2A;color:#fff;text-decoration:none;padding:10px 20px;border-radius:10px;font-weight:bold;display:inline-block">Rechnung in der App öffnen →</a></p>`,
            settings)
        });
      });
    }
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

    await audit(req, 'invoice_pdf_download', 'invoice', inv.invoice_number);
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
    const [offen, bezahlt, betreuerStunden, settings] = await Promise.all([
      pool.query(`SELECT COUNT(*) as n FROM invoices WHERE type='kunde' AND status NOT IN ('bezahlt','storniert','entwurf')`),
      pool.query(`SELECT COUNT(*) as n FROM invoices WHERE type='kunde' AND status='bezahlt' AND to_char(paid_at,'YYYY-MM') = $1`, [monat]),
      pool.query(`
        SELECT u.id, u.name, u.hourly_rate,
          ROUND(SUM(EXTRACT(EPOCH FROM (v.actual_end - v.actual_start))/3600.0)::numeric, 2) as stunden
        FROM visits v JOIN users u ON v.betreuer_id = u.id
        WHERE v.actual_end IS NOT NULL AND to_char(v.actual_end,'YYYY-MM') = $1
        GROUP BY u.id, u.name, u.hourly_rate ORDER BY u.name`, [monat]),
      getSettings()
    ]);
    const defaultRate = num(settings.default_hourly_rate);
    const ein = num(einnahmen.rows[0].s);
    const aus = num(ausgabenInv.rows[0].s) + num(ausgabenExp.rows[0].s);
    res.json({
      monat,
      einnahmen: ein,
      ausgaben_betreuer: num(ausgabenInv.rows[0].s),
      ausgaben_sonstige: num(ausgabenExp.rows[0].s),
      ausgaben: aus,
      ergebnis: Math.round((ein - aus) * 100) / 100,
      offene_rechnungen: parseInt(offen.rows[0].n),
      bezahlte_rechnungen: parseInt(bezahlt.rows[0].n),
      rechnungen_anzahl: parseInt(rechnungen.rows[0].n),
      rechnungen_volumen: num(rechnungen.rows[0].s),
      betreuer: betreuerStunden.rows.map(b => ({
        id: b.id, name: b.name, stunden: num(b.stunden),
        auszahlung: Math.round(num(b.stunden) * (num(b.hourly_rate) || defaultRate) * 100) / 100
      }))
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

    await audit(req, 'export_csv', 'buchhaltung', `${von || ''}-${bis || ''}`);
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
    await audit(req, 'export_datev', 'buchhaltung', `${von || ''}-${bis || ''}`);
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

// Steuer-ID maskieren (analog IBAN)
const maskTaxId = (v) => {
  const d = decryptField(v);
  return d && d.length > 3 ? '•••' + d.slice(-3) : d || '';
};

// Alle Betreuer mit Auslastung + Personalakten-Status (Dokumente, Ablauf-Warnungen)
app.get('/api/admin/betreuer', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.name, u.email, u.phone, u.hourly_rate, u.qualifications, u.active, u.iban, u.tax_id,
        u.address, u.shift_start, u.max_hours_per_day, u.birth_date, u.hired_at, u.employment_type, u.hr_notes,
        COALESCE(w.stunden, 0) as stunden_woche,
        COALESCE(o.offene, 0) as offene_besuche,
        COALESCE(d.docs, 0) as docs_anzahl,
        COALESCE(d.abgelaufen, 0) as docs_abgelaufen,
        COALESCE(d.bald, 0) as docs_bald_ablaufend
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
      LEFT JOIN (
        SELECT user_id, COUNT(*) as docs,
          COUNT(*) FILTER (WHERE valid_until IS NOT NULL AND valid_until < CURRENT_DATE) as abgelaufen,
          COUNT(*) FILTER (WHERE valid_until >= CURRENT_DATE AND valid_until < CURRENT_DATE + 30) as bald
        FROM documents GROUP BY user_id
      ) d ON d.user_id = u.id
      WHERE u.role = 'betreuer'
      ORDER BY u.name
    `);
    res.json(rows.map(r => ({
      ...r,
      iban: maskIban(r.iban),     // DSGVO: nur maskiert in Listen
      tax_id: maskTaxId(r.tax_id),
      qualifications: (() => { try { return JSON.parse(r.qualifications || '[]'); } catch { return []; } })(),
      auslastung: Math.min(100, Math.round(num(r.stunden_woche) / 40 * 100))
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Betreuer-Profil bearbeiten (Personalakte: Stammdaten, Beschäftigung, Finanzen)
app.patch('/api/admin/betreuer/:id', auth, adminOnly, async (req, res) => {
  const { name, phone, hourly_rate, qualifications, active, iban, tax_id, shift_start, max_hours_per_day,
          address, birth_date, hired_at, employment_type, hr_notes } = req.body;
  try {
    // Maskierte Werte aus dem Frontend nicht zurückschreiben
    const ibanVal = (iban != null && !String(iban).startsWith('••••')) ? encryptField(iban) : null;
    const taxVal = (tax_id != null && !String(tax_id).startsWith('•••')) ? encryptField(tax_id) : null;
    const { avatar_url, home_lat, home_lng } = req.body;
    // Heimatkoordinaten aus dem Adress-Autocomplete direkt übernehmen
    if (home_lat != null && home_lng != null && !isNaN(parseFloat(home_lat))) {
      await pool.query('UPDATE users SET home_lat=$1, home_lng=$2 WHERE id=$3',
        [parseFloat(home_lat), parseFloat(home_lng), req.params.id]);
    }
    const { rows } = await pool.query(`
      UPDATE users SET name=COALESCE($1,name), phone=COALESCE($2,phone), hourly_rate=COALESCE($3,hourly_rate),
        qualifications=COALESCE($4,qualifications), active=COALESCE($5,active), iban=COALESCE($6,iban), tax_id=COALESCE($7,tax_id),
        shift_start=COALESCE($8,shift_start), max_hours_per_day=COALESCE($9,max_hours_per_day), address=COALESCE($10,address),
        birth_date=COALESCE($11,birth_date), hired_at=COALESCE($12,hired_at),
        employment_type=COALESCE($13,employment_type), hr_notes=COALESCE($14,hr_notes), avatar_url=COALESCE($15,avatar_url)
      WHERE id=$16 AND role='betreuer'
      RETURNING id, name, email, phone, hourly_rate, qualifications, active, iban, tax_id, shift_start,
                max_hours_per_day, address, birth_date, hired_at, employment_type, hr_notes, avatar_url
    `, [name, phone, hourly_rate, qualifications ? JSON.stringify(qualifications) : null, active, ibanVal, taxVal,
        shift_start, max_hours_per_day, address, birth_date, hired_at, employment_type, hr_notes, avatar_url, req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Betreuer nicht gefunden' });
    await audit(req, 'update_betreuer_profile', 'user', req.params.id);
    res.json({ ...rows[0], iban: maskIban(rows[0].iban), tax_id: maskTaxId(rows[0].tax_id) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ Personalakte: Dokumente (Zeugnisse, Führungszeugnis, Nachweise) ═══
const DOC_MAX_KB = 5 * 1024;

app.post('/api/admin/documents', auth, adminOnly, async (req, res) => {
  const { user_id, patient_id, name, doc_type, data, valid_until } = req.body;
  if (!name || !data || (!user_id && !patient_id)) return res.status(400).json({ error: 'name, data und user_id/patient_id erforderlich' });
  if (!String(data).startsWith('data:')) return res.status(400).json({ error: 'data muss eine Base64-Data-URL sein' });
  try {
    const mime = data.substring(5, data.indexOf(';')) || 'application/octet-stream';
    const b64 = data.split(',')[1] || '';
    const sizeKb = Math.round(b64.length * 0.75 / 1024);
    if (sizeKb > DOC_MAX_KB) return res.status(400).json({ error: `Datei zu groß (${sizeKb} KB, max. ${DOC_MAX_KB} KB)` });
    const { rows } = await pool.query(`
      INSERT INTO documents (id, user_id, patient_id, name, doc_type, mime, data, size_kb, valid_until, uploaded_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      RETURNING id, user_id, patient_id, name, doc_type, mime, size_kb, valid_until, created_at
    `, [gid('doc'), user_id || null, patient_id || null, String(name).substring(0, 250),
        doc_type || 'sonstiges', mime, data, sizeKb, valid_until || null, req.user.id]);
    await audit(req, 'document_uploaded', 'document', rows[0].id);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/documents', auth, adminOnly, async (req, res) => {
  const { user_id, patient_id } = req.query;
  try {
    const conds = [], params = [];
    if (user_id) { params.push(user_id); conds.push(`user_id = $${params.length}`); }
    if (patient_id) { params.push(patient_id); conds.push(`patient_id = $${params.length}`); }
    const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT id, user_id, patient_id, name, doc_type, mime, size_kb, valid_until, created_at
      FROM documents ${where} ORDER BY created_at DESC LIMIT 200
    `, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/documents/:id/download', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM documents WHERE id=$1', [req.params.id]);
    const d = rows[0];
    if (!d) return res.status(404).json({ error: 'Nicht gefunden' });
    await audit(req, 'document_download', 'document', d.id);
    const b64 = (d.data || '').split(',')[1] || '';
    res.setHeader('Content-Type', d.mime || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(d.name)}"`);
    res.send(Buffer.from(b64, 'base64'));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/documents/:id', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('DELETE FROM documents WHERE id=$1 RETURNING id, name', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    await audit(req, 'document_deleted', 'document', req.params.id);
    res.json({ success: true });
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
  const { name, email, password, role, phone, hourly_rate,
          address, iban, tax_id, qualifications, shift_start, max_hours_per_day,
          birth_date, hired_at, employment_type, hr_notes, home_lat, home_lng } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, E-Mail, Passwort erforderlich' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Passwort: mindestens 8 Zeichen' });
  try {
    const hashed = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users (id, name, email, password, role, phone, hourly_rate,
         address, iban, tax_id, qualifications, shift_start, max_hours_per_day,
         birth_date, hired_at, employment_type, hr_notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
       RETURNING id, name, email, role, phone, hourly_rate, address, shift_start, max_hours_per_day,
                 birth_date, hired_at, employment_type`,
      [gid('u'), name, email.toLowerCase(), hashed, role || 'angehoeriger', phone || '', num(hourly_rate),
       address || '', iban ? encryptField(iban) : '', tax_id ? encryptField(tax_id) : '',
       JSON.stringify(qualifications || []), shift_start || '08:00', parseInt(max_hours_per_day) || 8,
       birth_date || null, hired_at || null, employment_type || '', hr_notes || '']
    );
    await audit(req, 'user_created', 'user', rows[0].id);
    // Willkommens-E-Mail an das neue Konto (Zugangsdaten nennt der Admin separat)
    setImmediate(async () => {
      const settings = await getSettings();
      await sendMail({
        to: email.toLowerCase(),
        subject: 'Ihr Curavio-Zugang wurde angelegt',
        html: mailLayout(`Willkommen bei Curavio, ${escapeHtml(name)}!`,
          `<p>Für Sie wurde ein Curavio-Konto als <b>${escapeHtml(role === 'betreuer' ? 'Betreuungskraft' : role === 'admin' ? 'Verwaltung' : 'Angehörige(r)')}</b> angelegt.</p>
           <p>Ihre Anmelde-E-Mail: <b>${escapeHtml(email.toLowerCase())}</b><br>Das Start-Passwort erhalten Sie von Ihrer Verwaltung.</p>
           <p style="margin-top:16px"><a href="${APP_URL}" style="background:#C47B3A;color:#fff;text-decoration:none;padding:11px 22px;border-radius:10px;font-weight:bold;display:inline-block">Zur App →</a></p>`,
          settings)
      });
    });
    // Heimatkoordinaten: aus Autocomplete übernehmen, sonst asynchron geocodieren
    if (home_lat != null && home_lng != null && !isNaN(parseFloat(home_lat))) {
      await pool.query('UPDATE users SET home_lat=$1, home_lng=$2 WHERE id=$3', [parseFloat(home_lat), parseFloat(home_lng), rows[0].id]);
    } else if ((role === 'betreuer') && address) {
      setImmediate(async () => {
        const c = await geocodeAddress(address);
        if (c) await pool.query('UPDATE users SET home_lat=$1, home_lng=$2 WHERE id=$3', [c.lat, c.lng, rows[0].id]).catch(() => {});
      });
    }
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
// SMTP-Passwort nie im Klartext ausliefern – nur Status (gesetzt/leer)
function maskSettings(s) {
  const out = { ...s };
  out.smtp_pass = (s.smtp_pass && s.smtp_pass.length) ? '••••••••' : '';
  return out;
}

app.get('/api/admin/settings', auth, adminOnly, async (req, res) => {
  try {
    const s = maskSettings(await getSettings());
    s.mail_env_configured = !!(process.env.SMTP_HOST && process.env.SMTP_USER); // SMTP via ENV gesetzt?
    res.json(s);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/settings', auth, adminOnly, async (req, res) => {
  try {
    for (const [k, v] of Object.entries(req.body || {})) {
      let val = String(v);
      // SMTP-Passwort verschlüsselt ablegen; maskierten Platzhalter ignorieren
      if (k === 'smtp_pass') {
        if (val.startsWith('••')) continue;        // unverändert gelassen
        val = val ? encryptField(val) : '';
      }
      await pool.query('INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', [k, val]);
    }
    _mailCache = { key: null, transport: null }; // Transport neu aufbauen
    await audit(req, 'settings_updated', 'settings', Object.keys(req.body || {}).join(','));
    res.json(maskSettings(await getSettings()));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// E-Mail-Status + Test-Mail
app.get('/api/admin/mail/status', auth, adminOnly, async (req, res) => {
  const cfg = await getMailConfig();
  res.json({ configured: !!cfg, source: cfg?.source || null, from: cfg?.from || null, host: cfg?.host || null });
});

app.post('/api/admin/mail/test', auth, adminOnly, async (req, res) => {
  const to = req.body?.to;
  if (!to) return res.status(400).json({ error: 'Empfänger-E-Mail (to) erforderlich' });
  const settings = await getSettings();
  const r = await sendMail({
    to, subject: 'Curavio – Test-E-Mail',
    html: mailLayout('Test-E-Mail erfolgreich', '<p>Diese Test-E-Mail bestätigt, dass der E-Mail-Versand von Curavio korrekt konfiguriert ist. 🎉</p>', settings)
  });
  await audit(req, 'mail_test', 'mail', to);
  if (r.error) return res.status(502).json({ error: 'Versand fehlgeschlagen: ' + r.error });
  if (r.skipped) return res.status(400).json({ error: 'E-Mail nicht konfiguriert (SMTP-Daten fehlen).' });
  res.json({ success: true, message: 'Test-E-Mail an ' + to + ' gesendet.' });
});

// ═══════════════════════════════════════════════════════════════
//  DSGVO: Auskunft (Art. 15), Löschung (Art. 17), Portabilität (Art. 20)
// ═══════════════════════════════════════════════════════════════

async function collectUserData(userId) {
  const user = (await pool.query('SELECT id, name, email, role, phone, address, hourly_rate, created_at, last_login, consent_accepted FROM users WHERE id=$1', [userId])).rows[0];
  if (!user) return null;
  const [patients, visits, reports, messages, consents, invoices] = await Promise.all([
    pool.query("SELECT * FROM patients WHERE angehoerige_ids LIKE $1 OR betreuer_id = $2", [`%"${userId}"%`, userId]),
    pool.query('SELECT * FROM visits WHERE betreuer_id=$1 OR patient_id IN (SELECT id FROM patients WHERE angehoerige_ids LIKE $2)', [userId, `%"${userId}"%`]),
    pool.query('SELECT * FROM reports WHERE betreuer_id=$1', [userId]),
    pool.query('SELECT * FROM messages WHERE sender_id=$1', [userId]),
    pool.query('SELECT * FROM consents WHERE user_id=$1', [userId]),
    pool.query("SELECT * FROM invoices WHERE recipient_id=$1", [userId])
  ]);
  return {
    exportiert_am: new Date().toISOString(),
    hinweis: 'Datenauskunft gemäß Art. 15 / Art. 20 DSGVO',
    benutzer: user,
    patienten: patients.rows.map(p => ({ ...p, phone: decryptField(p.phone), insurance_number: decryptField(p.insurance_number) })),
    besuche: visits.rows,
    berichte: reports.rows,
    nachrichten: messages.rows,
    einwilligungen: consents.rows,
    rechnungen: invoices.rows
  };
}

app.get('/api/me/dsgvo/export', auth, async (req, res) => {
  try {
    const data = await collectUserData(req.user.id);
    await audit(req, 'dsgvo_self_export', 'user', req.user.id);
    res.setHeader('Content-Disposition', `attachment; filename="curavio_datenauskunft_${req.user.id}.json"`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/dsgvo/export/:user_id', auth, adminOnly, async (req, res) => {
  try {
    const data = await collectUserData(req.params.user_id);
    if (!data) return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    await audit(req, 'dsgvo_admin_export', 'user', req.params.user_id);
    res.setHeader('Content-Disposition', `attachment; filename="curavio_datenauskunft_${req.params.user_id}.json"`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Pseudonymisierung statt hartem Löschen: Rechnungsdaten 10 Jahre Aufbewahrung (§257 HGB)
app.post('/api/admin/dsgvo/delete/:user_id', auth, adminOnly, async (req, res) => {
  const uid = req.params.user_id;
  try {
    const user = (await pool.query('SELECT * FROM users WHERE id=$1', [uid])).rows[0];
    if (!user) return res.status(404).json({ error: 'Benutzer nicht gefunden' });
    if (user.role === 'admin') return res.status(400).json({ error: 'Admin-Konten können nicht gelöscht werden' });

    await pool.query(`
      UPDATE users SET name='Gelöschter Nutzer', email=$1, password='!gelöscht!', phone='', address='',
        iban='', tax_id='', qualifications='[]', active=false, consent_accepted=false,
        home_lat=NULL, home_lng=NULL
      WHERE id=$2
    `, [`deleted_${uid}@curavio.de`, uid]);
    // Gesundheitsdaten löschen: Berichte + Chat des Nutzers
    await pool.query("UPDATE reports SET content='[gelöscht auf Nutzerwunsch]', ai_summary='' WHERE betreuer_id=$1", [uid]);
    await pool.query("UPDATE messages SET content='[gelöscht]', sender_name='Gelöschter Nutzer' WHERE sender_id=$1", [uid]);
    await audit(req, 'dsgvo_pseudonymized', 'user', uid);
    res.json({ success: true, message: 'Nutzer pseudonymisiert. Rechnungsdaten bleiben gemäß §257 HGB (10 Jahre) erhalten.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/audit-log', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 300');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
//  LEISTUNGSNACHWEISE — digital signiert (eIDAS: einfache el. Signatur)
// ═══════════════════════════════════════════════════════════════

async function nextLnNumber() {
  const year = new Date().getFullYear();
  const { rows } = await pool.query(
    "SELECT ln_number FROM leistungsnachweise WHERE ln_number LIKE $1 ORDER BY ln_number DESC LIMIT 1", [`LN-${year}-%`]);
  let n = 1;
  if (rows[0]) n = parseInt(rows[0].ln_number.split('-')[2]) + 1;
  return `LN-${year}-${String(n).padStart(3, '0')}`;
}

const parseLn = (ln) => ({
  ...ln,
  leistungen: (() => { try { return JSON.parse(ln.leistungen || '[]'); } catch { return []; } })(),
  // Signatur-Bilder nicht in Listen mitschicken (Payload)
  signature_client: ln.signature_client ? true : null,
  signature_betreuer: ln.signature_betreuer ? true : null
});

async function generateLn(patientId, periodFrom, periodTo, createdByReq, leistungsart) {
  const pat = (await pool.query('SELECT * FROM patients WHERE id=$1', [patientId])).rows[0];
  if (!pat) throw new Error('Patient nicht gefunden');
  const { rows: visits } = await pool.query(`
    SELECT v.*, u.name as betreuer_name,
      ROUND(EXTRACT(EPOCH FROM (actual_end - actual_start))/3600.0, 2) as stunden
    FROM visits v LEFT JOIN users u ON v.betreuer_id = u.id
    WHERE v.patient_id = $1 AND v.actual_end IS NOT NULL
      AND v.actual_end::date >= $2::date AND v.actual_end::date <= $3::date
    ORDER BY v.actual_end ASC
  `, [patientId, periodFrom, periodTo]);
  if (!visits.length) return null;

  const deTime = (d) => d ? new Date(d).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' }) : '';
  const leistungen = visits.map(v => ({
    datum: v.actual_end.toISOString().split('T')[0],
    von: deTime(v.actual_start),
    bis: deTime(v.actual_end),
    leistung: v.service || (() => { try { return JSON.parse(v.services || '[]')[0]; } catch { return ''; } })() || 'Alltagsbegleitung',
    stunden: num(v.stunden),
    betreuer: v.betreuer_name || '',
    betreuer_id: v.betreuer_id,
    visit_id: v.id
  }));
  // Hauptbetreuer = häufigster Betreuer im Zeitraum
  const counts = {};
  visits.forEach(v => { if (v.betreuer_id) counts[v.betreuer_id] = (counts[v.betreuer_id] || 0) + 1; });
  const mainBetreuer = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || null;
  if (!mainBetreuer) return null;

  const id = gid('ln');
  const lnNum = await nextLnNumber();
  const art = ['45b', '39', 'selbstzahler'].includes(leistungsart) ? leistungsart : '45b';
  const { rows } = await pool.query(`
    INSERT INTO leistungsnachweise (id, ln_number, patient_id, betreuer_id, period_from, period_to, leistungen, krankenkasse, status, leistungsart)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'ausstehend',$9) RETURNING *
  `, [id, lnNum, patientId, mainBetreuer, periodFrom, periodTo, JSON.stringify(leistungen), pat.insurance || '', art]);
  if (createdByReq) await audit(createdByReq, 'leistungsnachweis_created', 'leistungsnachweis', id);
  return rows[0];
}

app.post('/api/admin/leistungsnachweise/generate', auth, adminOnly, async (req, res) => {
  const { patient_id, period_from, period_to, leistungsart } = req.body;
  if (!patient_id || !period_from || !period_to) return res.status(400).json({ error: 'patient_id, period_from, period_to erforderlich' });
  try {
    const ln = await generateLn(patient_id, period_from, period_to, req, leistungsart);
    if (!ln) return res.status(400).json({ error: 'Keine abgeschlossenen Besuche im Zeitraum' });
    wsBroadcast({ type: 'nachweis_created', id: ln.id });
    res.json(parseLn(ln));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bulk: alle Klienten für einen Monat
app.post('/api/admin/leistungsnachweise/bulk-generate', auth, adminOnly, async (req, res) => {
  const { monat, leistungsart } = req.body; // YYYY-MM
  if (!monat) return res.status(400).json({ error: 'monat (YYYY-MM) erforderlich' });
  try {
    const from = monat + '-01';
    const toD = new Date(parseInt(monat.substring(0, 4)), parseInt(monat.substring(5, 7)), 0);
    const to = `${toD.getFullYear()}-${String(toD.getMonth() + 1).padStart(2, '0')}-${String(toD.getDate()).padStart(2, '0')}`;
    const { rows: pats } = await pool.query('SELECT id, name FROM patients');
    const created = [], skipped = [];
    for (const p of pats) {
      // Kein Duplikat für denselben Zeitraum
      const exists = (await pool.query(
        'SELECT 1 FROM leistungsnachweise WHERE patient_id=$1 AND period_from=$2::date AND period_to=$3::date', [p.id, from, to])).rows[0];
      if (exists) { skipped.push(p.name + ' (existiert)'); continue; }
      const ln = await generateLn(p.id, from, to, req, leistungsart);
      if (ln) created.push(ln.ln_number + ' – ' + p.name);
      else skipped.push(p.name + ' (keine Besuche)');
    }
    res.json({ created, skipped });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/leistungsnachweise', auth, adminOnly, async (req, res) => {
  const { status, patient_id, betreuer_id, monat } = req.query;
  try {
    const conds = [], params = [];
    if (status) { params.push(status); conds.push(`ln.status = $${params.length}`); }
    if (patient_id) { params.push(patient_id); conds.push(`ln.patient_id = $${params.length}`); }
    if (betreuer_id) { params.push(betreuer_id); conds.push(`ln.betreuer_id = $${params.length}`); }
    if (monat) { params.push(monat); conds.push(`to_char(ln.period_from,'YYYY-MM') = $${params.length}`); }
    const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT ln.*, p.name as patient_name, u.name as betreuer_name
      FROM leistungsnachweise ln
      LEFT JOIN patients p ON ln.patient_id = p.id LEFT JOIN users u ON ln.betreuer_id = u.id
      ${where} ORDER BY ln.created_at DESC LIMIT 300
    `, params);
    res.json(rows.map(parseLn));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Eigene Nachweise (Klient: über Patienten; Betreuer: eigene)
app.get('/api/me/leistungsnachweise', auth, async (req, res) => {
  try {
    let rows;
    if (req.user.role === 'betreuer') {
      rows = (await pool.query(`
        SELECT ln.*, p.name as patient_name, u.name as betreuer_name FROM leistungsnachweise ln
        LEFT JOIN patients p ON ln.patient_id = p.id LEFT JOIN users u ON ln.betreuer_id = u.id
        WHERE ln.betreuer_id = $1 ORDER BY ln.created_at DESC
      `, [req.user.id])).rows;
    } else {
      rows = (await pool.query(`
        SELECT ln.*, p.name as patient_name, u.name as betreuer_name FROM leistungsnachweise ln
        JOIN patients p ON ln.patient_id = p.id LEFT JOIN users u ON ln.betreuer_id = u.id
        WHERE p.angehoerige_ids LIKE $1 ORDER BY ln.created_at DESC
      `, [`%"${req.user.id}"%`])).rows;
    }
    res.json(rows.map(parseLn));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Signatur Klient/Angehöriger
app.patch('/api/leistungsnachweise/:id/sign-client', auth, async (req, res) => {
  const { signature, signed_by } = req.body;
  if (!signature || !signature.startsWith('data:image/')) return res.status(400).json({ error: 'Signatur (Base64-PNG) erforderlich' });
  try {
    const ln = (await pool.query('SELECT * FROM leistungsnachweise WHERE id=$1', [req.params.id])).rows[0];
    if (!ln) return res.status(404).json({ error: 'Nicht gefunden' });
    if (req.user.role !== 'admin' && !await isAngehoerigerOf(req.user.id, ln.patient_id)) {
      return res.status(403).json({ error: 'Keine Berechtigung' });
    }
    if (ln.signature_client) return res.status(400).json({ error: 'Bereits unterschrieben' });
    const { rows } = await pool.query(`
      UPDATE leistungsnachweise SET signature_client=$1, signed_by_client=$2, signed_at_client=NOW(),
        signed_ip_client=$3, status = CASE WHEN signature_betreuer IS NOT NULL THEN 'vollstaendig' ELSE 'klient_unterschrieben' END
      WHERE id=$4 RETURNING *
    `, [signature, signed_by || req.user.name || '', req.ip || '', req.params.id]);
    await audit(req, 'leistungsnachweis_signed_client', 'leistungsnachweis', req.params.id);
    wsBroadcast({ type: 'nachweis_signed', id: req.params.id, by: 'client' });
    res.json(parseLn(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Signatur Betreuer
app.patch('/api/leistungsnachweise/:id/sign-betreuer', auth, async (req, res) => {
  const { signature, signed_by } = req.body;
  if (!signature || !signature.startsWith('data:image/')) return res.status(400).json({ error: 'Signatur (Base64-PNG) erforderlich' });
  try {
    const ln = (await pool.query('SELECT * FROM leistungsnachweise WHERE id=$1', [req.params.id])).rows[0];
    if (!ln) return res.status(404).json({ error: 'Nicht gefunden' });
    if (req.user.role !== 'admin' && ln.betreuer_id !== req.user.id) {
      return res.status(403).json({ error: 'Keine Berechtigung' });
    }
    if (ln.signature_betreuer) return res.status(400).json({ error: 'Bereits unterschrieben' });
    const { rows } = await pool.query(`
      UPDATE leistungsnachweise SET signature_betreuer=$1, signed_by_betreuer=$2, signed_at_betreuer=NOW(),
        status = CASE WHEN signature_client IS NOT NULL THEN 'vollstaendig' ELSE status END
      WHERE id=$3 RETURNING *
    `, [signature, signed_by || req.user.name || '', req.params.id]);
    await audit(req, 'leistungsnachweis_signed_betreuer', 'leistungsnachweis', req.params.id);
    wsBroadcast({ type: 'nachweis_signed', id: req.params.id, by: 'betreuer' });
    res.json(parseLn(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/leistungsnachweise/:id/einreichen', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      UPDATE leistungsnachweise SET status='eingereicht', eingereicht_at=NOW()
      WHERE id=$1 AND status='vollstaendig' RETURNING *
    `, [req.params.id]);
    if (!rows[0]) return res.status(400).json({ error: 'Nur vollständig signierte Nachweise können eingereicht werden' });
    await audit(req, 'leistungsnachweis_eingereicht', 'leistungsnachweis', req.params.id);
    res.json(parseLn(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PDF mit beiden Unterschriften
app.get('/api/leistungsnachweise/:id/pdf', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ln.*, p.name as patient_name, p.address as patient_address, p.pflegegrad, p.birth_date,
             p.insurance, p.insurance_number, p.angehoerige_ids
      FROM leistungsnachweise ln LEFT JOIN patients p ON ln.patient_id = p.id WHERE ln.id = $1
    `, [req.params.id]);
    const ln = rows[0];
    if (!ln) return res.status(404).json({ error: 'Nicht gefunden' });

    // Zugriff: Admin, zugewiesener Betreuer, Angehörige des Patienten
    const allowed = req.user.role === 'admin'
      || ln.betreuer_id === req.user.id
      || (JSON.parse(ln.angehoerige_ids || '[]')).includes(req.user.id);
    if (!allowed) return res.status(403).json({ error: 'Keine Berechtigung' });

    await audit(req, 'leistungsnachweis_pdf_download', 'leistungsnachweis', req.params.id);
    const settings = await getSettings();
    const leistungen = JSON.parse(ln.leistungen || '[]');

    // Verknüpfte Rechnung (für Vergütungs-Hinweis)
    let invNum = null;
    if (ln.invoice_id) {
      const inv = (await pool.query('SELECT invoice_number FROM invoices WHERE id=$1', [ln.invoice_id])).rows[0];
      invNum = inv?.invoice_number || null;
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${ln.ln_number || ln.id}.pdf"`);
    const doc = new PDFDocument({ size: 'A4', margin: 40 });
    doc.pipe(res);

    // ═══ Kassenkonforme Vorlage (Aufbau analog Pflegekassen-Vordruck §45b/§39 SGB XI) ═══
    const M = 40, W = 515;
    const from = new Date(ln.period_from), to = new Date(ln.period_to);
    const sameMonth = from.getMonth() === to.getMonth() && from.getFullYear() === to.getFullYear();
    const monLabel = sameMonth
      ? from.toLocaleDateString('de-DE', { month: 'long', year: 'numeric' })
      : deDate(ln.period_from) + ' – ' + deDate(ln.period_to);

    // Kopfzeile
    doc.fillColor('#000').fontSize(15).font('Helvetica-Bold').text('LEISTUNGSNACHWEIS', M, 42);
    doc.fontSize(8.5).font('Helvetica').fillColor('#333')
       .text('über Betreuungs- und Entlastungsleistungen (ambulante Alltagsbegleitung)', M, 60);
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#000')
       .text('Nachweis-Nr.: ' + (ln.ln_number || ln.id), M + 330, 44, { width: 185, align: 'right' });
    doc.font('Helvetica')
       .text('Abrechnungsmonat: ' + monLabel, M + 330, 58, { width: 185, align: 'right' });
    doc.moveTo(M, 78).lineTo(M + W, 78).lineWidth(1).strokeColor('#000').stroke();

    // Zwei Stammdaten-Boxen: Leistungserbringer | Versicherte Person
    const boxY = 86, boxH = 100, colW = Math.floor(W / 2) - 6;
    doc.rect(M, boxY, colW, boxH).lineWidth(0.7).strokeColor('#888').stroke();
    doc.rect(M + colW + 12, boxY, colW, boxH).stroke();
    doc.fontSize(7.5).font('Helvetica-Bold').fillColor('#666')
       .text('LEISTUNGSERBRINGER', M + 8, boxY + 6)
       .text('VERSICHERTE PERSON', M + colW + 20, boxY + 6);

    const lrow = (x, yy, label, value, labW, totW) => {
      doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#000').text(label, x, yy, { width: labW });
      doc.font('Helvetica').text(value || '–', x + labW, yy, { width: totW - labW - 8, height: 12, ellipsis: true });
    };
    let yL = boxY + 19;
    lrow(M + 8, yL, 'Name:', settings.firma_name, 78, colW); yL += 13;
    lrow(M + 8, yL, 'Anschrift:', settings.firma_adresse, 78, colW); yL += 13;
    lrow(M + 8, yL, 'Telefon:', settings.firma_telefon, 78, colW); yL += 13;
    lrow(M + 8, yL, 'IK-Nummer:', settings.firma_ik_nummer || '–', 78, colW); yL += 13;
    lrow(M + 8, yL, 'Anerkennung:', settings.firma_anerkennung || '–', 78, colW); yL += 13;
    doc.fontSize(6.8).fillColor('#666').font('Helvetica')
       .text('(Anerkennung als Angebot zur Unterstützung im Alltag nach §45a SGB XI / Landesrecht)', M + 8, yL, { width: colW - 16 });

    const xR = M + colW + 20;
    let yR = boxY + 19;
    lrow(xR, yR, 'Name:', ln.patient_name, 88, colW); yR += 13;
    lrow(xR, yR, 'Geburtsdatum:', ln.birth_date ? deDate(ln.birth_date) : '–', 88, colW); yR += 13;
    lrow(xR, yR, 'Anschrift:', ln.patient_address, 88, colW); yR += 13;
    lrow(xR, yR, 'Pflegegrad:', String(ln.pflegegrad || '–'), 88, colW); yR += 13;
    lrow(xR, yR, 'Pflegekasse:', ln.insurance || ln.krankenkasse || '–', 88, colW); yR += 13;
    lrow(xR, yR, 'Versicherten-Nr.:', ln.insurance_number ? decryptField(ln.insurance_number) : '–', 88, colW);

    // Leistungsart (ankreuzbar)
    let y = boxY + boxH + 12;
    const art = ln.leistungsart || '45b';
    const checkbox = (x, yy, checked, label) => {
      doc.rect(x, yy, 9, 9).lineWidth(0.9).strokeColor('#000').stroke();
      if (checked) doc.font('Helvetica-Bold').fontSize(9).fillColor('#000').text('X', x + 1.6, yy + 0.5, { lineBreak: false });
      doc.font('Helvetica').fontSize(8.5).fillColor('#000').text(label, x + 14, yy + 1, { lineBreak: false });
    };
    doc.font('Helvetica-Bold').fontSize(8.5).text('Abrechnung als:', M, y + 1, { lineBreak: false });
    checkbox(M + 85, y, art === '45b', 'Entlastungsbetrag §45b SGB XI');
    checkbox(M + 255, y, art === '39', 'Verhinderungspflege §39 SGB XI');
    checkbox(M + 425, y, art === 'selbstzahler', 'Selbstzahler');
    y += 22;

    // Einzelnachweis-Tabelle mit Rahmen
    const cols = [
      { w: 24,  l: 'Nr.' }, { w: 58, l: 'Datum' }, { w: 72, l: 'Uhrzeit von–bis' },
      { w: 170, l: 'Art der Leistung' }, { w: 40, l: 'Std.' },
      { w: 106, l: 'Betreuungskraft' }, { w: 45, l: 'Hz.' }
    ];
    const tableX = M;
    const colX = []; let cx = tableX;
    cols.forEach(c => { colX.push(cx); cx += c.w; });
    const tableW = cx - tableX;
    const rowH = 17;

    const drawHeadRow = (yy) => {
      doc.rect(tableX, yy, tableW, rowH).fillColor('#EFEAD9').fill();
      doc.rect(tableX, yy, tableW, rowH).lineWidth(0.8).strokeColor('#000').stroke();
      cols.forEach((c, i) => {
        doc.font('Helvetica-Bold').fontSize(8).fillColor('#000')
           .text(c.l, colX[i] + 3, yy + 5, { width: c.w - 6, align: i === 4 ? 'right' : 'left', lineBreak: false });
        if (i > 0) doc.moveTo(colX[i], yy).lineTo(colX[i], yy + rowH).lineWidth(0.5).strokeColor('#000').stroke();
      });
      return yy + rowH;
    };

    y = drawHeadRow(y);
    let total = 0;
    const initials = (name) => String(name || '').split(' ').map(p => p[0]).filter(Boolean).join('.').toUpperCase() + '.';
    leistungen.forEach((l, idx) => {
      if (y > 600) { doc.addPage(); y = 50; y = drawHeadRow(y); }
      total += num(l.stunden);
      doc.rect(tableX, y, tableW, rowH).lineWidth(0.5).strokeColor('#888').stroke();
      const cells = [
        String(idx + 1), deDate(l.datum), (l.von && l.bis) ? `${l.von} – ${l.bis}` : '–',
        String(l.leistung || '').substring(0, 42), num(l.stunden).toFixed(2).replace('.', ','),
        String(l.betreuer || ''), initials(l.betreuer)
      ];
      cells.forEach((val, i) => {
        doc.font('Helvetica').fontSize(8).fillColor('#000')
           .text(val, colX[i] + 3, y + 5, { width: cols[i].w - 6, align: i === 4 ? 'right' : 'left', height: 10, ellipsis: true, lineBreak: false });
        if (i > 0) doc.moveTo(colX[i], y).lineTo(colX[i], y + rowH).lineWidth(0.5).strokeColor('#888').stroke();
      });
      y += rowH;
    });
    // Summenzeile
    doc.rect(tableX, y, tableW, rowH).lineWidth(0.8).strokeColor('#000').stroke();
    doc.font('Helvetica-Bold').fontSize(8.5)
       .text('Gesamtstunden im Abrechnungszeitraum:', colX[1] + 3, y + 5, { lineBreak: false })
       .text(total.toFixed(2).replace('.', ','), colX[4] + 3, y + 5, { width: cols[4].w - 6, align: 'right', lineBreak: false });
    y += rowH + 6;
    doc.font('Helvetica').fontSize(7.5).fillColor('#555')
       .text('Hz. = Handzeichen der Betreuungskraft.' + (invNum ? ` Die Vergütung wird mit Rechnung Nr. ${invNum} abgerechnet.` : ''), M, y);
    y += 16;

    // Bestätigung + Abtretung
    if (y > 580) { doc.addPage(); y = 50; }
    doc.font('Helvetica-Bold').fontSize(9).fillColor('#000').text('Bestätigung', M, y); y += 12;
    doc.font('Helvetica').fontSize(8.5).fillColor('#000')
       .text('Hiermit bestätige ich, dass die oben aufgeführten Leistungen an den angegebenen Tagen im angegebenen ' +
             'Umfang ordnungsgemäß erbracht wurden. Mir ist bekannt, dass unrichtige Angaben zum Verlust des ' +
             'Leistungsanspruchs führen können.', M, y, { width: W });
    y += 30;
    if (art !== 'selbstzahler') {
      doc.font('Helvetica-Bold').fontSize(9).text('Abtretungserklärung (bei Direktabrechnung mit der Pflegekasse)', M, y); y += 12;
      doc.font('Helvetica').fontSize(8.5)
         .text('Ich trete meinen Erstattungsanspruch gegenüber der Pflegekasse in Höhe des Rechnungsbetrags für die ' +
               'oben genannten Leistungen an den oben genannten Leistungserbringer ab.', M, y, { width: W });
      y += 28;
    }

    // Unterschriften (digitale Signaturbilder)
    if (y > 600) { doc.addPage(); y = 50; }
    const sigH = 52, sigW = 215;
    doc.fontSize(8.5).font('Helvetica-Bold')
       .text('Versicherte Person / Bevollmächtigte(r):', M, y, { lineBreak: false })
       .text('Betreuungskraft / Leistungserbringer:', M + 280, y, { lineBreak: false });
    y += 13;
    const drawSig = (dataUrl, x) => {
      try { doc.image(Buffer.from(dataUrl.split(',')[1], 'base64'), x, y, { fit: [sigW, sigH] }); }
      catch { doc.fontSize(8).fillColor('#999').text('[Signatur nicht darstellbar]', x, y + 20, { lineBreak: false }); }
    };
    if (ln.signature_client) drawSig(ln.signature_client, M);
    else doc.fontSize(8).fillColor('#999').text('— noch nicht unterschrieben —', M, y + 22, { lineBreak: false });
    if (ln.signature_betreuer) drawSig(ln.signature_betreuer, M + 280);
    else doc.fontSize(8).fillColor('#999').text('— noch nicht unterschrieben —', M + 280, y + 22, { lineBreak: false });
    y += sigH + 4;
    doc.moveTo(M, y).lineTo(M + sigW, y).lineWidth(0.6).strokeColor('#000').stroke();
    doc.moveTo(M + 280, y).lineTo(M + 280 + sigW, y).stroke();
    y += 4;
    doc.fontSize(8).fillColor('#000').font('Helvetica')
       .text((ln.signed_by_client || 'Name in Druckbuchstaben') + (ln.signed_at_client ? ' · ' + deDate(ln.signed_at_client) : ' · Ort, Datum'), M, y, { width: sigW, lineBreak: false })
       .text((ln.signed_by_betreuer || 'Name in Druckbuchstaben') + (ln.signed_at_betreuer ? ' · ' + deDate(ln.signed_at_betreuer) : ' · Ort, Datum'), M + 280, y, { width: sigW, lineBreak: false });
    y += 22;

    // Rechtsfooter digitale Signatur
    if (ln.signature_client || ln.signature_betreuer) {
      doc.moveTo(M, y).lineTo(M + W, y).lineWidth(0.4).strokeColor('#bbb').stroke(); y += 6;
      doc.fontSize(7).fillColor('#777')
         .text(`Dieser Nachweis wurde digital signiert. Signatur-ID: ${ln.ln_number || ln.id} · ` +
               'Rechtsgültig gemäß eIDAS-Verordnung (einfache elektronische Signatur).', M, y, { width: W });
      y += 9;
      doc.text(`Klient: IP ${ln.signed_ip_client || '–'} · Zeitstempel ${ln.signed_at_client ? new Date(ln.signed_at_client).toISOString() : '–'}` +
               ` | Betreuer: Zeitstempel ${ln.signed_at_betreuer ? new Date(ln.signed_at_betreuer).toISOString() : '–'}`, M, y, { width: W });
    }
    doc.end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
//  ROUTENPLANUNG: Geocoding + Tagesrouten + Optimierung
// ═══════════════════════════════════════════════════════════════

function httpJson(method, urlStr, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const data = body ? JSON.stringify(body) : null;
    const r = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method,
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'Curavio/1.0 (Pflegedienst-Software)', ...headers,
                 ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) }
    }, (res2) => {
      let buf = '';
      res2.on('data', d => buf += d);
      res2.on('end', () => { try { resolve(JSON.parse(buf)); } catch { reject(new Error('Ungültige Antwort: ' + buf.substring(0, 120))); } });
    });
    r.on('error', reject);
    r.setTimeout(10000, () => { r.destroy(); reject(new Error('Timeout')); });
    if (data) r.write(data);
    r.end();
  });
}

// Geocoding: ORS bevorzugt, sonst OSM Nominatim (DSGVO: nur Adresse wird übertragen, keine Namen)
async function geocodeAddress(address) {
  if (!address) return null;
  try {
    if (process.env.ORS_API_KEY) {
      const j = await httpJson('GET', `https://api.openrouteservice.org/geocode/search?api_key=${process.env.ORS_API_KEY}&text=${encodeURIComponent(address)}&boundary.country=DE&size=1`);
      const c = j?.features?.[0]?.geometry?.coordinates;
      if (c) return { lat: c[1], lng: c[0] };
    }
    const j = await httpJson('GET', `https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=de&q=${encodeURIComponent(address)}`);
    if (j?.[0]) return { lat: parseFloat(j[0].lat), lng: parseFloat(j[0].lon) };
  } catch { /* unten null */ }
  return null;
}

const haversineKm = (a, b) => {
  if (!a || !b || a.lat == null || b.lat == null) return null;
  const R = 6371, dLat = (b.lat - a.lat) * Math.PI / 180, dLng = (b.lng - a.lng) * Math.PI / 180;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * Math.PI / 180) * Math.cos(b.lat * Math.PI / 180) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.asin(Math.sqrt(h));
};
// Fahrzeit-Schätzung: Luftlinie × 1.4 Straßenfaktor bei Ø 30 km/h Stadtverkehr
const travelMinEstimate = (a, b) => {
  const km = haversineKm(a, b);
  return km == null ? null : Math.round(km * 1.4 / 30 * 60);
};

app.post('/api/admin/geocode/:patient_id', auth, adminOnly, async (req, res) => {
  try {
    const p = (await pool.query('SELECT id, address FROM patients WHERE id=$1', [req.params.patient_id])).rows[0];
    if (!p) return res.status(404).json({ error: 'Patient nicht gefunden' });
    const c = await geocodeAddress(p.address);
    if (!c) return res.status(400).json({ error: 'Adresse konnte nicht geocodiert werden: ' + p.address });
    await pool.query('UPDATE patients SET lat=$1, lng=$2, address_geocoded=true WHERE id=$3', [c.lat, c.lng, p.id]);
    res.json({ id: p.id, ...c });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/geocode/all', auth, adminOnly, async (req, res) => {
  try {
    const { rows: pats } = await pool.query("SELECT id, name, address FROM patients WHERE address_geocoded IS NOT TRUE AND address != ''");
    const ok = [], failed = [];
    for (const p of pats) {
      const c = await geocodeAddress(p.address);
      if (c) { await pool.query('UPDATE patients SET lat=$1, lng=$2, address_geocoded=true WHERE id=$3', [c.lat, c.lng, p.id]); ok.push(p.name); }
      else failed.push(p.name);
      await new Promise(r => setTimeout(r, 1500)); // Nominatim Rate-Limit: 1 Req/1.5s
    }
    // Betreuer-Heimatadressen gleich mit
    const { rows: betr } = await pool.query("SELECT id, name, address FROM users WHERE role='betreuer' AND home_lat IS NULL AND address != ''");
    for (const b of betr) {
      const c = await geocodeAddress(b.address);
      if (c) { await pool.query('UPDATE users SET home_lat=$1, home_lng=$2 WHERE id=$3', [c.lat, c.lng, b.id]); ok.push(b.name + ' (Betreuer)'); }
      await new Promise(r => setTimeout(r, 1500));
    }
    res.json({ geocoded: ok, fehlgeschlagen: failed });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Tagesroute eines Betreuers mit Koordinaten + Reisezeiten
async function buildDayRoute(betreuerId, date) {
  const betr = (await pool.query('SELECT id, name, home_lat, home_lng, shift_start, max_hours_per_day FROM users WHERE id=$1', [betreuerId])).rows[0];
  const { rows: visits } = await pool.query(`
    SELECT v.*, p.name as patient_name, p.address as patient_address, p.lat, p.lng, p.preferred_time_from, p.preferred_time_to
    FROM visits v JOIN patients p ON v.patient_id = p.id
    WHERE v.betreuer_id = $1 AND v.scheduled_at::date = $2::date
      AND v.status NOT IN ('abgelehnt','storniert','abgesagt')
    ORDER BY v.scheduled_at ASC
  `, [betreuerId, date]);
  const stops = visits.map(v => ({
    visit_id: v.id, patient_id: v.patient_id, patient_name: v.patient_name,
    address: v.patient_address, lat: v.lat != null ? parseFloat(v.lat) : null, lng: v.lng != null ? parseFloat(v.lng) : null,
    scheduled_at: v.scheduled_at, duration_min: v.duration_min || 60,
    service: v.service || '', status: v.status,
    preferred_time_from: v.preferred_time_from, preferred_time_to: v.preferred_time_to
  }));
  // Reisezeiten zwischen aufeinanderfolgenden Stopps
  const home = betr?.home_lat != null ? { lat: parseFloat(betr.home_lat), lng: parseFloat(betr.home_lng) } : null;
  let prev = home;
  for (const s of stops) {
    const here = s.lat != null ? { lat: s.lat, lng: s.lng } : null;
    s.travel_min_from_prev = (prev && here) ? travelMinEstimate(prev, here) : null;
    s.km_from_prev = (prev && here) ? Math.round((haversineKm(prev, here) || 0) * 1.4 * 10) / 10 : null;
    if (here) prev = here;
    // Warnung: Reisezeit + Besuch passt nicht in Slot zum nächsten Termin
  }
  for (let i = 0; i < stops.length - 1; i++) {
    const endThis = new Date(stops[i].scheduled_at).getTime() + stops[i].duration_min * 60000;
    const startNext = new Date(stops[i + 1].scheduled_at).getTime();
    const travel = (stops[i + 1].travel_min_from_prev || 0) * 60000;
    stops[i + 1].zeitkonflikt = endThis + travel > startNext;
  }
  return { betreuer: betr ? { id: betr.id, name: betr.name, home_lat: betr.home_lat, home_lng: betr.home_lng, shift_start: betr.shift_start } : null, date, stops };
}

app.get('/api/admin/route/:betreuer_id/:date', auth, adminOnly, async (req, res) => {
  try { res.json(await buildDayRoute(req.params.betreuer_id, req.params.date)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Optimierte Reihenfolge: Nearest Neighbor ab Betreuer-Heimat (oder erstem Stopp)
app.post('/api/admin/route/optimize', auth, adminOnly, async (req, res) => {
  const { betreuer_id, date } = req.body;
  if (!betreuer_id || !date) return res.status(400).json({ error: 'betreuer_id und date erforderlich' });
  try {
    const route = await buildDayRoute(betreuer_id, date);
    const geocoded = route.stops.filter(s => s.lat != null);
    if (geocoded.length < 2) return res.status(400).json({ error: 'Zu wenige geocodierte Stopps (erst Geocoding ausführen)' });

    const start = route.betreuer?.home_lat != null
      ? { lat: parseFloat(route.betreuer.home_lat), lng: parseFloat(route.betreuer.home_lng) }
      : { lat: geocoded[0].lat, lng: geocoded[0].lng };

    const remaining = [...geocoded];
    const ordered = [];
    let cur = start;
    while (remaining.length) {
      remaining.sort((a, b) => (haversineKm(cur, a) || 1e9) - (haversineKm(cur, b) || 1e9));
      const next = remaining.shift();
      ordered.push(next);
      cur = { lat: next.lat, lng: next.lng };
    }
    // Neue Zeiten: ab Schichtstart bzw. erster geplanter Zeit
    const dayStart = new Date(date + 'T' + (route.betreuer?.shift_start || '08:00'));
    const firstPlanned = new Date(Math.min(...route.stops.map(s => new Date(s.scheduled_at).getTime())));
    let t = isNaN(dayStart) ? firstPlanned : new Date(Math.max(dayStart.getTime(), 0) === 0 ? firstPlanned : dayStart);
    if (isNaN(t)) t = firstPlanned;
    let prev = start;
    const plan = ordered.map(s => {
      const travel = travelMinEstimate(prev, { lat: s.lat, lng: s.lng }) || 0;
      t = new Date(t.getTime() + travel * 60000);
      // Wunschzeitfenster respektieren (frühestens preferred_time_from)
      if (s.preferred_time_from) {
        const pref = new Date(date + 'T' + s.preferred_time_from);
        if (!isNaN(pref) && t < pref) t = pref;
      }
      const entry = {
        visit_id: s.visit_id, patient_name: s.patient_name,
        old_time: s.scheduled_at, new_time: t.toISOString(),
        travel_min: travel
      };
      t = new Date(t.getTime() + s.duration_min * 60000);
      prev = { lat: s.lat, lng: s.lng };
      return entry;
    });
    res.json({ betreuer_id, date, plan });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Optimierte Zeiten übernehmen + Benachrichtigungen bei Δ > 15 Min.
app.patch('/api/admin/route/apply', auth, adminOnly, async (req, res) => {
  const { changes } = req.body; // [{visit_id, new_time}]
  if (!Array.isArray(changes) || !changes.length) return res.status(400).json({ error: 'changes[] erforderlich' });
  try {
    const applied = [];
    for (const c of changes) {
      const old = (await pool.query('SELECT scheduled_at, betreuer_id, patient_id FROM visits WHERE id=$1', [c.visit_id])).rows[0];
      if (!old) continue;
      await pool.query('UPDATE visits SET scheduled_at=$1 WHERE id=$2', [c.new_time, c.visit_id]);
      const deltaMin = Math.abs(new Date(c.new_time) - new Date(old.scheduled_at)) / 60000;
      applied.push({ visit_id: c.visit_id, delta_min: Math.round(deltaMin) });
      if (deltaMin > 15) {
        const newT = new Date(c.new_time);
        const fmtT = newT.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
        const fmtD = newT.toLocaleDateString('de-DE');
        // Betreuer benachrichtigen
        wsBroadcast({ type: 'route_update', visit_id: c.visit_id, new_time: c.new_time, old_time: old.scheduled_at,
                      message: `Termin verschoben: ${fmtD}, ${fmtT} Uhr` },
          ws => ws.userId === old.betreuer_id || ws.userRole === 'admin');
        // NUR die Angehörigen dieses Patienten benachrichtigen (DSGVO) + Anruf-Option
        const pat = (await pool.query('SELECT angehoerige_ids FROM patients WHERE id=$1', [old.patient_id])).rows[0];
        const angIds = (() => { try { return JSON.parse(pat?.angehoerige_ids || '[]'); } catch { return []; } })();
        const betr = old.betreuer_id ? (await pool.query('SELECT name, phone FROM users WHERE id=$1', [old.betreuer_id])).rows[0] : null;
        wsBroadcast({ type: 'visit_rescheduled', visit_id: c.visit_id, new_time: c.new_time, old_time: old.scheduled_at,
                      patient_id: old.patient_id, betreuer_name: betr?.name || '', phone: betr?.phone || '',
                      message: `Ihr Termin am ${fmtD} wurde auf ${fmtT} Uhr verschoben.` },
          ws => angIds.includes(ws.userId));
        // E-Mail an die Angehörigen über die Terminverschiebung
        setImmediate(async () => {
          const settings = await getSettings();
          const emails = await emailsForPatient(old.patient_id);
          if (!emails.length) return;
          await sendMail({
            to: emails.join(','),
            subject: `Terminänderung – neuer Termin ${fmtD}, ${fmtT} Uhr`,
            html: mailLayout('Ihr Termin wurde verschoben',
              `<p>Ihr Besuch wurde auf <b>${fmtD}, ${fmtT} Uhr</b> verschoben.</p>
               ${betr?.name ? `<p>Betreuungskraft: <b>${escapeHtml(betr.name)}</b>${betr.phone ? ` · <a href="tel:${escapeHtml(betr.phone)}">${escapeHtml(betr.phone)}</a>` : ''}</p>` : ''}
               <p style="margin-top:16px"><a href="${APP_URL}" style="background:#1C3A2A;color:#fff;text-decoration:none;padding:10px 20px;border-radius:10px;font-weight:bold;display:inline-block">Zur App →</a></p>`,
              settings)
          });
        });
      }
    }
    await audit(req, 'route_applied', 'route', applied.length + ' Besuche');
    notifyVisitUpdate('route');
    res.json({ applied });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
//  KI-DISPOSITION (claude-haiku, Fallback: regelbasierte Heuristik)
// ═══════════════════════════════════════════════════════════════

function callClaude(prompt, maxTokens = 600) {
  return new Promise((resolve) => {
    if (!process.env.ANTHROPIC_API_KEY) return resolve(null);
    const data = JSON.stringify({
      model: 'claude-haiku-4-5-20251001', max_tokens: maxTokens,
      messages: [{ role: 'user', content: prompt }]
    });
    const r = https.request({
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01',
                 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) }
    }, (res2) => {
      let buf = '';
      res2.on('data', d => buf += d);
      res2.on('end', () => { try { resolve(JSON.parse(buf).content[0].text); } catch { resolve(null); } });
    });
    r.on('error', () => resolve(null));
    r.setTimeout(20000, () => { r.destroy(); resolve(null); });
    r.write(data); r.end();
  });
}

async function aiDispatchVisit(visitId) {
  const visit = (await pool.query(`
    SELECT v.*, p.name as patient_name, p.address as patient_address, p.pflegegrad,
           p.lat, p.lng, p.preferred_time_from, p.preferred_time_to
    FROM visits v JOIN patients p ON v.patient_id = p.id WHERE v.id=$1
  `, [visitId])).rows[0];
  if (!visit) throw new Error('Besuch nicht gefunden');

  // Patient ggf. on-the-fly geocodieren
  let pCoord = visit.lat != null ? { lat: parseFloat(visit.lat), lng: parseFloat(visit.lng) } : null;
  if (!pCoord && visit.patient_address) {
    pCoord = await geocodeAddress(visit.patient_address);
    if (pCoord) await pool.query('UPDATE patients SET lat=$1, lng=$2, address_geocoded=true WHERE id=$3', [pCoord.lat, pCoord.lng, visit.patient_id]);
  }

  const dateStr = new Date(visit.scheduled_at).toISOString().split('T')[0];
  const { rows: betreuer } = await pool.query(`
    SELECT u.id, u.name, u.qualifications, u.home_lat, u.home_lng, u.shift_start, u.max_hours_per_day,
      COALESCE(t.stops, 0) as stops_heute,
      COALESCE(t.minuten, 0) as gebuchte_minuten
    FROM users u
    LEFT JOIN (
      SELECT betreuer_id, COUNT(*) as stops, SUM(COALESCE(duration_min, 60)) as minuten
      FROM visits WHERE scheduled_at::date = $1::date AND status NOT IN ('abgelehnt','storniert','abgesagt')
      GROUP BY betreuer_id
    ) t ON t.betreuer_id = u.id
    WHERE u.role='betreuer' AND u.active IS NOT FALSE
  `, [dateStr]);
  // Abwesende Betreuer ausschließen
  const { rows: absent } = await pool.query('SELECT betreuer_id FROM availability WHERE date=$1::date AND available=false', [dateStr]);
  const absentIds = new Set(absent.map(a => a.betreuer_id));
  const candidates = betreuer.filter(b => !absentIds.has(b.id)).map(b => {
    const home = b.home_lat != null ? { lat: parseFloat(b.home_lat), lng: parseFloat(b.home_lng) } : null;
    const km = (pCoord && home) ? Math.round((haversineKm(home, pCoord) || 0) * 10) / 10 : null;
    const freieStunden = Math.max(0, (b.max_hours_per_day || 8) - num(b.gebuchte_minuten) / 60);
    return {
      betreuer_id: b.id, name: b.name, stops_heute: parseInt(b.stops_heute),
      freie_stunden: Math.round(freieStunden * 10) / 10,
      entfernung_km: km,
      qualifikationen: (() => { try { return JSON.parse(b.qualifications || '[]'); } catch { return []; } })()
    };
  });
  if (!candidates.length) return { error: 'Keine aktiven Betreuer verfügbar' };

  let decision = null;
  const aiText = await callClaude(
`Du bist Dispositions-KI für ambulante Pflege/Alltagsbegleitung.
Neuer Auftrag:
${JSON.stringify({ patient: visit.patient_name, adresse: visit.patient_address, pflegegrad: visit.pflegegrad, leistung: visit.service, dauer_min: visit.duration_min || 60, datum: visit.scheduled_at, zeitfenster: { von: visit.preferred_time_from, bis: visit.preferred_time_to } })}
Verfügbare Betreuer (mit Distanz zum Patienten in km, null = unbekannt):
${JSON.stringify(candidates)}
Wähle den besten Betreuer (kurze Wege, freie Kapazität, passende Qualifikation).
Antworte NUR mit einem JSON-Objekt, kein anderer Text:
{"betreuer_id":"...","empfohlene_zeit":"HH:MM","begruendung":"max 2 Sätze","konfidenz":0.0-1.0,"alternative":[{"betreuer_id":"...","grund":"..."}],"warnungen":["..."]}`);

  if (aiText) {
    try {
      const m = aiText.match(/\{[\s\S]*\}/);
      const j = JSON.parse(m ? m[0] : aiText);
      if (j.betreuer_id && candidates.find(c => c.betreuer_id === j.betreuer_id)) decision = { ...j, quelle: 'ki' };
    } catch { /* Fallback unten */ }
  }

  if (!decision) {
    // Regelbasierte Heuristik: nächster Betreuer mit freier Kapazität
    const ranked = candidates
      .filter(c => c.freie_stunden >= (visit.duration_min || 60) / 60)
      .sort((a, b) => (a.entfernung_km ?? 999) - (b.entfernung_km ?? 999) || a.stops_heute - b.stops_heute);
    const best = ranked[0] || candidates.sort((a, b) => a.stops_heute - b.stops_heute)[0];
    decision = {
      betreuer_id: best.betreuer_id,
      empfohlene_zeit: null,
      begruendung: `Heuristik: ${best.name} – ${best.entfernung_km != null ? best.entfernung_km + ' km Entfernung, ' : ''}${best.freie_stunden} freie Std., ${best.stops_heute} Stopps heute.`,
      konfidenz: 0.5,
      warnungen: ranked.length ? [] : ['Alle Betreuer ausgelastet – Kapazität prüfen'],
      quelle: 'heuristik'
    };
  }

  // Zeit übernehmen falls die KI eine im Format HH:MM geliefert hat
  let newScheduled = null;
  if (decision.empfohlene_zeit && /^\d{2}:\d{2}$/.test(decision.empfohlene_zeit)) {
    newScheduled = `${dateStr}T${decision.empfohlene_zeit}:00`;
  }

  const { rows } = await pool.query(`
    UPDATE visits SET betreuer_id=$1, scheduled_at=COALESCE($2, scheduled_at),
      status = CASE WHEN status IN ('anfrage','offen') THEN 'geplant' ELSE status END,
      ai_dispatch_note=$3, ai_dispatch_confidence=$4, ai_dispatched_at=NOW(), dispatch_overridden=false
    WHERE id=$5 RETURNING *
  `, [decision.betreuer_id, newScheduled,
      JSON.stringify({ begruendung: decision.begruendung, alternative: decision.alternative || [], warnungen: decision.warnungen || [], quelle: decision.quelle }),
      Math.min(1, Math.max(0, num(decision.konfidenz))), visitId]);

  notifyNewAssignment(rows[0]);
  notifyVisitUpdate(visitId);
  wsBroadcast({ type: 'ai_dispatch', visit_id: visitId, betreuer_id: decision.betreuer_id, konfidenz: decision.konfidenz },
    ws => ws.userRole === 'admin');
  return { visit: parseVisit(rows[0]), decision };
}

app.post('/api/admin/ai-dispatch/:visit_id', auth, adminOnly, async (req, res) => {
  try {
    const result = await aiDispatchVisit(req.params.visit_id);
    if (result.error) return res.status(400).json(result);
    await audit(req, 'ai_dispatch_manual', 'visit', req.params.visit_id);
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/ai-dispatch/log', auth, adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.id, v.scheduled_at, v.service, v.status, v.ai_dispatch_note, v.ai_dispatch_confidence,
             v.ai_dispatched_at, v.dispatch_overridden, p.name as patient_name, u.name as betreuer_name
      FROM visits v LEFT JOIN patients p ON v.patient_id=p.id LEFT JOIN users u ON v.betreuer_id=u.id
      WHERE v.ai_dispatched_at IS NOT NULL ORDER BY v.ai_dispatched_at DESC LIMIT 50
    `);
    res.json(rows.map(r => ({ ...r, ai_dispatch_note: (() => { try { return JSON.parse(r.ai_dispatch_note || '{}'); } catch { return { begruendung: r.ai_dispatch_note }; } })() })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/ai-dispatch/:visit_id/override', auth, adminOnly, async (req, res) => {
  const { betreuer_id, scheduled_at } = req.body;
  try {
    const { rows } = await pool.query(`
      UPDATE visits SET betreuer_id=COALESCE($1, betreuer_id), scheduled_at=COALESCE($2, scheduled_at),
        dispatch_overridden=true, status = CASE WHEN status IN ('anfrage','offen') THEN 'geplant' ELSE status END
      WHERE id=$3 RETURNING *
    `, [betreuer_id, scheduled_at, req.params.visit_id]);
    if (!rows[0]) return res.status(404).json({ error: 'Nicht gefunden' });
    await audit(req, 'ai_dispatch_override', 'visit', req.params.visit_id);
    notifyNewAssignment(rows[0]);
    notifyVisitUpdate(req.params.visit_id);
    res.json(parseVisit(rows[0]));
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

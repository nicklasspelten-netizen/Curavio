/**
 * CURAVIO – Backend (In-Memory, kein SQLite)
 * Node.js + Express + WebSocket + Claude AI
 * Rollen: angehöriger | betreuer | admin
 */

require('dotenv').config();
const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const cors       = require('cors');
const path       = require('path');

// Anthropic KI – optional
let Anthropic = null;
try { Anthropic = require('@anthropic-ai/sdk'); } catch {}

// ─── Setup ───────────────────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });
const ai     = (Anthropic && process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_API_KEY.startsWith('HIER'))
               ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;
const JWT    = process.env.JWT_SECRET || 'curavio_dev_secret';
const PORT   = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── In-Memory Datenbank ──────────────────────────────────────────────────────
const DB = {
  users:    [],
  patients: [],
  visits:   [],
  reports:  [],
  messages: []
};

function now() { return new Date().toISOString(); }

function seedDemoData() {
  const pw = bcrypt.hashSync('curavio123', 10);

  DB.users.push(
    { id: 'u1', name: 'Thomas Mueller',  email: 'thomas@demo.de',    password: pw, role: 'angehoeriger', phone: '+49 170 1234567', created_at: now() },
    { id: 'u2', name: 'Maria Kovacs',    email: 'maria@demo.de',     password: pw, role: 'betreuer',     phone: '+49 151 9876543', created_at: now() },
    { id: 'u3', name: 'Admin Curavio',   email: 'admin@curavio.de',  password: pw, role: 'admin',        phone: '+49 30 1234567',  created_at: now() }
  );

  DB.patients.push({
    id: 'p1', name: 'Heinrich Mueller', birthdate: '1946-03-15',
    address: 'Kantstrasse 42, 10625 Berlin', pflegegrad: 2, kasse: 'AOK Berlin',
    notes: null, angehoeriger_id: 'u1', created_at: now()
  });

  const today     = new Date().toISOString().split('T')[0];
  const lastMonth = new Date(Date.now() - 28 * 86400000).toISOString().split('T')[0];

  DB.visits.push(
    { id: 'v1', patient_id: 'p1', betreuer_id: 'u2', service: 'Koerperpflege & Medikamente',
      scheduled_at: today + 'T14:30:00', duration_min: 60, status: 'unterwegs', notes: null, created_at: now() },
    { id: 'v2', patient_id: 'p1', betreuer_id: 'u2', service: 'Hauswirtschaft & Einkauf',
      scheduled_at: today + 'T10:00:00', duration_min: 90, status: 'geplant', notes: null, created_at: now() },
    { id: 'v3', patient_id: 'p1', betreuer_id: 'u2', service: 'Koerperpflege & Medikamente',
      scheduled_at: lastMonth + 'T14:30:00', duration_min: 60, status: 'abgeschlossen', notes: null, created_at: now() }
  );

  DB.reports.push({
    id: 'r1', visit_id: 'v3',
    content: 'Heinrich war heute in sehr guter Stimmung. Gemeinsamer Spaziergang im Volkspark verlief problemlos.',
    tasks_done: JSON.stringify(['Koerperpflege', 'Medikamente', 'Spaziergang', 'Mittagessen']),
    mood: 4, vitals: null,
    ai_summary: 'Sehr positiver Besuch. Heinrich wirkte ausgeglichen und aktiv. Keine Auffaelligkeiten. Medikamente planmaessig eingenommen.',
    created_at: now()
  });
}

seedDemoData();

// ─── Middleware: JWT-Auth ─────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Kein Token' });
  try {
    req.user = jwt.verify(h.replace('Bearer ', ''), JWT);
    next();
  } catch { res.status(401).json({ error: 'Ungültiger Token' }); }
}

function role(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: 'Keine Berechtigung' });
    next();
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTEN
// ═══════════════════════════════════════════════════════════════════════════════

// ─── AUTH ─────────────────────────────────────────────────────────────────────

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' });

  const user = DB.users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'E-Mail oder Passwort falsch' });

  const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
});

app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role = 'angehoeriger', phone } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, E-Mail und Passwort erforderlich' });

  if (DB.users.find(u => u.email === email))
    return res.status(409).json({ error: 'E-Mail bereits registriert' });

  const id   = uuid();
  const hash = bcrypt.hashSync(password, 10);
  DB.users.push({ id, name, email, password: hash, role, phone: phone || null, created_at: now() });

  const token = jwt.sign({ id, name, role }, JWT, { expiresIn: '7d' });
  res.status(201).json({ token, user: { id, name, role, email } });
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = DB.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Nicht gefunden' });
  const { password, ...safe } = user;
  res.json(safe);
});

// ─── PATIENTEN ────────────────────────────────────────────────────────────────

app.get('/api/patients', auth, (req, res) => {
  let patients;
  if (req.user.role === 'admin') {
    patients = DB.patients;
  } else if (req.user.role === 'angehoeriger') {
    patients = DB.patients.filter(p => p.angehoeriger_id === req.user.id);
  } else {
    const myPatientIds = [...new Set(
      DB.visits.filter(v => v.betreuer_id === req.user.id).map(v => v.patient_id)
    )];
    patients = DB.patients.filter(p => myPatientIds.includes(p.id));
  }
  res.json(patients);
});

app.post('/api/patients', auth, (req, res) => {
  const { name, birthdate, address, pflegegrad, kasse, notes } = req.body;
  if (!name) return res.status(400).json({ error: 'Name erforderlich' });

  const id = uuid();
  const angehoeriger_id = req.user.role === 'angehoeriger' ? req.user.id : req.body.angehoeriger_id;
  DB.patients.push({ id, name, birthdate: birthdate || null, address: address || null,
    pflegegrad: pflegegrad || 1, kasse: kasse || 'AOK', notes: notes || null,
    angehoeriger_id, created_at: now() });
  res.status(201).json({ id, name });
});

// ─── BESUCHE ─────────────────────────────────────────────────────────────────

app.get('/api/visits', auth, (req, res) => {
  let visits = DB.visits;

  if (req.user.role === 'betreuer') {
    visits = visits.filter(v => v.betreuer_id === req.user.id);
  } else if (req.user.role === 'angehoeriger') {
    const myPatientIds = DB.patients.filter(p => p.angehoeriger_id === req.user.id).map(p => p.id);
    visits = visits.filter(v => myPatientIds.includes(v.patient_id));
  }

  const enriched = visits.map(v => {
    const patient = DB.patients.find(p => p.id === v.patient_id);
    const betreuer = DB.users.find(u => u.id === v.betreuer_id);
    return { ...v, patient_name: patient ? patient.name : '', betreuer_name: betreuer ? betreuer.name : '' };
  }).sort((a, b) => b.scheduled_at.localeCompare(a.scheduled_at));

  res.json(enriched);
});

app.post('/api/visits', auth, (req, res) => {
  const { patient_id, betreuer_id, service, scheduled_at, duration_min, notes } = req.body;
  if (!patient_id || !service || !scheduled_at)
    return res.status(400).json({ error: 'Patient, Service und Datum erforderlich' });

  let assignedBetreuer = betreuer_id;
  if (!assignedBetreuer) {
    const available = DB.users.find(u => u.role === 'betreuer');
    assignedBetreuer = available ? available.id : null;
  }

  const id = uuid();
  DB.visits.push({ id, patient_id, betreuer_id: assignedBetreuer, service, scheduled_at,
    duration_min: duration_min || 60, status: 'geplant', notes: notes || null, created_at: now() });

  res.status(201).json({ id, service, scheduled_at, betreuer_id: assignedBetreuer });
});

app.patch('/api/visits/:id/status', auth, (req, res) => {
  const { status } = req.body;
  const allowed = ['geplant', 'bestaetigt', 'unterwegs', 'angekommen', 'abgeschlossen', 'storniert'];
  if (!allowed.includes(status))
    return res.status(400).json({ error: 'Ungültiger Status' });

  const visit = DB.visits.find(v => v.id === req.params.id);
  if (!visit) return res.status(404).json({ error: 'Besuch nicht gefunden' });
  visit.status = status;

  broadcast({ type: 'visit_update', visit });
  res.json({ success: true, status });
});

// ─── BERICHTE ─────────────────────────────────────────────────────────────────

app.get('/api/reports', auth, (req, res) => {
  let reports = DB.reports;

  if (req.user.role === 'betreuer') {
    const myVisitIds = DB.visits.filter(v => v.betreuer_id === req.user.id).map(v => v.id);
    reports = reports.filter(r => myVisitIds.includes(r.visit_id));
  } else if (req.user.role === 'angehoeriger') {
    const myPatientIds = DB.patients.filter(p => p.angehoeriger_id === req.user.id).map(p => p.id);
    const relVisitIds  = DB.visits.filter(v => myPatientIds.includes(v.patient_id)).map(v => v.id);
    reports = reports.filter(r => relVisitIds.includes(r.visit_id));
  }

  const enriched = reports.map(r => {
    const visit   = DB.visits.find(v => v.id === r.visit_id);
    const patient = visit ? DB.patients.find(p => p.id === visit.patient_id) : null;
    const betreuer = visit ? DB.users.find(u => u.id === visit.betreuer_id) : null;
    return {
      ...r,
      tasks_done:   r.tasks_done ? JSON.parse(r.tasks_done) : [],
      vitals:       r.vitals ? JSON.parse(r.vitals) : null,
      service:      visit ? visit.service : '',
      scheduled_at: visit ? visit.scheduled_at : '',
      patient_name: patient ? patient.name : '',
      betreuer_name: betreuer ? betreuer.name : ''
    };
  }).sort((a, b) => b.created_at.localeCompare(a.created_at));

  res.json(enriched);
});

app.post('/api/reports', auth, async (req, res) => {
  const { visit_id, content, tasks_done, mood, vitals } = req.body;
  if (!visit_id || !content)
    return res.status(400).json({ error: 'Besuch und Inhalt erforderlich' });

  let ai_summary = null;
  try {
    if (!ai) throw new Error('Kein API Key');
    const visit   = DB.visits.find(v => v.id === visit_id);
    const patient = visit ? DB.patients.find(p => p.id === visit.patient_id) : null;
    const msg = await ai.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 300,
      messages: [{
        role: 'user',
        content: `Du bist Assistent bei Curavio, einem Pflegedienst. Erstelle eine kurze, freundliche Zusammenfassung (2-3 Saetze) fuer die Angehoerigen eines Patienten.

Patient: ${patient ? patient.name : 'Unbekannt'}
Leistung: ${visit ? visit.service : ''}
Bericht: ${content}
Aufgaben: ${JSON.stringify(tasks_done || [])}
Stimmung (1-5): ${mood || 3}

Schreibe in der Du-Form an die Angehoerigen.`
      }]
    });
    ai_summary = msg.content[0].text;
  } catch (e) {
    console.error('KI-Fehler:', e.message);
    ai_summary = content.substring(0, 200);
  }

  const id = uuid();
  DB.reports.push({
    id, visit_id, content,
    tasks_done: tasks_done ? JSON.stringify(tasks_done) : null,
    mood: mood || 3,
    vitals: vitals ? JSON.stringify(vitals) : null,
    ai_summary,
    created_at: now()
  });

  const visit = DB.visits.find(v => v.id === visit_id);
  if (visit) visit.status = 'abgeschlossen';

  broadcast({ type: 'new_report', visit_id, ai_summary });
  res.status(201).json({ id, ai_summary });
});

// ─── CHAT ─────────────────────────────────────────────────────────────────────

app.get('/api/messages/:room_id', auth, (req, res) => {
  const messages = DB.messages
    .filter(m => m.room_id === req.params.room_id)
    .slice(-100)
    .map(m => {
      const sender = DB.users.find(u => u.id === m.sender_id);
      return { ...m, sender_name: sender ? sender.name : '', sender_role: sender ? sender.role : '' };
    });
  res.json(messages);
});

app.get('/api/betreuer', auth, (req, res) => {
  res.json(DB.users.filter(u => u.role === 'betreuer').map(u => ({ id: u.id, name: u.name, phone: u.phone })));
});

app.get('/api/admin/users', auth, role('admin'), (req, res) => {
  res.json(DB.users.map(function(u) { var o = Object.assign({}, u); delete o.password; return o; }));
});

app.get('/api/admin/stats', auth, role('admin'), (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  res.json({
    users:    DB.users.length,
    patients: DB.patients.length,
    visits:   DB.visits.length,
    today:    DB.visits.filter(v => v.scheduled_at.startsWith(today)).length,
    reports:  DB.reports.length
  });
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
const clients = new Map();

wss.on('connection', function(ws) {
  var userId = null;

  ws.on('message', function(raw) {
    try {
      var msg = JSON.parse(raw);

      if (msg.type === 'auth') {
        try {
          var user = jwt.verify(msg.token, JWT);
          userId = user.id;
          clients.set(userId, ws);
          ws.send(JSON.stringify({ type: 'auth_ok', user: user }));
        } catch(e) {
          ws.send(JSON.stringify({ type: 'auth_error' }));
        }
        return;
      }

      if (!userId) return;

      if (msg.type === 'chat') {
        var id = uuid();
        var sender = DB.users.find(function(u) { return u.id === userId; });
        DB.messages.push({ id: id, room_id: msg.room_id, sender_id: userId, content: msg.content, created_at: now() });
        broadcast({ type: 'chat', id: id, room_id: msg.room_id,
          sender_id: userId, sender_name: sender ? sender.name : '', sender_role: sender ? sender.role : '',
          content: msg.content, created_at: now() });
      }

      if (msg.type === 'location') {
        broadcast({ type: 'location', betreuer_id: userId, lat: msg.lat, lng: msg.lng });
      }

    } catch(e) { console.error('WS-Fehler:', e.message); }
  });

  ws.on('close', function() { if (userId) clients.delete(userId); });
});

function broadcast(data) {
  var str = JSON.stringify(data);
  clients.forEach(function(ws) {
    if (ws.readyState === WebSocket.OPEN) ws.send(str);
  });
}

// ─── SPA Fallback ─────────────────────────────────────────────────────────────
app.get('*', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, function() {
  var kiStatus = ai ? 'KI aktiv (Claude API)' : 'KI inaktiv (kein API Key)';
  console.log('');
  console.log('  ==========================================');
  console.log('   CURAVIO laeuft!');
  console.log('   http://localhost:' + PORT);
  console.log('   ' + kiStatus);
  console.log('');
  console.log('   Demo-Logins:');
  console.log('   thomas@demo.de    / curavio123');
  console.log('   maria@demo.de     / curavio123');
  console.log('   admin@curavio.de  / curavio123');
  console.log('  ==========================================');
  console.log('');
});

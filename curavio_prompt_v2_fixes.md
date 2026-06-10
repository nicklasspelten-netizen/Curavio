# Curavio — Chirurgischer Fix-Prompt (v2)

**WICHTIG: Lies CLAUDE.md für Projektkontext. Lies KEINE Dateien komplett neu ein
– du kennst die Architektur. Arbeite ausschließlich an den unten definierten
Punkten. Verändere nichts anderes. Jede Änderung muss rückwärtskompatibel sein.**

---

## ARBEITSWEISE

1. Lies CLAUDE.md (einmal, vollständig)
2. Für jeden Fix: betroffene Funktion / Zeile mit `grep -n` lokalisieren
3. Nur die betroffenen Stellen ändern — kein Refactoring unbeteiligter Code-Bereiche
4. Nach jedem Block: `node check_html_js.js` und `node -e "require('./server.js')"` ausführen
5. Am Ende: einmal `push_zu_github.bat` — commit-message "Curavio v2 Fixes"

---

## BLOCK 1 — KRITISCHER LOGIN-BUG (zuerst, höchste Priorität)

### Problem
- Betreuer-Login landet fälschlicherweise in der Klienten-App
- Es gibt keine sichtbare An-/Abmeldung für Betreuer und Angehörige
- `showApp()` routet nach JWT-Rolle, aber irgendetwas überschreibt das

### Fix in `public/index.html`

**1a. `showApp()` absichern:**
```javascript
function showApp() {
  connectWS();
  const role = USER?.role;
  // Alle Navbars zuerst verstecken
  document.getElementById('bnav')?.style && (document.getElementById('bnav').style.display = 'none');
  document.getElementById('bnav-b')?.style && (document.getElementById('bnav-b').style.display = 'none');

  if (role === 'betreuer') {
    document.getElementById('bnav-b').style.display = 'flex';
    goTo('sc-bh');
    loadBetreuerHome();
    loadAuftraege();
    loadArbeitszeiten();
  } else if (role === 'angehoeriger') {
    document.getElementById('bnav').style.display = 'flex';
    goTo('sc-home');
    loadPatients();
    loadVisits();
  } else if (role === 'admin') {
    // Admin kommt zu admin.html — redirect
    window.location.href = '/admin';
  }
}
```

**1b. Login-Screen (`sc-login`) muss in index.html vorhanden sein:**
- Prüfe: existiert `<div id="sc-login">` mit Email + Passwort Feldern und Login-Button?
- Falls nicht: Screen anlegen (kompakt, wie restliche Screens)
- Login-Button ruft `doLogin()` auf

**1c. `doLogin()` — nach erfolgreichem Login TOKEN + USER korrekt speichern:**
```javascript
async function doLogin() {
  const email = document.getElementById('login-email').value.trim();
  const pw = document.getElementById('login-pw').value;
  const r = await fetch('/api/login', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({email, password: pw})
  });
  const d = await r.json();
  if (!r.ok) { showToast(d.error || 'Login fehlgeschlagen', 'error'); return; }
  localStorage.setItem('token', d.token);
  localStorage.setItem('user', JSON.stringify(d.user));
  TOKEN = d.token;
  USER = d.user;
  document.getElementById('sc-login').style.display = 'none';
  showApp(); // role-based routing
}
```

**1d. `doLogout()` — für beide Rollen:**
```javascript
function doLogout() {
  stopStempelTimer?.();
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  TOKEN = null; USER = null;
  document.getElementById('bnav').style.display = 'none';
  document.getElementById('bnav-b').style.display = 'none';
  goTo('sc-login');
}
```

**1e. Logout-Button in beiden Navbars einbauen:**
- `#bnav` (Angehörige): Icon + Label "Abmelden", onclick="doLogout()"
- `#bnav-b` (Betreuer): gleiches Icon + Label "Abmelden", onclick="doLogout()"

**1f. App-Start (`DOMContentLoaded`):**
```javascript
TOKEN = localStorage.getItem('token');
USER = JSON.parse(localStorage.getItem('user') || 'null');
if (TOKEN && USER) {
  showApp();
} else {
  goTo('sc-login');
}
```
Kein Auto-Login ohne gültigen gespeicherten Token.

---

## BLOCK 2 — ADRESS-AUTOCOMPLETE (überall)

Jede Stelle in index.html und admin.html, wo eine Adresse eingegeben wird,
bekommt ein Autocomplete via Nominatim (OpenStreetMap, kostenlos, DSGVO-konform).

### Funktion (einmalig in `<script>` einfügen — beide HTML-Dateien):
```javascript
function initAddressAutocomplete(inputId, onSelect) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  let timeout;
  let dropdown = document.createElement('ul');
  dropdown.className = 'addr-dropdown';
  dropdown.style.cssText =
    'position:absolute;z-index:9999;background:#1e1e2e;border:1px solid #7c3aed;' +
    'border-radius:8px;list-style:none;margin:0;padding:4px 0;max-height:200px;' +
    'overflow-y:auto;width:100%;box-shadow:0 8px 24px rgba(0,0,0,.4);display:none;';
  inp.parentElement.style.position = 'relative';
  inp.parentElement.appendChild(dropdown);

  inp.addEventListener('input', () => {
    clearTimeout(timeout);
    const q = inp.value.trim();
    if (q.length < 3) { dropdown.style.display='none'; return; }
    timeout = setTimeout(async () => {
      try {
        const res = await fetch(
          `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}&format=json&addressdetails=1&limit=5&countrycodes=de`,
          { headers: { 'Accept-Language': 'de', 'User-Agent': 'Curavio/1.0' } }
        );
        const data = await res.json();
        dropdown.innerHTML = '';
        if (!data.length) { dropdown.style.display='none'; return; }
        data.forEach(item => {
          const li = document.createElement('li');
          li.textContent = item.display_name;
          li.style.cssText = 'padding:8px 12px;cursor:pointer;font-size:13px;color:#e2e8f0;';
          li.onmouseenter = () => li.style.background = '#2d2d44';
          li.onmouseleave = () => li.style.background = '';
          li.onclick = () => {
            // Formatierte Standardadresse: Straße HNr, PLZ Ort
            const a = item.address;
            const street = [a.road, a.house_number].filter(Boolean).join(' ');
            const city = [a.postcode, a.city || a.town || a.village].filter(Boolean).join(' ');
            const formatted = [street, city].filter(Boolean).join(', ');
            inp.value = formatted;
            dropdown.style.display = 'none';
            if (onSelect) onSelect({
              formatted,
              lat: parseFloat(item.lat),
              lng: parseFloat(item.lon),
              raw: item
            });
          };
          dropdown.appendChild(li);
        });
        dropdown.style.display = 'block';
      } catch(e) { dropdown.style.display='none'; }
    }, 400); // Debounce: Nominatim max 1 Req/Sek
  });

  document.addEventListener('click', e => {
    if (!inp.contains(e.target)) dropdown.style.display = 'none';
  });
}
```

### Anwenden auf alle Adressfelder:
Suche alle `<input>` mit `placeholder` der "Adresse" oder "Straße" enthält.
Ruf nach dem DOM-Init auf:
```javascript
// index.html
initAddressAutocomplete('patient-address', d => { /* lat/lng in hidden fields */ });
initAddressAutocomplete('booking-address', d => { /* falls vorhanden */ });

// admin.html
initAddressAutocomplete('new-patient-address', d => {
  document.getElementById('new-patient-lat').value = d.lat;
  document.getElementById('new-patient-lng').value = d.lng;
});
initAddressAutocomplete('edit-patient-address', d => { ... });
initAddressAutocomplete('new-betreuer-address', d => { ... });
```
Hidden-Input-Felder `lat`/`lng` anlegen wo noch nicht vorhanden.
Beim Speichern diese Werte mitsenden → patients.lat, patients.lng in DB direkt befüllt.

---

## BLOCK 3 — DEMO-ELEMENTE ENTFERNEN

Folgende Elemente in `public/index.html` vollständig entfernen (innerHTML + CSS):

**Entfernen:**
- Animierte Echtzeituhr / digitaler Uhrzeitanzeige (`:` blink-animation, `setInterval` clock)
- Blutdruck-Anzeige / Blutdruck-Kachel (systolisch, diastolisch)
- Herzfrequenz-Anzeige / Herzfrequenz-Kachel (BPM, Puls)
- Alle `setInterval`-Aufrufe die nur für Demo-Simulation existieren (zufällige Vitalwerte)
- CSS-Klassen und Keyframe-Animationen die ausschließlich für o.g. Elemente sind
- Jegliche simulierten "Live"-Daten die nicht aus der echten DB kommen

**Behalten:**
- Stempel-Timer (echter Arbeitszeiterfassungs-Timer — bleibt!)
- Echte Daten-Ladeanimationen (Spinner beim API-Call)
- Toast-Benachrichtigungen

---

## BLOCK 4 — TERMINABSAGE (alle Rollen) + AUSFALLRECHNUNG

### 4a. Backend: `server.js`

**Neue Route:**
```javascript
PATCH /api/visits/:id/cancel
// Auth: role angehoeriger | betreuer | admin
// Body: { reason: string }
```
Logik:
```javascript
app.patch('/api/visits/:id/cancel', auth, async (req, res) => {
  const { reason = '' } = req.body;
  const { rows } = await pool.query('SELECT * FROM visits WHERE id=$1', [req.params.id]);
  if (!rows.length) return res.status(404).json({error:'Nicht gefunden'});
  const visit = rows[0];

  // Berechtigungsprüfung
  const role = req.user.role;
  const uid = req.user.id;
  if (role === 'angehoeriger') {
    // Darf nur eigene Patienten absagen
    const { rows: pts } = await pool.query(
      'SELECT id FROM patients WHERE id=$1 AND angehoerige_ids::text LIKE $2',
      [visit.patient_id, `%${uid}%`]
    );
    if (!pts.length) return res.status(403).json({error:'Kein Zugriff'});
  } else if (role === 'betreuer') {
    if (visit.betreuer_id !== uid) return res.status(403).json({error:'Kein Zugriff'});
  }

  // Kurzfristige Absage < 24h?
  const now = new Date();
  const scheduled = new Date(visit.scheduled_at);
  const hoursUntil = (scheduled - now) / 36e5;
  const isLateCancel = hoursUntil < 24 && hoursUntil > 0;

  await pool.query(
    "UPDATE visits SET status='abgesagt', notes=CONCAT(notes, $1) WHERE id=$2",
    [`\n[Absage ${new Date().toLocaleString('de-DE')} durch ${role}: ${reason}]`, req.params.id]
  );

  // Ausfallrechnung bei < 24h (Angehöriger oder Betreuer)
  let ausfallInvoiceId = null;
  if (isLateCancel) {
    const invId = 'inv-' + Date.now();
    const invNr = 'AUS-' + new Date().getFullYear() + '-' + invId.slice(-6).toUpperCase();
    const patient = await pool.query('SELECT * FROM patients WHERE id=$1', [visit.patient_id]);
    const pt = patient.rows[0];
    const rate = visit.hourly_rate || 35.00; // Fallback-Stundensatz
    const durationH = (visit.duration_min || 60) / 60;
    const cancelFee = Math.round(rate * durationH * 100) / 100;

    await pool.query(`
      INSERT INTO invoices (id, invoice_number, type, recipient_id, recipient_name,
        period_from, period_to, line_items, subtotal, total_netto, total_brutto,
        status, notes, created_by)
      VALUES ($1,$2,'kunde',$3,$4,$5,$6,$7,$8,$8,$8,'entwurf',$9,$10)
    `, [
      invId, invNr,
      visit.patient_id, pt?.name || 'Klient',
      visit.scheduled_at, visit.scheduled_at,
      JSON.stringify([{
        beschreibung: `Ausfallgebühr – kurzfristige Absage (< 24h) am ${new Date(visit.scheduled_at).toLocaleDateString('de-DE')}`,
        stunden: durationH, stundensatz: rate, betrag: cancelFee
      }]),
      cancelFee,
      `Automatisch erstellt: Kurzfristige Absage durch ${role}. Gemäß AGB und Datenschutzerklärung (§ Ausfallgebühren).`,
      uid
    ]);
    ausfallInvoiceId = invId;
  }

  // WebSocket-Broadcast
  broadcast({ type: 'visit_cancelled', visit_id: req.params.id,
              cancelled_by: role, reason, is_late_cancel: isLateCancel,
              ausfall_invoice_id: ausfallInvoiceId });

  // E-Mail-Hinweis (wenn Mailer konfiguriert — Platzhalter, kein echtes SMTP nötig)
  // TODO: sendCancellationEmail(visit, role, reason, isLateCancel)

  res.json({ ok: true, is_late_cancel: isLateCancel, ausfall_invoice_id: ausfallInvoiceId });
});
```

### 4b. Frontend: index.html

In der Detailansicht eines Besuchs (Angehörige + Betreuer):
- Button "Termin absagen" (nur wenn status = 'geplant' | 'bestätigt' | 'offen')
- Modal: Absagegrund (Textarea) + Bestätigen
- Bei `is_late_cancel: true` → Toast: "⚠️ Kurzfristige Absage – Ausfallgebühr wird berechnet"
- Nach Absage: Visit aus Liste entfernen / Status aktualisieren

### 4c. DSGVO-Ergänzung in `/api/admin/settings` (app_settings Tabelle):
Key `datenschutz_hinweis_absage` →
Value: `"Bei kurzfristiger Absage (< 24 Stunden vor Termin) wird eine Ausfallgebühr
gemäß unserer AGB erhoben. Die Verarbeitung Ihrer Buchungsdaten zur Rechnungsstellung
erfolgt auf Basis von Art. 6 Abs. 1 lit. b DSGVO (Vertragserfüllung)."`
Dieser Text soll in der Datenschutzerklärung (sc-datenschutz / settings-tab) angezeigt werden.

---

## BLOCK 5 — SMART SCHEDULING: VERFÜGBARKEITSABGLEICH + ALTERNATIVVORSCHLAG

### 5a. Backend: Buchung prüfen

Erweitere `POST /api/visits` und die Buchungs-UI:

```javascript
// Neue Route: Verfügbarkeit prüfen BEVOR Buchung gespeichert wird
GET /api/availability/check?betreuer_id=X&date=YYYY-MM-DD&time=HH:MM&duration_min=60
```
```javascript
app.get('/api/availability/check', auth, async (req, res) => {
  const { betreuer_id, date, time, duration_min = 60 } = req.query;
  const start = new Date(`${date}T${time}:00`);
  const end = new Date(start.getTime() + duration_min * 60000);

  // Kollisionscheck: überlappende Besuche des Betreuers
  const { rows: conflicts } = await pool.query(`
    SELECT id, scheduled_at, duration_min, patient_id
    FROM visits
    WHERE betreuer_id = $1
      AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen')
      AND scheduled_at < $3
      AND (scheduled_at + (duration_min || ' minutes')::interval) > $2
  `, [betreuer_id, start.toISOString(), end.toISOString()]);

  if (!conflicts.length) return res.json({ available: true });

  // Alternativen berechnen: ±2h Fenster beim gleichen Betreuer
  const alternatives = [];
  for (let delta of [-120,-60,60,120,180,240]) {
    const altStart = new Date(start.getTime() + delta * 60000);
    const altEnd = new Date(altStart.getTime() + duration_min * 60000);
    const { rows: c2 } = await pool.query(`
      SELECT id FROM visits
      WHERE betreuer_id=$1 AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen')
        AND scheduled_at < $3
        AND (scheduled_at + (duration_min || ' minutes')::interval) > $2
    `, [betreuer_id, altStart.toISOString(), altEnd.toISOString()]);
    if (!c2.length) {
      alternatives.push({
        type: 'same_betreuer',
        betreuer_id,
        time: altStart.toISOString(),
        label: `${altStart.toLocaleTimeString('de-DE',{hour:'2-digit',minute:'2-digit'})} Uhr (${delta>0?'+':''}${delta/60}h)`
      });
      if (alternatives.length >= 3) break;
    }
  }

  // Falls keine Alternative gleicher Betreuer → andere Betreuer prüfen
  if (alternatives.length === 0) {
    const { rows: betreuer } = await pool.query(
      "SELECT id, name FROM users WHERE role='betreuer' AND active=true AND id!=$1", [betreuer_id]
    );
    for (const b of betreuer) {
      const { rows: c3 } = await pool.query(`
        SELECT id FROM visits
        WHERE betreuer_id=$1 AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen')
          AND scheduled_at < $3
          AND (scheduled_at + (duration_min || ' minutes')::interval) > $2
      `, [b.id, start.toISOString(), end.toISOString()]);
      if (!c3.length) {
        alternatives.push({ type: 'alt_betreuer', betreuer_id: b.id,
                            betreuer_name: b.name, time: start.toISOString(),
                            label: `Gleiche Zeit mit ${b.name}` });
        if (alternatives.length >= 3) break;
      }
    }
  }

  res.json({ available: false, conflicts: conflicts.length, alternatives });
});
```

### 5b. Frontend: index.html — Buchungs-Flow

Beim Auswählen von Datum + Uhrzeit + Betreuer:
- `onchange` auf Uhrzeit-/Datum-Feld: sofort `GET /api/availability/check` aufrufen
- Wenn `available: false`: rotes Banner anzeigen
  "❌ [Betreuer] ist zu dieser Zeit belegt."
  Darunter: Alternativ-Buttons (max. 3):
  → "[Zeit] Uhr – Gleicher Betreuer" | "[Betreuer-Name] – Gleiche Zeit"
  → Klick füllt Formular automatisch mit Alternativ-Zeit/-Betreuer
- Wenn `available: true`: grünes Häkchen
- Submit-Button ist disabled solange `available: false` und keine Alternative gewählt

### 5c. Doppelbelegungs-Schutz (DB-Ebene, `POST /api/visits`):
```javascript
// In POST /api/visits, VOR dem INSERT:
if (body.betreuer_id) {
  const startDt = new Date(body.scheduled_at);
  const endDt = new Date(startDt.getTime() + (body.duration_min||60)*60000);
  const { rows: clash } = await pool.query(`
    SELECT id FROM visits
    WHERE betreuer_id=$1
      AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen')
      AND scheduled_at < $3
      AND (scheduled_at+(duration_min||' minutes')::interval) > $2
  `, [body.betreuer_id, startDt.toISOString(), endDt.toISOString()]);
  if (clash.length) return res.status(409).json({
    error: 'Betreuer ist zu dieser Zeit bereits verplant.',
    conflict_visit_id: clash[0].id
  });
}
// Gleicher Patient, gleiche Zeit:
const { rows: patClash } = await pool.query(`
  SELECT id FROM visits
  WHERE patient_id=$1
    AND status NOT IN ('abgesagt','abgelehnt','abgeschlossen')
    AND scheduled_at < $3
    AND (scheduled_at+(duration_min||' minutes')::interval) > $2
`, [body.patient_id, startDt.toISOString(), endDt.toISOString()]);
if (patClash.length) return res.status(409).json({
  error: 'Dieser Patient hat bereits einen Termin zu dieser Zeit.'
});
```

---

## BLOCK 6 — BETREUER-PROFIL (LinkedIn-Style)

### 6a. Backend:
```javascript
GET /api/betreuer/:id/profil   // Public für eingeloggte User jeder Rolle
```
Gibt zurück: name, qualifications, hourly_rate, aktiv, durchschnittsbewertung,
bewertungen (aus visits.rating + rating_comment), avatar_url, phone (nur Admin/selbst),
visits_count (abgeschlossene Einsätze), member_since (created_at)

### 6b. Frontend: index.html — Modal `#betreuer-profil-modal`
```html
<div id="betreuer-profil-modal" style="display:none" class="modal-overlay">
  <div class="modal-card profil-card">
    <button onclick="closeBetreuerProfil()" class="modal-close">✕</button>
    <div class="profil-avatar-wrap">
      <img id="bp-avatar" src="" alt="" class="profil-avatar" />
      <div class="profil-badge" id="bp-badge">●</div>
    </div>
    <h2 id="bp-name"></h2>
    <p id="bp-quali" class="profil-quali"></p>
    <div class="profil-stats">
      <div><span id="bp-einsaetze"></span><small>Einsätze</small></div>
      <div><span id="bp-bewertung">★</span><small>Bewertung</small></div>
      <div><span id="bp-seit"></span><small>Dabei seit</small></div>
    </div>
    <div id="bp-bewertungen-list" class="bewertungen-list"></div>
  </div>
</div>
```
CSS: Avatar rund 80px, Badge grün (aktiv)/grau, Karte max-width:420px,
bewertungen-list: je Eintrag Sterne + Kommentar + Datum.

Funktion:
```javascript
async function openBetreuerProfil(betreuerId) {
  const d = await apiFetch(`/api/betreuer/${betreuerId}/profil`);
  document.getElementById('bp-name').textContent = d.name;
  document.getElementById('bp-avatar').src = d.avatar_url || '/icons/avatar-placeholder.svg';
  document.getElementById('bp-badge').style.color = d.aktiv ? '#22c55e' : '#6b7280';
  document.getElementById('bp-quali').textContent = (d.qualifications||[]).join(' · ') || 'Alltagsbegleitung';
  document.getElementById('bp-einsaetze').textContent = d.visits_count || 0;
  document.getElementById('bp-seit').textContent = new Date(d.member_since).getFullYear();
  // Sterne-Durchschnitt
  const avg = d.avg_rating ? parseFloat(d.avg_rating).toFixed(1) : '–';
  document.getElementById('bp-bewertung').textContent = avg !== '–' ? `★ ${avg}` : '–';
  // Bewertungs-Liste
  const list = document.getElementById('bp-bewertungen-list');
  list.innerHTML = (d.bewertungen||[]).slice(0,5).map(b =>
    `<div class="bew-item">
      <span class="bew-stars">${'★'.repeat(b.rating)}${'☆'.repeat(5-b.rating)}</span>
      <span class="bew-text">${b.comment||'Kein Kommentar'}</span>
      <span class="bew-date">${new Date(b.date).toLocaleDateString('de-DE')}</span>
    </div>`
  ).join('') || '<p style="color:#94a3b8">Noch keine Bewertungen</p>';
  document.getElementById('betreuer-profil-modal').style.display = 'flex';
}
function closeBetreuerProfil() {
  document.getElementById('betreuer-profil-modal').style.display = 'none';
}
```
Aufruf: Betreuer-Karte im Buchungs-Flow und in Auftrags-/Besuchsdetails
→ Button "Profil ansehen" oder Klick auf Betreuer-Name.

Avatar-Upload: `PATCH /api/admin/betreuer/:id` erweitern um `avatar_url`.
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT DEFAULT '';

---

## BLOCK 7 — DISPO: EINGEHENDE BUCHUNGEN ALS QUEUE

### 7a. Backend:
```javascript
GET /api/admin/bookings/eingang
// Gibt alle Visits mit status='anfrage' zurück, neueste zuerst
// Mit patient_name, angehoerige_name (aus users JOIN), betreuer_name falls schon zugewiesen
```

### 7b. admin.html — Tab "Einsatzplanung" → Sub-Tab "Eingang"
Oben im Tab: Badge-Zähler "🔔 N neue Buchungsanfragen"
Tabelle:
| Eingang | Klient | Leistung | Wunschzeit | Wunsch-Betreuer | KI-Vorschlag | Aktion |
Zeile = Buchungsanfrage
Status-Info: "KI hat [Betreuer] vorgeschlagen (94% Konfidenz)"
Aktionen: [Details] [Route prüfen] — KEINE Bestätigung nötig (auto-bestätigt)
Aber: [Überschreiben] → Betreuer manuell ändern
Farb-Codierung: < 2h alt = grün | < 24h = gelb | älter = grau

WebSocket-Event `new_booking` → Badge-Counter inkrementieren + Zeile prependen

---

## BLOCK 8 — PUSH-BENACHRICHTIGUNGEN + ANRUF-OPTION

### 8a. WebSocket-basierte In-App-Benachrichtigungen (bereits vorhanden — erweitern)

Betreuer-App (`bnav-b`): Glocken-Icon mit Badge-Zähler
- Badge = Anzahl ungelesener Events: neue Aufträge, Zeitänderungen
- Bei `new_assignment` oder `route_update`: Toast + Badge+1 + Ton (kurz, optional)

Klienten-App (`bnav`): Glocken-Icon mit Badge
- Bei `visit_rescheduled` (Zeitverschiebung > 15min): Toast mit Detailansicht
- Benachrichtigungs-Screen `sc-benachrichtigungen`: Liste aller Events (read/unread)

### 8b. Route-Änderungs-Benachrichtigung (Dispo → Klient)

Wenn `PATCH /api/admin/route/apply` ausgeführt wird:
```javascript
// Nach dem Update:
changedVisits.forEach(({ visit_id, old_time, new_time, patient_id, betreuer_id }) => {
  const delta = Math.abs(new Date(new_time) - new Date(old_time)) / 60000;
  if (delta >= 15) {
    // An Klient
    broadcastToUser(patient_id_angehoerige, {
      type: 'visit_rescheduled',
      visit_id, old_time, new_time,
      message: `Ihr Termin am ${fmtDate(new_time)} wurde auf ${fmtTime(new_time)} Uhr verschoben.`,
      phone: betreuer_phone  // Anruf-Option
    });
    // An Betreuer
    broadcastToUser(betreuer_id, {
      type: 'route_update',
      visit_id, old_time, new_time,
      message: `Termin verschoben: ${fmtDate(new_time)}, ${fmtTime(new_time)} Uhr`
    });
    // E-Mail-Queue (fire-and-forget, kein echtes SMTP nötig → console.log als Platzhalter)
    console.log(`[EMAIL] Sende Terminänderung an ${patient_email}: ${fmtTime(new_time)} Uhr`);
  }
});
```

### 8c. Anruf-Button in der Benachrichtigung (index.html)
Wenn `visit_rescheduled` Event empfangen:
```html
<div class="notif-card">
  <p>⏰ Ihr Termin wurde verschoben auf <strong>{{new_time}}</strong></p>
  <a href="tel:{{betreuer_phone}}" class="btn-call">📞 Betreuer anrufen</a>
</div>
```
`broadcastToUser`: Hilfsfunktion in server.js die WSS-Clients nach `user_id` filtert:
```javascript
function broadcastToUser(userId, msg) {
  wss.clients.forEach(c => {
    if (c.userId === userId && c.readyState === WebSocket.OPEN)
      c.send(JSON.stringify(msg));
  });
}
```
Beim WS-Handshake: `ws.userId = decoded.id` setzen (bereits vorhanden — prüfen).

### 8d. Betreuer-Selbstannahme
In der Betreuer-App (`sc-auftraege`, Anfrage-Tab):
Button "Annehmen" ruft `PATCH /api/visits/:id/accept` auf
→ bereits implementiert (aus vorherigem Sprint) — sicherstellen dass er sichtbar ist
→ WebSocket: nach Accept broadcast `assignment_accepted` an Admin

---

## BLOCK 9 — KLIENTEN-DATENEDIT (Angehöriger bearbeitet eigene Daten)

### 9a. Backend:
```javascript
PATCH /api/me/profile
// Auth: jede Rolle, ändert nur eigene User-Felder
// Erlaubte Felder: name, phone, address, password (mit altem PW bestätigen)
// NICHT änderbar: email, role, patient_ids (nur Admin)

PATCH /api/me/patient/:patient_id
// Auth: angehoeriger, nur eigene Patienten
// Erlaubte Felder: name, address, phone, insurance, insurance_number, notes, pflegegrad
// NICHT: betreuer_id, angehoerige_ids (nur Admin)
// Validierung: pflegegrad 1-5, keine XSS
// Audit-Log: 'patient_data_updated'
```

### 9b. Frontend: index.html — Screen `sc-mein-profil`
- Felder: Name, Telefon, Adresse (mit Autocomplete!)
- Passwort ändern: Altes PW + Neues PW + Bestätigen
- Patientendaten-Karte für jeden eigenen Patienten:
  Editierbare Felder: Name, Adresse, Telefon, Versicherung, Notizen
  [Speichern]-Button → `PATCH /api/me/patient/:id`
- Link in `#bnav`: Profil-Icon → `goTo('sc-mein-profil')`

---

## DATENBANKÄNDERUNGEN (alle `IF NOT EXISTS`)

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT DEFAULT '';
ALTER TABLE visits ADD COLUMN IF NOT EXISTS cancelled_by VARCHAR(50) DEFAULT '';
ALTER TABLE visits ADD COLUMN IF NOT EXISTS cancelled_reason TEXT DEFAULT '';
-- (status 'abgesagt' bereits im Workflow vorhanden)
```

---

## QUALITÄTSSICHERUNG (nach jedem Block ausführen)

```bash
node check_html_js.js          # JS-Syntax in index.html + admin.html
node -e "require('./server.js')" # Server startet ohne Fehler
# Manuell testen:
# 1. Login als betreuer@demo.com → landet in Betreuer-App ✓
# 2. Login als test@demo.com → landet in Angehörigen-App ✓
# 3. Adressfeld: "Berliner Str" tippen → Dropdown erscheint ✓
# 4. Termin in < 24h absagen → Toast "Ausfallgebühr" + Rechnung in DB ✓
# 5. Gleiche Zeit + Betreuer buchen → 409 Fehler ✓
# 6. Betreuer-Profil öffnen → Modal mit Bewertungen ✓
```

---

## COMMIT

Nach erfolgreichem Test:
```
push_zu_github.bat
Commit-Message: "Curavio v2: Login-Fix, Autocomplete, Smart-Scheduling, Notifications, Profile"
```

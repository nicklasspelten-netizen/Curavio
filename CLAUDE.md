# CURAVIO – Projektkontext für Claude Code

## Projektübersicht
Curavio ist eine mobile PWA für ambulante Alltagsbegleitung (Pflegebranche).
- **Live-URL:** https://curavio.onrender.com
- **GitHub:** https://github.com/nicklasspelten-netizen/Curavio
- **Deployment:** Render.com (auto-deploy bei git push)
- **Owner:** Nicklas Spelten, nicklas.spelten@therapiezentrum.com

---

## Technologie-Stack

| Schicht | Technologie |
|---|---|
| Backend | Node.js + Express.js |
| Datenbank | PostgreSQL (Render managed DB) |
| Auth | JWT (HS256), bcryptjs |
| Realtime | WebSocket (ws-Paket) |
| KI | Anthropic Claude API (Berichts-Zusammenfassung) |
| Frontend | Vanilla JS SPA, eine einzige HTML-Datei |
| PWA | manifest.json + sw.js (installierbar auf Handy) |
| Deploy | Render.com Free Tier |

---

## Ordnerstruktur

```
curavio-backend/
├── server.js              # Haupt-Backend (Express + WS + DB + PDF + Buchhaltung)
├── check_html_js.js       # Dev-Tool: Syntax-Check der <script>-Blöcke
├── public/
│   ├── index.html         # Mobile SPA (Angehörige + Betreuer)
│   ├── admin.html         # Disponenten-Dashboard (Desktop, /admin)
│   ├── manifest.json      # PWA-Manifest
│   └── sw.js              # Service Worker
├── .env                   # Lokale Umgebungsvariablen (nicht in Git)
├── .env.example           # Vorlage für .env
├── package.json
├── render.yaml            # Render-Deployment-Konfiguration
├── push_zu_github.bat     # Ein-Klick GitHub Push (Windows)
├── starten.bat            # Lokalen Server starten (Windows)
└── install_und_start.bat  # npm install + Start
```

---

## Umgebungsvariablen

### Lokal (.env)
```
JWT_SECRET=curavio_super_secret_jwt_key_2024
PORT=3000
DATABASE_URL=postgresql://curavio_db_user:2dF2WTqZNDriII1zmnl7hntKHeHqQQZG@dpg-d8k54rtdt1ts73ao0mvg-a/curavio_db
ANTHROPIC_API_KEY=<key hier eintragen>
```

### Render.com (bereits gesetzt)
- `DATABASE_URL` – PostgreSQL Internal URL (bereits verbunden)
- `JWT_SECRET` – gesetzt
- `PORT` – von Render automatisch gesetzt

---

## Datenbankschema (PostgreSQL)

```sql
-- Benutzer (3 Rollen: angehoeriger | betreuer | admin)
users (id, name, email, password, role, patient_ids, created_at)

-- Patienten / Pflegebedürftige
patients (id, name, address, care_level, pflegegrad, betreuer_id,
          angehoerige_ids, notes, created_at)

-- Besuche / Aufträge
visits (id, patient_id, betreuer_id, service, scheduled_at,
        duration_min, status, services, notes,
        actual_start, actual_end,   -- Stempeluhr-Zeitstempel
        created_at)

-- Berichte nach Besuch
reports (id, visit_id, patient_id, betreuer_id, content,
         tasks_done, mood, ai_summary, created_at)

-- Chat-Nachrichten
messages (id, room_id, sender_id, sender_name, content, created_at)
```

### Visit-Status-Workflow
```
anfrage → geplant → bestätigt → unterwegs → abgeschlossen
                              ↘ abgelehnt
```

---

## API-Routen (server.js)

### Auth
```
POST /api/register    – Registrierung
POST /api/login       – Login → JWT zurück
GET  /api/me          – Eigenes Profil
```

### Patienten (angehöriger-Sicht)
```
GET  /api/patients               – Eigene Patienten
POST /api/patients               – Patient anlegen
```

### Besuche
```
GET  /api/visits                 – Besuche für eingeloggten User
POST /api/visits                 – Neuen Besuch buchen
GET  /api/betreuer/visits        – Alle Aufträge für Betreuer (inkl. offene Anfragen)
```

### Betreuer – Stempeluhr
```
PATCH /api/visits/:id/clockin    – Einstempeln (actual_start = NOW())
PATCH /api/visits/:id/clockout   – Ausstempeln (actual_end = NOW())
GET   /api/betreuer/arbeitszeiten – Alle erfassten Zeiten mit Stunden
```

### Betreuer – Anfragen
```
PATCH /api/visits/:id/accept     – Auftrag annehmen (status → geplant)
PATCH /api/visits/:id/decline    – Auftrag ablehnen (status → abgelehnt)
```

### Berichte
```
GET  /api/reports                – Berichte für eingeloggten User
POST /api/reports                – Neuen Bericht erstellen (löst Claude-Zusammenfassung aus)
```

### Chat
```
GET  /api/messages/:room_id      – Nachrichtenverlauf
WS   ws://...                    – Echtzeit-Chat (auth + chat + visit_update Events)
```

### Admin / Disponent
```
GET  /api/admin/users            – Alle Benutzer
POST /api/admin/users            – User erstellen
GET  /api/admin/visits[/all]     – Alle Besuche (Filter: status, betreuer_id, patient_id, von, bis)
PATCH /api/admin/visits/:id/assign – Betreuer zuweisen (Disponent)
GET  /api/admin/stats            – Zähler-Stats
GET  /api/admin/dashboard        – KPIs (Umsatz, offene Rechnungen, Einsätze, Anfragen)
GET  /api/admin/betreuer         – Betreuer mit Auslastung/Wochenstunden
PATCH /api/admin/betreuer/:id    – Profil (Stundensatz, Quali, IBAN, aktiv)
POST /api/admin/demo             – Demo-Daten generieren (idempotent)
GET/PUT /api/admin/settings      – Firmen-/Rechnungseinstellungen
```

### Rechnungen & Zahlungen
```
GET  /api/invoices                      – Eigene Rechnungen (Rolle-abhängig)
GET  /api/invoices/:id/pdf              – PDF (Besitzer od. Admin; Token auch via ?token=)
GET  /api/admin/invoices                – Alle Rechnungen
POST /api/admin/invoices/generate       – Auto-Generierung aus Arbeitszeiten
                                          Body: {recipient_id, type:'kunde'|'betreuer',
                                                 period_from, period_to,
                                                 apply_entlastung, apply_verhinderung}
                                          → zieht Freibeträge automatisch ab, §35a-Hinweis
GET  /api/admin/invoices/:id/pdf        – Rechnungs-PDF (pdfkit)
PATCH /api/admin/invoices/:id/status    – entwurf|versendet|bezahlt|storniert
                                          (Storno bucht Freibeträge zurück)
POST /api/admin/invoices/:id/payment    – Zahlung erfassen (markiert bezahlt bei Vollzahlung)
GET  /api/admin/payments[/offen]        – Zahlungen / offene+überfällige Rechnungen
```

### Freibeträge (§45b SGB XI · §39 SGB XI · §35a EStG)
```
GET  /api/freibetraege/:patient_id/:year        – Jahresübersicht (Angehörige/Betreuer/Admin)
GET  /api/admin/freibetraege/:pid/check         – Restbudgets aktuelles Jahr
GET/PUT /api/admin/freibetraege/:pid/:year      – Budgets lesen/setzen
```
Neue Patienten bekommen automatisch einen Freibetrag-Datensatz mit Richtwerten
nach Pflegegrad (Pflegegeld, Verhinderungspflege ab PG2, Entlastung 125€/Monat).

### Buchhaltung
```
GET /api/admin/buchhaltung/monat/:YYYY-MM   – Monatsabschluss (Einnahmen/Ausgaben/Ergebnis)
GET /api/admin/buchhaltung/betreuer/:id     – Betreuer-Abrechnung (?monat=YYYY-MM)
GET /api/admin/buchhaltung/export/csv       – Steuerberater-CSV (?von=&bis=)
GET /api/admin/buchhaltung/export/datev     – DATEV-ähnlicher Buchungsstapel
GET /api/admin/leistungsnachweis/:visit_id  – Leistungsnachweis-PDF für Pflegekasse
GET/POST /api/admin/expenses                – Ausgaben
GET /api/betreuer/abrechnung                – Eigene Monatsabrechnung (Stunden × Satz)
GET/PUT /api/betreuer/availability          – Verfügbarkeit/Abwesenheit
POST /api/visits/:id/rating                 – Besuch bewerten (1-5 Sterne, Angehörige)
```

### Disponenten-Dashboard
`public/admin.html` → erreichbar unter **/admin** (Desktop, nur role=admin).
Tabs: Übersicht (KPIs + Anfragen-Queue + Live-Feed), Einsatzplanung (Wochenkalender
mit Konflikterkennung), Betreuer, Klienten (Freibeträge), Rechnungen & Buchhaltung,
Einstellungen.

---

## Frontend-Architektur (public/index.html)

Eine einzige HTML-Datei mit vollständiger SPA-Logik.

### Screens nach Rolle

**Angehöriger (role: angehoeriger)**
- `sc-login` – Login/Register
- `sc-home` – Dashboard mit Patientenkarte + Besuchsliste
- `sc-track` – Live-Tracking (animierte Karte + ETA)
- `sc-book` – Besuch buchen (3-Step-Flow)
- `sc-rep` – Besuchsberichte lesen
- `sc-chat` – Chat mit Betreuer

**Betreuer (role: betreuer)**
- `sc-bh` – Betreuer-Home (Stats, Heute-Übersicht, Schnellzugriff)
- `sc-auftraege` – Aufträge (Tabs: Heute / Woche / Anfragen)
- `sc-stempel` – Stempeluhr (Ein-/Ausstempeln + Timer)
- `sc-stunden` – Arbeitszeiten (Woche/Monat + Liste)
- `sc-brep` – Besuchsberichte schreiben
- `sc-bchat` – Chat mit Familien

### Wichtige JS-Funktionen

```javascript
showApp()             // Routing nach Rolle (angehöriger vs betreuer)
showBetreuerApp()     // Betreuer-Dashboard initialisieren
goTo(id)              // Screen wechseln + Nav-Highlight
api(path, opts)       // Fetch-Wrapper mit JWT-Auth

// Angehöriger
loadAll()             // loadPatient + loadVisits + loadReports + loadMessages
loadVisits()          // Besuche laden und rendern
doBook()              // Besuch buchen

// Betreuer
loadBetreuerHome()    // Home-Stats + Heute-Liste
loadAuftraege()       // Auftrags-Tabs laden
auftrTab(tab)         // Tab wechseln (heute|woche|anfragen)
doAccept(id)          // Auftrag annehmen
doDecline(id)         // Auftrag ablehnen
doClockIn(id)         // Einstempeln
doClockOut(id)        // Ausstempeln
loadArbeitszeiten()   // Stunden-Übersicht laden
loadBetreuerBerichte()// Eigene Berichte laden
submitBericht()       // Neuen Bericht speichern
```

### CSS-Design-System
```css
--forest       /* Hauptfarbe Grün */
--amber        /* Akzent Gelb-Orange */
--cream-lt     /* Hintergrund hell */
--border       /* Rahmenfarbe */
--f-serif      /* Überschriften-Font */
--f-sans       /* Body-Font */
```

---

## Demo-Zugänge (lokal & live)

```
Angehöriger:  demo@curavio.de    /  demo123
Betreuer:     betreuer@curavio.de / demo123
Admin:        admin@curavio.de   /  admin123
```

Falls nicht vorhanden: POST /api/admin/demo aufrufen.

---

## Lokale Entwicklung

```bash
cd curavio-backend
npm install
node server.js
# → http://localhost:3000
```

## Deploy zu Render

```bash
# Windows: Doppelklick auf
push_zu_github.bat
# → Render deployed automatisch in ~2 Min
```

---

## Offene Aufgaben / Nächste Schritte

### Erledigt (Juni 2026)
- [x] **index.lock Problem** – bat-Script löscht Lock-Dateien vor `git add`
- [x] **Admin-Dashboard** – `public/admin.html` unter /admin (6 Tabs, Disposition + Buchhaltung)
- [x] **Rechnungsstellung** – Auto-Generierung aus Arbeitszeiten inkl. Freibetragsabzug + PDF (pdfkit)
- [x] **Freibetragslogik** – §45b Entlastungsbetrag, §39 Verhinderungspflege, §35a-Hinweis, Restbudget-Tracking
- [x] **Zahlungsverfolgung** – Zahlungen buchen, Überfällig-Erkennung, Monatsabschluss, CSV/DATEV-Export
- [x] **Kalenderansicht** – Wochenkalender im Admin mit Konflikterkennung
- [x] **Demo-Daten idempotent** – POST /api/admin/demo mit ON CONFLICT DO NOTHING
- [x] **WS-Token-Validierung** – auth-Event vor join/chat, Reconnect nur bei gültigem Login
- [x] **Kritischer Bugfix** – VARCHAR-Visit-IDs in onclick-Handlern jetzt gequotet (Annehmen/Stempeln funktionierte vorher nie)
- [x] **Pflichtbericht vor Ausstempeln** + optionaler GPS-Zeitstempel
- [x] **Klienten-Finanzen** – Rechnungen einsehen/PDF, Freibetragsstand, Bewertung nach Besuch

### Mittlere Priorität
- [ ] **Push-Benachrichtigungen** – Web Push API (VAPID-Keys nötig) für neue Aufträge / Statusänderungen
- [ ] **Patientenprofil** – Detailansicht mit Medikamenten, Notizen, Kontakten
- [ ] **Mehrere Patienten** – Angehörige mit mehreren Pflegebedürftigen (UI; API unterstützt es bereits)
- [ ] **Freibetrags-Werte prüfen** – Defaults folgen der Projektvorgabe (125€/Monat §45b, 1.612€
      Verhinderungspflege, 4.000€ §35a). Gesetzliche Anpassungen pro Klient im Admin pflegbar.

### Technische Schulden
- [ ] **index.html aufteilen** – React oder zumindest separate JS/CSS-Dateien
- [ ] **Tests** – API-Tests mit Jest oder Supertest (aktuell Syntax-Check via check_html_js.js)
- [ ] **Logging** – Structured logging statt console.log
- [ ] **Rechnungsnummern** – String-Sortierung bricht bei >999 Rechnungen/Jahr

---

## Wichtige Hinweise für Claude Code

1. **Alles in einer Datei**: `public/index.html` ist ~1200 Zeilen und enthält HTML + CSS + JS in einer Datei. Das war eine bewusste Entscheidung für einfaches Deployment.

2. **PostgreSQL-Migrationen**: Neue Spalten immer mit `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` hinzufügen — die DB läuft live auf Render.

3. **Visit-IDs sind VARCHAR**: Nicht INTEGER — bei neuen Routen `$1::varchar` beachten falls nötig.

4. **Betreuer-Routing**: In `showApp()` prüfen ob `USER.role === 'betreuer'` und dann `showBetreuerApp()` aufrufen. Beide Nav-Bars (`#bnav` für Angehörige, `#bnav-b` für Betreuer) immer korrekt ein-/ausblenden.

5. **WebSocket Events**: `visit_update` triggert Reload bei Angehörigen, `new_assignment` bei Betreuern.

6. **ANTHROPIC_API_KEY**: Für die KI-Berichts-Zusammenfassung nötig. Lokal in `.env`, auf Render als Env-Variable setzen.

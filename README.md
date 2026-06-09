# Curavio – Setup & Deployment

## In 5 Schritten live

### 1. Node.js installieren
https://nodejs.org → LTS Version herunterladen und installieren

### 2. Projekt einrichten
```bash
# Ordner öffnen
cd curavio-backend

# Abhängigkeiten installieren
npm install

# .env Datei erstellen
copy .env.example .env
```

### 3. .env ausfüllen
Öffne die `.env` Datei und trage ein:
- `ANTHROPIC_API_KEY` → von https://console.anthropic.com (kostenlos registrieren)
- `JWT_SECRET` → beliebiger langer Text z.B. "mein_geheimer_curavio_key_2024"

### 4. App starten
```bash
node server.js
```

Dann im Browser öffnen: **http://localhost:3000**

### 5. Demo-Logins
| Rolle | E-Mail | Passwort |
|---|---|---|
| Angehöriger | thomas@demo.de | curavio123 |
| Betreuer | maria@demo.de | curavio123 |
| Admin | admin@curavio.de | curavio123 |

---

## Online deployen (kostenlos)

### Option A: Render.com (empfohlen, kostenlos)
1. Account erstellen auf https://render.com
2. "New Web Service" → GitHub Repo verbinden ODER Code hochladen
3. Environment Variables eintragen (ANTHROPIC_API_KEY, JWT_SECRET)
4. Deploy klicken → App ist live unter https://curavio-xxx.onrender.com

### Option B: Railway.app
1. https://railway.app → New Project → Deploy from GitHub
2. Variables eintragen
3. Fertig – kostenlos bis 500h/Monat

### Option C: Eigener Server (Hetzner, ~5€/Monat)
```bash
# Server einrichten (Ubuntu)
apt update && apt install nodejs npm -y
git clone [dein-repo]
cd curavio-backend
npm install
cp .env.example .env
nano .env  # API Keys eintragen
node server.js
```

---

## Was ist drin

### Backend (server.js)
- ✅ JWT-Authentifizierung (Login / Register)
- ✅ SQLite Datenbank (keine externe DB nötig)
- ✅ 3 Rollen: Angehöriger, Betreuer, Admin
- ✅ Echtzeit-Chat via WebSocket
- ✅ KI-Besuchsberichte via Claude API (Anthropic)
- ✅ Termin-Buchungssystem
- ✅ Demo-Daten werden automatisch angelegt

### Frontend (public/index.html)
- ✅ Echtes Login mit JWT
- ✅ Home mit Live-Besuchen aus Datenbank
- ✅ Live-Tracking Screen
- ✅ Buchungsflow (speichert in DB)
- ✅ Echte Besuchsberichte mit KI-Zusammenfassung
- ✅ Echtzeit-Chat (WebSocket)

### API-Endpunkte
```
POST /api/auth/login          Login
POST /api/auth/register       Registrierung
GET  /api/patients            Meine Patienten
POST /api/patients            Patient anlegen
GET  /api/visits              Besuche abrufen
POST /api/visits              Termin buchen
PATCH /api/visits/:id/status  Status aktualisieren
GET  /api/reports             Berichte abrufen
POST /api/reports             Bericht + KI erstellen
GET  /api/messages/:room_id   Chatverlauf
GET  /api/admin/stats         Admin Dashboard
```

---

## Nächste Schritte (Phase 2)

- [ ] Betreuer-App (eigener Screen für Maria)
- [ ] Push-Benachrichtigungen (Firebase)
- [ ] Echte GPS-Karte (Google Maps API)
- [ ] E-Mail-Benachrichtigungen
- [ ] Kassenabrechnung (XML-Export)
- [ ] iOS/Android App (React Native)
- [ ] DSGVO-Hosting Deutschland (Hetzner Falkenstein)

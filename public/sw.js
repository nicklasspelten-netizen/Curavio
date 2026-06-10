// Bei jedem Deploy hochzählen → erzwingt frische App-Version auf allen Geräten
const CACHE = 'curavio-v4';

self.addEventListener('install', e => {
  // Neue Version sofort aktiv schalten, nicht auf Tab-Schließen warten
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.map(k => caches.delete(k)))) // ALLE alten Caches löschen
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  // API + WebSocket nie cachen
  if (req.url.includes('/api/') || req.url.includes('/ws')) return;

  // HTML-Navigation (die App-Seite selbst): IMMER frisch aus dem Netz holen,
  // Cache nur als Offline-Fallback. So kann keine alte index.html „kleben bleiben".
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).catch(() => caches.match('/') || caches.match(req))
    );
    return;
  }

  // Übrige statische Dateien: Netz zuerst, Cache als Fallback
  e.respondWith(
    fetch(req)
      .then(res => {
        if (res && res.status === 200 && req.method === 'GET') {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(req, clone));
        }
        return res;
      })
      .catch(() => caches.match(req))
  );
});

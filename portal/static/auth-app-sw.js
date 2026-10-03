/* ServerManager Authenticator — offline cache for the phone app. */
const CACHE = "sm-auth-app-v5";
const ASSETS = [
  "/auth-app.html",
  "/static/auth-app.webmanifest",
  "/static/auth-app-icon-180.png",
  "/static/auth-app-icon-192.png",
  "/static/auth-app-icon-512.png",
  "/static/auth-app-sw.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  event.respondWith(
    caches.match(req).then((hit) => {
      if (hit) return hit;
      return fetch(req)
        .then((res) => {
          const copy = res.clone();
          if (res.ok && new URL(req.url).origin === self.location.origin) {
            caches.open(CACHE).then((cache) => cache.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => caches.match("/auth-app.html"));
    })
  );
});

/* ServerManager iPhone Authenticator — offline cache */
const CACHE = "sm-auth-iphone-v27";
const ASSETS = [
  "/auth-app-iphone.html",
  "/static/auth-app-iphone.webmanifest",
  "/static/auth-app-icon-180.png",
  "/static/auth-app-icon-192.png",
  "/static/auth-app-icon-512.png",
  "/static/auth-app-iphone-sw.js",
  "/static/sm-circle-crypto.js",
  "/static/sm-network-exit.js",
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
  const url = new URL(req.url);
  // HTML always prefers network so layout fixes land immediately.
  const isHtml =
    req.mode === "navigate" ||
    req.destination === "document" ||
    url.pathname.endsWith(".html");
  if (isHtml) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          if (res.ok) {
            caches.open(CACHE).then((cache) => cache.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => caches.match("/auth-app-iphone.html"))
    );
    return;
  }
  event.respondWith(
    caches.match(req).then((hit) => {
      if (hit) return hit;
      return fetch(req)
        .then((res) => {
          const copy = res.clone();
          if (res.ok && url.origin === self.location.origin) {
            caches.open(CACHE).then((cache) => cache.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => caches.match("/auth-app-iphone.html"));
    })
  );
});

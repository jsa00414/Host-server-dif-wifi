/* ServerManager iPhone Authenticator — offline cache */
const CACHE = "sm-auth-iphone-v32";
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
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // Drop every Authenticator cache so stale layouts cannot stick.
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
      await caches.open(CACHE).then((cache) => cache.addAll(ASSETS));
      await self.clients.claim();
      const clients = await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });
      for (const client of clients) {
        try {
          client.postMessage({ type: "SM_AUTH_FORCE_RELOAD", cache: CACHE });
        } catch (_) {}
        try {
          if (client.navigate) client.navigate(client.url);
        } catch (_) {}
      }
    })()
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  const isHtml =
    req.mode === "navigate" ||
    req.destination === "document" ||
    url.pathname.endsWith(".html") ||
    url.pathname.endsWith("-sw.js") ||
    url.pathname.endsWith(".webmanifest");

  // HTML / SW / manifest: always network-first so layout fixes land.
  if (isHtml) {
    event.respondWith(
      fetch(req, { cache: "no-store" })
        .then((res) => {
          const copy = res.clone();
          if (res.ok) {
            caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => caches.match("/auth-app-iphone.html"))
    );
    return;
  }

  event.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        if (res.ok && url.origin === self.location.origin) {
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req))
  );
});

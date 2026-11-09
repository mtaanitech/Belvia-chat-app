// Orivoclass service worker.
// 1) Keeps the app updating itself: the page is always fetched from the network first, so a new push shows up the next time the app opens.
// 2) Falls back to the saved copy when there is no internet.
// 3) Shows push notifications. Keep this file next to index.html.
const VERSION = "2026-11-08.1";
const CACHE = "orivoclass-" + VERSION;
const SHELL = ["./", "index.html", "manifest.webmanifest", "icon-192.png", "icon-512.png", "icon-maskable-512.png", "apple-touch-icon.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => Promise.all(SHELL.map((u) => c.add(u).catch(() => {})))).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k.indexOf("orivoclass-") === 0 && k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("message", (e) => { if (e.data === "skipWaiting") self.skipWaiting(); });

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // never touch the API or other sites
  const isPage = req.mode === "navigate" || url.pathname.endsWith("/") || url.pathname.endsWith("/index.html");
  if (isPage) { // network first, so updates arrive without anyone downloading anything
    e.respondWith((async () => {
      try {
        const r = await fetch(url.pathname + url.search, { cache: "no-store" });
        if (r.ok) { const c = await caches.open(CACHE); c.put("index.html", r.clone()).catch(() => {}); }
        return r;
      } catch (err) {
        return (await caches.match("index.html")) || (await caches.match("./")) || Response.error();
      }
    })());
    return;
  }
  // icons and manifest: saved copy first, refreshed in the background
  e.respondWith((async () => {
    const hit = await caches.match(req);
    const net = fetch(req).then((r) => { if (r.ok) caches.open(CACHE).then((c) => c.put(req, r.clone())); return r; }).catch(() => hit);
    return hit || net;
  })());
});

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) {}
  e.waitUntil((async () => {
    // If the app is open and on screen, the person already sees what is happening.
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (wins.some((c) => c.visibilityState === "visible")) return;
    const call = !!(d.tag && String(d.tag).indexOf("call") === 0);
    await self.registration.showNotification(d.title || "Orivoclass", { body: d.body || "", icon: "icon-192.png", badge: "icon-192.png", tag: d.tag || undefined, renotify: !!d.tag, requireInteraction: call, vibrate: call ? [400, 200, 400, 200, 400] : [100] });
  })());
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of wins) if ("focus" in c) return c.focus();
    return self.clients.openWindow("./");
  })());
});

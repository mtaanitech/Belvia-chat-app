// Orivoclass service worker.
// 1) Keeps the app updating itself: the page is always fetched from the network first, so a new push shows up the next time the app opens.
// 2) Falls back to the saved copy when there is no internet.
// 3) Shows push notifications. Keep this file next to index.html.
const VERSION = "2026-11-13.1";
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
  if (isPage) { // newest copy first; the saved copy is used only when the network is slow or missing
    e.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const cached = await cache.match("index.html");
      const fresh = fetch(url.pathname + url.search, { cache: "no-store" }).then(async (r) => {
        if (r.ok) {
          const was = cached && (cached.headers.get("etag") || cached.headers.get("last-modified"));
          const now = r.headers.get("etag") || r.headers.get("last-modified");
          await cache.put("index.html", r.clone());
          if (was && now && was !== now) (await self.clients.matchAll({ type: "window" })).forEach((c) => c.postMessage({ type: "updated" }));
        }
        return r;
      });
      if (!cached) { try { return await fresh; } catch (err) { return Response.error(); } }
      const timeout = new Promise((res) => setTimeout(() => res(null), 2500));
      const first = await Promise.race([fresh.catch(() => null), timeout]);
      if (first && first.ok) return first;
      e.waitUntil(fresh.catch(() => {}));
      return cached;
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
    const type = d.type || "";
    const actions = type === "call" ? [{ action: "answer", title: "Answer" }, { action: "decline", title: "Decline" }]
      : type === "msg" ? [{ action: "reply", title: "Reply" }, { action: "read", title: "Mark as read" }] : [];
    await self.registration.showNotification(d.title || "Orivoclass", {
      body: d.body || "", icon: "icon-192.png", badge: "icon-192.png", tag: d.tag || undefined, renotify: !!d.tag,
      requireInteraction: call, vibrate: call ? [400, 200, 400, 200, 400] : [100], actions,
      data: { type, id: d.id || "", peer: d.peer || "" },
    });
  })());
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const d = e.notification.data || {};
  const p = { act: e.action || "", call: d.type === "call" ? String(d.id || "") : "", peer: d.type === "msg" ? String(d.peer || "") : "" };
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (wins.length) { const c = wins[0]; if ("focus" in c) await c.focus(); c.postMessage({ type: "action", p }); return; }
    const q = new URLSearchParams();
    if (p.act) q.set("act", p.act);
    if (p.call) q.set("call", p.call);
    if (p.peer) q.set("peer", p.peer);
    return self.clients.openWindow("./" + (q.toString() ? "?" + q.toString() : ""));
  })());
});

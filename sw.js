// Orivoclass service worker: shows push notifications. Keep this file next to index.html.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) {}
  e.waitUntil((async () => {
    // If the app is open and on screen, the person already sees what is happening.
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (wins.some((c) => c.visibilityState === "visible")) return;
    await self.registration.showNotification(d.title || "Orivoclass", { body: d.body || "", tag: d.tag || undefined, renotify: !!d.tag });
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

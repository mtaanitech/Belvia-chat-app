require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
// Push notifications need the "web-push" package and VAPID keys. Without them the server works and notifications stay off.
let webpush = null;
try {
  const { VAPID_PUBLIC, VAPID_PRIVATE, VAPID_SUBJECT } = process.env;
  if (VAPID_PUBLIC && VAPID_PRIVATE) { webpush = require("web-push"); webpush.setVapidDetails(VAPID_SUBJECT || "mailto:admin@example.com", VAPID_PUBLIC, VAPID_PRIVATE); }
} catch (e) { console.warn("Push notifications are off:", e.message); webpush = null; }
const { Pool } = require("pg");

const { DATABASE_URL, JWT_SECRET, FRONTEND_ORIGIN } = process.env;
if (!DATABASE_URL || !JWT_SECRET) {
  console.error("Set DATABASE_URL and JWT_SECRET");
  process.exit(1);
}

const db = new Pool({ connectionString: DATABASE_URL });
const app = express();
app.set("trust proxy", 1);
// Behind Cloudflare the visitor's real address is in CF-Connecting-IP. Use it, so limits apply to each person.
app.use((req, res, next) => {
  const cf = req.headers["cf-connecting-ip"];
  if (cf) Object.defineProperty(req, "ip", { value: String(cf).split(",")[0].trim(), configurable: true });
  next();
});
// If the security settings are ever rejected, start anyway (without the content policy) instead of crashing.
let helmetMw;
try {
  helmetMw = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:", "blob:"],
      "media-src": ["'self'", "blob:", "data:"],
      "connect-src": ["'self'", "https:"],
      "worker-src": ["'self'"],
      "manifest-src": ["'self'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'none'"],
    },
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }, // the API stays usable from the app wherever it is opened
});
} catch (e) { console.warn("helmet settings problem, using a simpler setup:", e.message); helmetMw = helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: "cross-origin" } }); }
app.use(helmetMw);
app.use(cors({ origin: FRONTEND_ORIGIN ? FRONTEND_ORIGIN.split(",") : false, maxAge: 86400 })); // browsers remember the "may I talk to this server?" check, so each request is one trip instead of two
app.use(express.json({ limit: "2mb" })); // room for one picture for the AI
// Whole-app switch (set by the admin). While it is off, nothing works except the admin and the health check.
let APPFLAG = { on: true, off: [], at: 0 };
app.use(async (req, res, next) => {
  if (req.path === "/health" || req.path.startsWith("/api/admin") || req.path === "/api/version") return next();
  if (Date.now() - APPFLAG.at > 10000) {
    try {
      const r = await db.query("SELECT value FROM app_settings WHERE key='app'");
      const c = (await db.query("SELECT value FROM app_settings WHERE key='countries'")).rows[0];
      APPFLAG = { on: !r.rows[0] || r.rows[0].value.on !== false, off: c ? Object.keys(c.value).filter((k) => c.value[k] === false) : [], at: Date.now() };
    } catch (e) { APPFLAG.at = Date.now(); }
  }
  const visitorCountry = String(req.headers["cf-ipcountry"] || "").toUpperCase();
  if (visitorCountry && APPFLAG.off.includes(visitorCountry)) {
    if (req.path.startsWith("/api/")) return res.status(403).json({ error: "Orivoclass is not available in your country right now." });
    return res.status(403).type("html").send("<!doctype html><meta charset=utf-8><body style='font-family:system-ui;text-align:center;padding:40px'><h2>Orivoclass is not available in your country right now.</h2>");
  }
  if (APPFLAG.on) return next();
  if (req.path.startsWith("/api/")) return res.status(503).json({ error: "Orivoclass is not available right now." });
  res.status(503).type("html").send("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><body style='font-family:system-ui;text-align:center;padding:40px'><h2>Orivoclass is not available right now.</h2><p>Please try again later.</p></body>");
}); // status photos are up to ~160 KB; each route checks its own size
app.use("/api/", rateLimit({ windowMs: 60000, max: 1500, keyGenerator: (req) => (req.headers.authorization ? "t" + String(req.headers.authorization).slice(-32) : req.ip) })); // per person, not per IP: many tabs and phones behind one network are fine
const authLimit = rateLimit({ windowMs: 15 * 60000, max: 20 });

// ---- Recovery code: XXXX-XXXX-XXXX-XXXX (only the hash is stored) ----
const ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const makeCode = () => {
  const b = crypto.randomBytes(16);
  let s = "";
  for (let i = 0; i < 16; i++) s += ALPHA[b[i] % 32];
  return s.match(/.{4}/g).join("-");
};
const hashCode = (c) => crypto.createHash("sha256").update(String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "")).digest("hex");

const typing = new Map();
const isTyping = (from, to) => Date.now() - (typing.get(from + ">" + to) || 0) < 6000;
setInterval(() => { for (const [k, t] of typing) if (Date.now() - t > 60000) typing.delete(k); }, 60000);
// Decides what a viewer may see about another user's online status and last seen.
function presence(row, inTheirContacts, blocked) {
  const p = row.seen_privacy || "everyone";
  const hidden = blocked || p === "nobody" || (p === "contacts" && !inTheirContacts);
  if (hidden || !row.last_seen) return { hidden: true, online: false, last_seen: null };
  return { hidden: false, online: Date.now() - new Date(row.last_seen).getTime() < 30000, last_seen: row.last_seen };
}

const wrap = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((e) => {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  });
const need = (req, res, next) => {
  const h = req.headers.authorization || "";
  let d;
  try { d = jwt.verify(h.replace(/^Bearer /, ""), JWT_SECRET); } catch { return res.status(401).json({ error: "Please log in again." }); }
  if (!d.uid) return res.status(401).json({ error: "Please log in again." });
  req.uid = d.uid;
  const touchUser = () => db.query("UPDATE users SET last_seen=now() WHERE id=$1 AND (last_seen IS NULL OR last_seen < now() - interval '10 seconds')", [req.uid]).catch(() => {});
  if (!d.sid) return res.status(401).json({ error: "Please log in again." }); // tokens made before sessions existed
  db.query("SELECT 1 FROM sessions WHERE id=$1 AND user_id=$2", [d.sid, d.uid]).then((r) => {
    if (!r.rowCount) return res.status(401).json({ error: "Please log in again." });
    req.sid = d.sid;
    db.query("UPDATE sessions SET last_seen=now() WHERE id=$1 AND last_seen < now() - interval '1 minute'", [d.sid]).catch(() => {});
    touchUser();
    next();
  }).catch(() => res.status(500).json({ error: "Server error" }));
};
const isId = (s) => /^[0-9a-f-]{36}$/i.test(String(s || ""));
const pub = (u) => ({ id: u.id, name: u.name, phone: u.phone, about: u.about, seen_privacy: u.seen_privacy, photo_privacy: u.photo_privacy, trust: u.trust_score, cover: u.cover, mood: u.mood, created_at: u.created_at });
const deviceName = (req) => { // plain names only: "Phone", "iPhone", "Computer" or "Browser"
  const ua = String(req.headers["user-agent"] || "");
  if (/iPhone|iPad|iPod/i.test(ua)) return "iPhone";
  if (/Android/i.test(ua)) return "Android phone";
  if (/Windows|Macintosh|Mac OS|Linux|X11/i.test(ua)) return "Computer";
  return "Browser";
};
// Every login creates a session. A session can be ended (log out) and is what the owner's "Is this you?" approval relies on.
async function newSession(u, req, dev) {
  const d = dev !== undefined ? dev : String((req.body && req.body.device) || "").replace(/[^A-Za-z0-9-]/g, "").slice(0, 80);
  if (d) await db.query("DELETE FROM sessions WHERE user_id=$1 AND device_id=$2", [u.id, d]); // the same browser or phone logs in again: one row, not a new one
  const r = await db.query("INSERT INTO sessions(user_id,device,device_id) VALUES($1,$2,$3) RETURNING id", [u.id, deviceName(req), d || null]);
  return { token: jwt.sign({ uid: u.id, sid: r.rows[0].id }, JWT_SECRET, { expiresIn: "30d" }), user: pub(u) };
}
setInterval(() => { db.query("DELETE FROM login_requests WHERE created_at < now() - interval '2 days'").catch(() => {}); db.query("DELETE FROM sessions WHERE last_seen < now() - interval '60 days'").catch(() => {}); }, 3600000);
// Normalises a number so one real phone = one account (removes the extra 0 in 2540712...)
const phoneOf = (p) => {
  let d = String(p || "").replace(/\D/g, "");
  if (d.startsWith("2540")) d = "254" + d.slice(4);
  return "+" + d;
};
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

app.get("/health", (req, res) => res.json({ service: "orivoclass-api", status: "ok", app: appDir ? "found" : "missing" }));
// Lets an old copy of the app know it must refresh. Raise MIN_CLIENT (and APP_VERSION in index.html) only when you make a change that old apps cannot work with.
app.get("/api/version", (req, res) => res.json({ min_client: Number(process.env.MIN_CLIENT) || 1 }));

// Proof that the Android app and this website belong to the same owner (removes the browser bar from the Android app).
// Set ANDROID_PACKAGE (e.g. com.orivoclass.app) and ANDROID_SHA256 (one or more fingerprints, separated by commas) on Render.
app.get("/.well-known/assetlinks.json", (req, res) => {
  const pkg = String(process.env.ANDROID_PACKAGE || "").trim();
  const prints = String(process.env.ANDROID_SHA256 || "").split(",").map((x) => x.trim().toUpperCase()).filter((x) => /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(x));
  if (!pkg || !prints.length) return res.status(404).json({ error: "Android app link is not set up yet." });
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.json([{ relation: ["delegate_permission/common.handle_all_urls"], target: { namespace: "android_app", package_name: pkg, sha256_cert_fingerprints: prints } }]);
});

// The app itself. Only these exact files are shown to visitors (never server.js or anything else).
// They are looked for next to server.js, in a folder called "public", or one folder above.
const APP_FILES = ["index.html", "admin.html", "sw.js", "manifest.webmanifest", "icon-192.png", "icon-512.png", "icon-maskable-512.png", "apple-touch-icon.png"];
let ICONS = {}; try { ICONS = require("./icons.js"); } catch (e) {} // icons kept as text in icons.js (optional)
// The app files are taken from the repository root first (the newest copy), then from "public" or the backend folder. Old copies inside backend are ignored.
const appDir = [path.join(__dirname, ".."), path.join(__dirname, "public"), __dirname].find((d) => fs.existsSync(path.join(d, "index.html")));
if (!appDir) console.warn("App files (index.html and the others) were not found next to server.js, so the app page will not be shown.");
for (const name of APP_FILES) {
  app.get(name === "index.html" ? ["/", "/index.html"] : ["/" + name], (req, res, next) => {
    if (appDir && fs.existsSync(path.join(appDir, name))) return res.sendFile(name, { root: appDir, headers: /\.(html|js|webmanifest)$/.test(name) ? { "Cache-Control": "no-cache" } : {} }); // html, sw.js and manifest are always re-checked, so updates arrive
    if (ICONS[name]) { res.setHeader("Content-Type", "image/png"); res.setHeader("Cache-Control", "public, max-age=86400"); return res.end(Buffer.from(ICONS[name], "base64")); }
    next();
  });
}

// ---- SMS code (OTP) ----
// DEV_SHOW_CODE=true  -> no SMS is sent, the code is returned to the app and shown on screen (testing only, NOT secure).
// otherwise           -> the code is sent by SMS through Africa's Talking (AT_USERNAME, AT_API_KEY).
if (process.env.DEV_SHOW_CODE === "true") console.warn("WARNING: DEV_SHOW_CODE is ON. Codes are shown on screen. Turn it off before launch.");
const otpHash = (phone, code) => crypto.createHash("sha256").update(phone + ":" + code + ":" + JWT_SECRET).digest("hex");
// Frostwood sends the SMS when FROST_API_KEY is set (FROST_SENDER = the approved sender name).
// Kenyan numbers are sent in the local form (07..), as Frostwood's examples show.
async function sendSms(to, text) {
  if (process.env.FROST_API_KEY) {
    const local = to.startsWith("+254") ? "0" + to.slice(4) : to;
    const r = await fetch("https://sms.frostwood.co.ke/api/v1/messages", {
      method: "POST",
      headers: { Authorization: "Bearer " + process.env.FROST_API_KEY, "Content-Type": "application/json", "Idempotency-Key": "otp-" + crypto.randomUUID() },
      body: JSON.stringify({ sender_id: process.env.FROST_SENDER || "ORIVOCLASS", category: "transactional", recipients: [local], body: text, client_reference: "otp-" + Date.now() }),
    });
    const j = await r.json().catch(() => ({}));
    if (r.status !== 202) {
      const detail = (j.error && (j.error.message || j.error.code)) || j.message || ("HTTP " + r.status);
      throw new Error("Frostwood: " + detail);
    }
    return; // 202 means accepted and queued
  }
  const { AT_USERNAME, AT_API_KEY } = process.env;
  const host = AT_USERNAME === "sandbox" ? "api.sandbox.africastalking.com" : "api.africastalking.com";
  const r = await fetch("https://" + host + "/version1/messaging", {
    method: "POST",
    headers: { apiKey: AT_API_KEY, Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: AT_USERNAME, to, message: text }),
  });
  const j = await r.json().catch(() => ({}));
  const rec = j.SMSMessageData && j.SMSMessageData.Recipients && j.SMSMessageData.Recipients[0];
  if (!r.ok || !rec || ![100, 101, 102].includes(rec.statusCode)) throw new Error("SMS failed: " + (rec ? rec.status : r.status));
}
app.post("/api/otp/send", authLimit, wrap(async (req, res) => {
  if (await countryOff(req.body.country)) return bad(res, "Orivoclass is not available in this country right now.", 403);
  const phone = phoneOf(req.body.phone);
  if (phone.length < 10 || phone.length > 16) return bad(res, "Enter a valid phone number.");
  if (phone.startsWith("+254") && !/^\+254[17]\d{8}$/.test(phone)) return bad(res, "Enter a valid Kenyan number.");
  if (await isBlockedPhone(phone)) return bad(res, "This number cannot be used on Orivoclass right now.", 403);
  if ((await db.query("SELECT 1 FROM users WHERE phone=$1", [phone])).rowCount) return bad(res, "This number is already registered.", 409);
  const prev = (await db.query("SELECT last_sent FROM otps WHERE phone=$1", [phone])).rows[0];
  if (prev && Date.now() - new Date(prev.last_sent).getTime() < 30000) return bad(res, "Wait 30 seconds before asking for a new code.", 429);
  const dev = process.env.DEV_SHOW_CODE === "true" && !process.env.FROST_API_KEY; // codes on screen only when no SMS service is set
  if (!dev && !process.env.FROST_API_KEY && (!process.env.AT_USERNAME || !process.env.AT_API_KEY)) return bad(res, "SMS is not set up yet.", 503);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  await db.query(
    `INSERT INTO otps(phone,code_hash,expires_at,attempts,last_sent) VALUES($1,$2,now()+interval '10 minutes',0,now())
     ON CONFLICT (phone) DO UPDATE SET code_hash=EXCLUDED.code_hash, expires_at=EXCLUDED.expires_at, attempts=0, last_sent=now()`,
    [phone, otpHash(phone, code)]);
  if (dev) return res.json({ sent: true, dev_code: code });
  try { await sendSms(phone, "Orivoclass code: " + code + ". Valid for 10 minutes. If you did not ask for it, ignore this message."); }
  catch (e) { console.error(e.message); return bad(res, "Could not send the SMS. Try again.", 502); }
  res.json({ sent: true });
}));
// END OF PART 1

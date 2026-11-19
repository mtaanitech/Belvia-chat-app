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
app.use(express.json({ limit: "256kb" })); // status photos are up to ~160 KB; each route checks its own size
app.use("/api/", rateLimit({ windowMs: 60000, max: 300 }));
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
const deviceName = (req) => {
  const ua = String(req.headers["user-agent"] || "");
  const os = /Android/i.test(ua) ? "Android" : /iPhone|iPad|iOS/i.test(ua) ? "iPhone/iPad" : /Windows/i.test(ua) ? "Windows" : /Mac OS/i.test(ua) ? "Mac" : /Linux/i.test(ua) ? "Linux" : "Unknown device";
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "browser";
  return os + " · " + br;
};
// Every login creates a session. A session can be ended (log out) and is what the owner's "Is this you?" approval relies on.
async function newSession(u, req) {
  const r = await db.query("INSERT INTO sessions(user_id,device) VALUES($1,$2) RETURNING id", [u.id, deviceName(req)]);
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
async function sendSms(to, text) {
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
  const phone = phoneOf(req.body.phone);
  if (phone.length < 10 || phone.length > 16) return bad(res, "Enter a valid phone number.");
  if (phone.startsWith("+254") && !/^\+254[17]\d{8}$/.test(phone)) return bad(res, "Enter a valid Kenyan number.");
  if (await isBlockedPhone(phone)) return bad(res, "This number cannot be used on Orivoclass right now.", 403);
  if ((await db.query("SELECT 1 FROM users WHERE phone=$1", [phone])).rowCount) return bad(res, "This number is already registered.", 409);
  const prev = (await db.query("SELECT last_sent FROM otps WHERE phone=$1", [phone])).rows[0];
  if (prev && Date.now() - new Date(prev.last_sent).getTime() < 30000) return bad(res, "Wait 30 seconds before asking for a new code.", 429);
  const dev = process.env.DEV_SHOW_CODE === "true";
  if (!dev && (!process.env.AT_USERNAME || !process.env.AT_API_KEY)) return bad(res, "SMS is not set up yet.", 503);
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
// ---- Auth ----
app.post("/api/signup", authLimit, wrap(async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 60);
  const phone = phoneOf(req.body.phone);
  const password = String(req.body.password || "");
  if (!name) return bad(res, "Please enter your name.");
  if (phone.length < 10 || phone.length > 16) return bad(res, "Enter a valid phone number.");
  if (phone.startsWith("+254") && !/^\+254[17]\d{8}$/.test(phone)) return bad(res, "Enter a valid Kenyan number.");
  if (password.length < 8) return bad(res, "Password must be at least 8 characters.");
  if (await isBlockedPhone(phone)) return bad(res, "This number cannot be used on Orivoclass right now.", 403);
  const otp = String(req.body.otp || "").replace(/\D/g, "");
  const row = (await db.query("SELECT * FROM otps WHERE phone=$1", [phone])).rows[0];
  if (!row || new Date(row.expires_at) < new Date()) return bad(res, "The code expired. Ask for a new one.", 410);
  if (row.attempts >= 5) return bad(res, "Too many wrong tries. Ask for a new code.", 429);
  if (row.code_hash !== otpHash(phone, otp)) {
    await db.query("UPDATE otps SET attempts=attempts+1 WHERE phone=$1", [phone]);
    return bad(res, "Wrong code.", 400);
  }
  const hash = await bcrypt.hash(password, 10);
  const code = makeCode();
  try {
    const r = await db.query(
      "INSERT INTO users(phone,name,pass_hash,recovery_hash) VALUES($1,$2,$3,$4) RETURNING *",
      [phone, name, hash, hashCode(code)]
    );
    await db.query("DELETE FROM otps WHERE phone=$1", [phone]);
    res.json({ ...(await newSession(r.rows[0], req)), recovery_code: code });
  } catch (e) {
    if (e.code === "23505") return bad(res, "This number is already registered.", 409);
    throw e;
  }
}));

const pollLimit = rateLimit({ windowMs: 60000, max: 90 });
const sha = (x) => crypto.createHash("sha256").update(String(x || "")).digest("hex");

app.post("/api/login", authLimit, wrap(async (req, res) => {
  const r = await db.query("SELECT * FROM users WHERE phone=$1", [phoneOf(req.body.phone)]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.pass_hash)))
    return bad(res, "Wrong number or password.", 401);
  const lm = await lockMsg(u);
  if (lm) return res.status(403).json({ error: lm, appeal: true });
  // If the owner still has a logged-in device, that device must approve this login ("Is this you?").
  const active = await db.query("SELECT 1 FROM sessions WHERE user_id=$1 AND last_seen > now() - interval '30 days' LIMIT 1", [u.id]);
  if (!active.rowCount) return res.json(await newSession(u, req));
  if ((await db.query("SELECT 1 FROM login_requests WHERE user_id=$1 AND status='denied' AND created_at > now() - interval '1 hour'", [u.id])).rowCount)
    return bad(res, "A login to this account was blocked by its owner. Try again later, or use your recovery code.", 403);
  const many = await db.query("SELECT count(*)::int AS n FROM login_requests WHERE user_id=$1 AND created_at > now() - interval '1 hour'", [u.id]);
  if (many.rows[0].n >= 3) return bad(res, "Too many login requests for this account. Try again later.", 429);
  const secret = crypto.randomBytes(24).toString("hex");
  const q = await db.query("INSERT INTO login_requests(user_id,secret_hash,device,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes') RETURNING id", [u.id, sha(secret), deviceName(req)]);
  res.json({ pending: true, request_id: q.rows[0].id, secret });
}));

// The new device asks "was I approved yet?" using the secret only it knows.
app.post("/api/login/status", pollLimit, wrap(async (req, res) => {
  if (!isId(req.body.id)) return bad(res, "Request not found.", 404);
  const r = (await db.query("SELECT * FROM login_requests WHERE id=$1", [req.body.id])).rows[0];
  if (!r || r.secret_hash !== sha(req.body.secret)) return bad(res, "Request not found.", 404);
  if ((r.status === "pending" || r.status === "approved") && new Date(r.expires_at) < new Date()) {
    await db.query("UPDATE login_requests SET status='expired' WHERE id=$1 AND status IN ('pending','approved')", [r.id]);
    return res.json({ status: "expired" });
  }
  if (r.status === "approved") {
    const used = await db.query("UPDATE login_requests SET status='used' WHERE id=$1 AND status='approved' RETURNING user_id", [r.id]);
    if (!used.rowCount) return res.json({ status: "used" });
    const u = (await db.query("SELECT * FROM users WHERE id=$1", [r.user_id])).rows[0];
    if (!u) return res.json({ status: "expired" });
    if (await lockMsg(u)) return res.json({ status: "denied" });
    return res.json({ status: "approved", ...(await newSession(u, req)) });
  }
  res.json({ status: r.status });
}));

// The owner's logged-in device checks for waiting requests and answers them.
app.get("/api/login-requests", need, wrap(async (req, res) => {
  const r = await db.query("SELECT id, device, created_at FROM login_requests WHERE user_id=$1 AND status='pending' AND expires_at > now() ORDER BY created_at DESC LIMIT 1", [req.uid]);
  const n = await db.query("SELECT id, kind, reason, until, created_at FROM sanctions WHERE user_id=$1 AND seen=false AND kind IN ('warning','restriction') ORDER BY id LIMIT 1", [req.uid]);
  await expireCalls();
  const cl = await db.query(`SELECT c.id, c.kind, c.caller AS from_id, COALESCE(NULLIF(k.alias,''), u.name) AS name FROM calls c JOIN users u ON u.id=c.caller LEFT JOIN contacts k ON k.owner=$1 AND k.contact=c.caller WHERE c.callee=$1 AND c.status='ringing' ORDER BY c.created_at DESC LIMIT 1`, [req.uid]);
  res.json({ request: r.rows[0] || null, notice: n.rows[0] || null, call: cl.rows[0] || null });
}));
app.post("/api/login-requests/:id/answer", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const r = await db.query("UPDATE login_requests SET status=$3 WHERE id=$1 AND user_id=$2 AND status='pending' AND expires_at > now() RETURNING id", [req.params.id, req.uid, req.body.approve === true ? "approved" : "denied"]);
  if (!r.rowCount) return bad(res, "This request has expired.", 410);
  res.json({ ok: true });
}));

// Linked devices: see every device logged in to the account and remove any of them.
app.get("/api/sessions", need, wrap(async (req, res) => {
  const r = await db.query("SELECT id, device, created_at, last_seen FROM sessions WHERE user_id=$1 ORDER BY last_seen DESC", [req.uid]);
  res.json({ sessions: r.rows.map((x) => ({ ...x, current: x.id === req.sid })) });
}));
app.post("/api/sessions/logout-others", need, wrap(async (req, res) => {
  if (!req.sid) return bad(res, "Please log out and log in again first.");
  await db.query("DELETE FROM sessions WHERE user_id=$1 AND id<>$2", [req.uid, req.sid]);
  res.json({ ok: true });
}));
app.delete("/api/sessions/:id", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  if (req.params.id === req.sid) return bad(res, "Use Log out for this device.");
  await db.query("DELETE FROM sessions WHERE id=$1 AND user_id=$2", [req.params.id, req.uid]);
  res.json({ ok: true });
}));

app.post("/api/logout", need, wrap(async (req, res) => {
  if (req.sid) await db.query("DELETE FROM sessions WHERE id=$1", [req.sid]);
  res.json({ ok: true });
}));

// Forgot password: number + recovery code + new password. A new code is issued after use.
app.post("/api/recover", authLimit, wrap(async (req, res) => {
  const password = String(req.body.password || "");
  if (password.length < 8) return bad(res, "Password must be at least 8 characters.");
  const u = (await db.query("SELECT * FROM users WHERE phone=$1", [phoneOf(req.body.phone)])).rows[0];
  if (!u || !u.recovery_hash || u.recovery_hash !== hashCode(req.body.code))
    return bad(res, "Wrong number or recovery code.", 401);
  const lmR = await lockMsg(u);
  if (lmR) return res.status(403).json({ error: lmR, appeal: true });
  const code = makeCode();
  await db.query("UPDATE users SET pass_hash=$2, recovery_hash=$3 WHERE id=$1", [u.id, await bcrypt.hash(password, 10), hashCode(code)]);
  await db.query("DELETE FROM sessions WHERE user_id=$1", [u.id]); // recovery signs out every other device
  await db.query("UPDATE login_requests SET status='denied' WHERE user_id=$1 AND status='pending'", [u.id]);
  res.json({ ...(await newSession(u, req)), recovery_code: code });
}));

// New recovery code for a logged-in user (needs the password). The old code stops working.
app.post("/api/me/recovery-code", need, authLimit, wrap(async (req, res) => {
  const u = (await db.query("SELECT * FROM users WHERE id=$1", [req.uid])).rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.pass_hash))) return bad(res, "Wrong password.", 403);
  const code = makeCode();
  await db.query("UPDATE users SET recovery_hash=$2 WHERE id=$1", [u.id, hashCode(code)]);
  res.json({ recovery_code: code });
}));

// Delete account for good. All related rows go too (ON DELETE CASCADE), and the number is free to register again.
app.post("/api/me/delete", need, authLimit, wrap(async (req, res) => {
  const u = (await db.query("SELECT * FROM users WHERE id=$1", [req.uid])).rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.pass_hash))) return bad(res, "Wrong password.", 403);
  const until = [u.restricted_until, u.rest_until].filter(Boolean).map((d) => new Date(d)).filter((d) => d > new Date()).sort((a, b) => b - a)[0];
  if (until && !u.banned) await db.query("INSERT INTO blocked_phones(phone,until,reason) VALUES($1,$2,'Account deleted during a restriction') ON CONFLICT (phone) DO UPDATE SET until = CASE WHEN blocked_phones.until IS NULL THEN NULL ELSE GREATEST(blocked_phones.until, EXCLUDED.until) END", [u.phone, until]);
  for (const g of (await db.query("SELECT group_id FROM group_members WHERE user_id=$1", [u.id])).rows) await leaveGroup(g.group_id, u.id, true);
  await db.query("DELETE FROM users WHERE id=$1", [u.id]);
  for (const k of typing.keys()) if (k.includes(u.id)) typing.delete(k);
  res.json({ ok: true });
}));

app.get("/api/me", need, wrap(async (req, res) => {
  const r = await db.query("SELECT * FROM users WHERE id=$1", [req.uid]);
  if (!r.rows[0]) return bad(res, "Please log in again.", 401);
  res.json(pub(r.rows[0]));
}));

app.put("/api/me", need, wrap(async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 60);
  const about = String(req.body.about || "").trim().slice(0, 140);
  if (!name) return bad(res, "Name cannot be empty.");
  const sp = ["everyone", "contacts", "nobody"].includes(req.body.seen_privacy) ? req.body.seen_privacy : null;
  const pp = ["everyone", "contacts", "nobody"].includes(req.body.photo_privacy) ? req.body.photo_privacy : null;
  const cv = Number.isInteger(req.body.cover) && req.body.cover >= 0 && req.body.cover < 8 ? req.body.cover : null;
  const md = typeof req.body.mood === "string" ? [...req.body.mood].slice(0, 2).join("") : null;
  const r = await db.query("UPDATE users SET name=$2, about=$3, seen_privacy=COALESCE($4, seen_privacy), photo_privacy=COALESCE($5, photo_privacy), cover=COALESCE($6, cover), mood=COALESCE($7, mood) WHERE id=$1 RETURNING *", [req.uid, name, about, sp, pp, cv, md]);
  res.json({ user: pub(r.rows[0]) });
}));

// ---- Profile photo (small JPEG, resized by the app) ----
app.put("/api/me/photo", need, wrap(async (req, res) => {
  const p = String(req.body.photo || "");
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+\/]+={0,2})$/.exec(p);
  if (!m || p.length > 90000) return bad(res, "Please choose a smaller picture.");
  const b = Buffer.from(m[1], "base64");
  if (b.length < 100 || b[0] !== 0xff || b[1] !== 0xd8) return bad(res, "That is not a JPEG picture.");
  await db.query("UPDATE users SET photo=$2 WHERE id=$1", [req.uid, p]);
  res.json({ ok: true });
}));
app.delete("/api/me/photo", need, wrap(async (req, res) => {
  await db.query("UPDATE users SET photo=NULL WHERE id=$1", [req.uid]);
  res.json({ ok: true });
}));
// Returns only the photos this person is allowed to see (own photo, or "everyone", or "contacts" if they are in that person's contacts; never across a block).
app.post("/api/photos", need, wrap(async (req, res) => {
  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).filter(isId).slice(0, 60);
  if (!ids.length) return res.json({ photos: {} });
  const r = await db.query(
    `SELECT u.id, u.photo FROM users u WHERE u.id = ANY($2::uuid[]) AND u.photo IS NOT NULL AND (
       u.id=$1 OR (
         NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=u.id AND b.blocked=$1) OR (b.blocker=$1 AND b.blocked=u.id))
         AND (u.photo_privacy='everyone' OR (u.photo_privacy='contacts' AND EXISTS (SELECT 1 FROM contacts c WHERE c.owner=u.id AND c.contact=$1)))))`,
    [req.uid, ids]);
  const photos = {}; for (const x of r.rows) photos[x.id] = x.photo;
  res.json({ photos });
}));

// ---- Contacts ----
app.get("/api/contacts", need, wrap(async (req, res) => {
  const r = await db.query(
    `SELECT u.id, u.phone, COALESCE(NULLIF(c.alias,''), u.name) AS name
     FROM contacts c JOIN users u ON u.id = c.contact
     WHERE c.owner = $1 ORDER BY name`, [req.uid]);
  res.json({ contacts: r.rows });
}));

app.post("/api/contacts", need, wrap(async (req, res) => {
  const u = (await db.query("SELECT id FROM users WHERE phone=$1", [phoneOf(req.body.phone)])).rows[0];
  if (!u) return bad(res, "This number is not on Orivoclass yet.", 404);
  if (u.id === req.uid) return bad(res, "That is your own number.");
  const alias = String(req.body.alias || "").trim().slice(0, 60);
  await db.query(
    `INSERT INTO contacts(owner,contact,alias) VALUES($1,$2,$3)
     ON CONFLICT (owner,contact) DO UPDATE SET alias = EXCLUDED.alias`, [req.uid, u.id, alias]);
  res.json({ ok: true });
}));

app.delete("/api/contacts/:id", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  await db.query("DELETE FROM contacts WHERE owner=$1 AND contact=$2", [req.uid, req.params.id]);
  res.json({ ok: true });
}));

// ---- Disappearing messages: one timer per conversation, shared by both people ----
const pair = (x, y) => { x = String(x).toLowerCase(); y = String(y).toLowerCase(); return x < y ? [x, y] : [y, x]; };
const chatTtl = async (a, b) => {
  const [p, q] = pair(a, b);
  const r = (await db.query("SELECT ttl FROM chat_settings WHERE user_a=$1 AND user_b=$2", [p, q])).rows[0];
  return r ? r.ttl : 0;
};
setInterval(() => db.query("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < now()").catch(() => {}), 60000);
app.post("/api/chats/:peer/disappear", need, wrap(async (req, res) => {
  if (!isId(req.params.peer) || req.params.peer.toLowerCase() === req.uid) return bad(res, "Invalid id.");
  const sec = Number(req.body.seconds);
  if (![0, 86400, 604800].includes(sec)) return bad(res, "Choose Off, 24 hours or 7 days.");
  if (!(await db.query("SELECT 1 FROM users WHERE id=$1", [req.params.peer])).rowCount) return bad(res, "Not found.", 404);
  if ((await db.query("SELECT 1 FROM blocks WHERE (blocker=$1 AND blocked=$2) OR (blocker=$2 AND blocked=$1)", [req.uid, req.params.peer])).rowCount) return bad(res, "You cannot change this chat right now.", 403);
  const [p, q] = pair(req.uid, req.params.peer);
  await db.query("INSERT INTO chat_settings(user_a,user_b,ttl,set_by,updated_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT (user_a,user_b) DO UPDATE SET ttl=EXCLUDED.ttl, set_by=EXCLUDED.set_by, updated_at=now()", [p, q, sec, req.uid]);
  res.json({ ok: true, ttl: sec });
}));
// END OF PART 2
 // ---- Chats and messages ----
app.get("/api/chats", need, wrap(async (req, res) => {
  const r = await db.query(
    `WITH m AS (
       SELECT DISTINCT ON (peer) peer, id, body, from_id, created_at FROM (
         SELECT CASE WHEN from_id=$1 THEN to_id ELSE from_id END AS peer, id, CASE WHEN view_once THEN 'View once message' ELSE body END AS body, from_id, created_at
         FROM messages WHERE ((from_id=$1 AND NOT del_from) OR (to_id=$1 AND NOT del_to)) AND (expires_at IS NULL OR expires_at > now())
       ) x ORDER BY peer, id DESC)
     SELECT m.*, (SELECT count(*)::int FROM messages x WHERE x.from_id=m.peer AND x.to_id=$1 AND x.read_at IS NULL AND NOT x.del_to AND (x.expires_at IS NULL OR x.expires_at > now())) AS unread, u.phone, u.last_seen, u.seen_privacy, COALESCE(NULLIF(c.alias,''), CASE WHEN c.contact IS NOT NULL THEN u.name ELSE u.phone END) AS display, (c.contact IS NOT NULL) AS saved, u.name AS pname,
            EXISTS (SELECT 1 FROM contacts k WHERE k.owner=m.peer AND k.contact=$1) AS theirs,
            COALESCE(p.pinned, false) AS pinned, COALESCE(p.archived, false) AS archived,
            EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=m.peer) OR (b.blocker=m.peer AND b.blocked=$1)) AS blk,
            (SELECT count(*)::int FROM messages x WHERE x.to_id=$1 AND x.from_id=m.peer AND x.read_at IS NULL AND NOT x.del_to AND (x.expires_at IS NULL OR x.expires_at > now())) AS unread
     FROM m JOIN users u ON u.id = m.peer
     LEFT JOIN contacts c ON c.owner=$1 AND c.contact=m.peer
     LEFT JOIN chat_prefs p ON p.owner=$1 AND p.peer=m.peer
     ORDER BY m.id DESC`, [req.uid]);
  res.json({
    chats: r.rows.map((x) => ({ ...x, ...presence(x, x.theirs, x.blk), typing: !x.blk && isTyping(x.peer, req.uid), seen_privacy: undefined, theirs: undefined, blk: undefined })),
  });
}));

app.get("/api/messages/:peer", need, wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  await db.query("UPDATE messages SET read_at=now() WHERE to_id=$1 AND from_id=$2 AND read_at IS NULL AND NOT del_to", [req.uid, req.params.peer]);
  const r = await db.query(
    `SELECT * FROM (
       SELECT id, from_id, to_id, CASE WHEN view_once THEN NULL ELSE body END AS body, view_once, opened_at, forwarded, reply, reaction, read_at, created_at, expires_at FROM messages
       WHERE ((from_id=$1 AND to_id=$2 AND NOT del_from) OR (from_id=$2 AND to_id=$1 AND NOT del_to)) AND (expires_at IS NULL OR expires_at > now())
       ORDER BY id DESC LIMIT 200) t ORDER BY id`, [req.uid, req.params.peer]);
  res.json({ messages: r.rows, ttl: await chatTtl(req.uid, req.params.peer) });
}));

app.post("/api/messages", need, wrap(async (req, res) => {
  const body = String(req.body.body || "").trim().slice(0, 4000);
  const reply = req.body.reply ? String(req.body.reply).slice(0, 120) : null;
  if (!body) return bad(res, "Message is empty.");
  if (!isId(req.body.to) || req.body.to === req.uid) return bad(res, "Invalid recipient.");
  if (req.body.once && !req.body.fwd) {
    const ru = (await db.query("SELECT restricted_until FROM users WHERE id=$1", [req.uid])).rows[0];
    if (ru && ru.restricted_until && new Date(ru.restricted_until) > new Date()) return bad(res, "Your account is restricted, so you cannot send View Once messages for now.", 403);
  }
  const ok = await db.query("SELECT 1 FROM users WHERE id=$1", [req.body.to]);
  if (!ok.rowCount) return bad(res, "Recipient not found.", 404);
  const bl = (await db.query("SELECT blocker FROM blocks WHERE (blocker=$1 AND blocked=$2) OR (blocker=$2 AND blocked=$1)", [req.uid, req.body.to])).rows;
  if (bl.some((x) => x.blocker === req.uid)) return bad(res, "Unblock this person to send messages.", 403);
  const ttl = await chatTtl(req.uid, req.body.to);
  const hideFromThem = bl.length > 0; // if they blocked you, the message is saved for you but never delivered
  const r = await db.query(
    "INSERT INTO messages(from_id,to_id,body,reply,view_once,forwarded,del_to,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
    [req.uid, req.body.to, body, reply, !!req.body.once && !req.body.fwd, !!req.body.fwd, hideFromThem, ttl ? new Date(Date.now() + ttl * 1000) : null]);
  await db.query("UPDATE chat_prefs SET archived=false WHERE (owner=$1 AND peer=$2) OR (owner=$2 AND peer=$1)", [req.uid, req.body.to]);
  if (webpush && !hideFromThem) // never include the message text
    db.query("SELECT COALESCE(NULLIF(c.alias,''), CASE WHEN c.contact IS NOT NULL THEN u.name ELSE u.phone END) AS n FROM users u LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE u.id=$1", [req.uid, req.body.to])
      .then((q) => notify(req.body.to, "msg", { title: (q.rows[0] && q.rows[0].n) || "Orivoclass", body: "New message", tag: "m" + req.uid })).catch(() => {});
  res.json({ id: r.rows[0].id });
}));

app.post("/api/typing/:peer", need, (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  typing.set(req.uid + ">" + req.params.peer, Date.now());
  res.json({ ok: true });
});

app.get("/api/presence/:peer", need, wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  const r = await db.query(
    `SELECT u.last_seen, u.seen_privacy,
            EXISTS (SELECT 1 FROM contacts k WHERE k.owner=u.id AND k.contact=$2) AS theirs,
            EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$2 AND b.blocked=u.id) OR (b.blocker=u.id AND b.blocked=$2)) AS blk
     FROM users u WHERE u.id=$1`, [req.params.peer, req.uid]);
  if (!r.rows[0]) return bad(res, "Not found.", 404);
  res.json({ ...presence(r.rows[0], r.rows[0].theirs, r.rows[0].blk), typing: !r.rows[0].blk && isTyping(req.params.peer, req.uid) });
}));

// View once: the text is returned a single time, then erased from the database.
app.post("/api/messages/:id/open", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  const r = await db.query(
    `WITH old AS (SELECT body FROM messages WHERE id=$1 AND to_id=$2 AND view_once AND opened_at IS NULL),
          upd AS (UPDATE messages SET opened_at=now(), body='' WHERE id=$1 AND to_id=$2 AND view_once AND opened_at IS NULL RETURNING id)
     SELECT old.body FROM old`, [req.params.id, req.uid]);
  if (!r.rows[0]) return bad(res, "This message was already opened.", 410);
  res.json({ body: r.rows[0].body });
}));

app.post("/api/messages/:id/react", need, wrap(async (req, res) => {
  const emoji = req.body.emoji ? String(req.body.emoji).slice(0, 8) : null;
  await db.query(
    "UPDATE messages SET reaction=$3 WHERE id=$1 AND (from_id=$2 OR to_id=$2)",
    [req.params.id, req.uid, emoji]);
  res.json({ ok: true });
}));

// ---- Block and report ----
app.get("/api/blocks", need, wrap(async (req, res) => {
  const r = await db.query("SELECT u.id, u.name, u.phone FROM blocks b JOIN users u ON u.id=b.blocked WHERE b.blocker=$1 ORDER BY u.name", [req.uid]);
  res.json({ blocks: r.rows });
}));
app.post("/api/blocks/:id", need, wrap(async (req, res) => {
  if (!isId(req.params.id) || req.params.id === req.uid) return bad(res, "Invalid id.");
  await db.query("INSERT INTO blocks(blocker,blocked) SELECT $1, id FROM users WHERE id=$2 ON CONFLICT DO NOTHING", [req.uid, req.params.id]);
  res.json({ ok: true });
}));
app.delete("/api/blocks/:id", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  await db.query("DELETE FROM blocks WHERE blocker=$1 AND blocked=$2", [req.uid, req.params.id]);
  res.json({ ok: true });
}));
const REASONS = ["Spam", "Harassment or insults", "Unsolicited nudes", "Scam or fake links", "Other"];
const reportLimit = rateLimit({ windowMs: 60 * 60000, max: 20 });
app.post("/api/reports", need, reportLimit, wrap(async (req, res) => {
  const uid2 = req.body.user_id;
  if (!isId(uid2) || uid2 === req.uid) return bad(res, "Invalid report.");
  const reason = REASONS.includes(req.body.reason) ? req.body.reason : "Other";
  const note = (req.body.singles === true ? "[Singles] " : "") + String(req.body.note || "").trim().slice(0, 500);
  // Evidence: the last messages this person sent to the reporter. View once messages are never included.
  const m = await db.query(
    req.body.singles === true ? "SELECT id, body, created_at FROM singles_messages WHERE from_id=$1 AND to_id=$2 ORDER BY id DESC LIMIT 5" : "SELECT id, body, created_at FROM messages WHERE from_id=$1 AND to_id=$2 AND NOT view_once AND NOT del_to AND (expires_at IS NULL OR expires_at > now()) ORDER BY id DESC LIMIT 5",
    [uid2, req.uid]);
  await db.query("INSERT INTO reports(reporter,reported,reason,note,evidence) VALUES($1,$2,$3,$4,$5)", [req.uid, uid2, reason, note, JSON.stringify(m.rows)]);
  res.json({ ok: true });
}));

const setPref = (col) => wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  await db.query(
    `INSERT INTO chat_prefs(owner,peer,${col}) VALUES($1,$2,$3)
     ON CONFLICT (owner,peer) DO UPDATE SET ${col} = EXCLUDED.${col}`,
    [req.uid, req.params.peer, !!req.body.value]);
  res.json({ ok: true });
});
app.post("/api/chats/:peer/pin", need, setPref("pinned"));
app.post("/api/chats/:peer/archive", need, setPref("archived"));

app.delete("/api/chats/:peer", need, wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  await db.query("UPDATE messages SET del_from=true WHERE from_id=$1 AND to_id=$2", [req.uid, req.params.peer]);
  await db.query("UPDATE messages SET del_to=true WHERE to_id=$1 AND from_id=$2", [req.uid, req.params.peer]);
  res.json({ ok: true });
}));

// ---- Status (text updates, 24 hours) ----
app.get("/api/status", need, wrap(async (req, res) => {
  const r = await db.query(
    `SELECT s.id, s.user_id, s.body, s.color, s.created_at, COALESCE(NULLIF(k.alias,''), u.name) AS name, (s.image IS NOT NULL) AS has_image,
            (SELECT count(*)::int FROM status_views v WHERE v.status_id=s.id AND s.user_id=$1) AS views
     FROM statuses s JOIN users u ON u.id = s.user_id LEFT JOIN contacts k ON k.owner=$1 AND k.contact=s.user_id
     WHERE s.created_at > now() - interval '24 hours'
       AND (s.user_id=$1 OR EXISTS (SELECT 1 FROM contacts c WHERE c.owner=$1 AND c.contact=s.user_id))
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=s.user_id AND b.blocked=$1) OR (b.blocker=$1 AND b.blocked=s.user_id))
     ORDER BY s.created_at DESC`, [req.uid]);
  res.json({ status: r.rows });
}));

app.post("/api/status", need, wrap(async (req, res) => {
  const body = String(req.body.body || "").trim().slice(0, 200);
  const color = /^#[0-9a-f]{6}$/i.test(req.body.color || "") ? req.body.color : "#5A3FD6";
  let image = null;
  if (req.body.image) {
    const p = String(req.body.image), m = /^data:image\/jpeg;base64,([A-Za-z0-9+\/]+={0,2})$/.exec(p);
    if (!m || p.length > 160000) return bad(res, "Please choose a smaller picture.");
    const buf = Buffer.from(m[1], "base64");
    if (buf.length < 100 || buf[0] !== 0xff || buf[1] !== 0xd8) return bad(res, "That is not a JPEG picture.");
    image = p;
  }
  if (!body && !image) return bad(res, "Write something or add a photo first.");
  await db.query("INSERT INTO statuses(user_id,body,color,image) VALUES($1,$2,$3,$4)", [req.uid, body, color, image]);
  if (webpush) { // tell the people who can see it (fire and forget)
    const me = (await db.query("SELECT name FROM users WHERE id=$1", [req.uid])).rows[0];
    const to = await db.query("SELECT owner AS contact FROM contacts WHERE contact=$1 AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=contacts.owner) OR (b.blocker=contacts.owner AND b.blocked=$1))", [req.uid]);
    to.rows.forEach((r) => notify(r.contact, "status", { title: me.name, body: "posted a status", tag: "s" + req.uid }));
  }
  res.json({ ok: true });
}));

app.delete("/api/status/:id", need, wrap(async (req, res) => {
  await db.query("DELETE FROM statuses WHERE id=$1 AND user_id=$2", [req.params.id, req.uid]);
  res.json({ ok: true });
}));
// END OF PART 3
   
// END OF PART 3
// ---- Moderation: warnings, restrictions, resting periods, bans and appeals ----
// Steps follow the Community Rules: warning -> 24h restriction -> resting period (3 or 7 days) -> permanent ban.
const PENALTY = { warning: 10, restriction: 20, rest3: 30, rest7: 40, ban: 100 }; // trust score points removed
async function isBlockedPhone(phone) {
  return (await db.query("SELECT 1 FROM blocked_phones WHERE phone=$1 AND (until IS NULL OR until > now())", [phone])).rowCount > 0;
}
async function lockMsg(u) {
  const rest = u.rest_until && new Date(u.rest_until) > new Date();
  if (!u.banned && !rest) return null;
  const s = (await db.query("SELECT reason FROM sanctions WHERE user_id=$1 AND kind IN ('rest','ban') ORDER BY id DESC LIMIT 1", [u.id])).rows[0];
  return (u.banned ? "This account has been permanently banned." : "Your account is resting until " + new Date(u.rest_until).toUTCString() + ".") + (s ? " Reason: " + s.reason : "");
}
async function recompute(uid) {
  await db.query(`UPDATE users SET
    restricted_until=(SELECT max(until) FROM sanctions WHERE user_id=$1 AND kind='restriction' AND appeal_status IS DISTINCT FROM 'accepted'),
    rest_until=(SELECT max(until) FROM sanctions WHERE user_id=$1 AND kind='rest' AND appeal_status IS DISTINCT FROM 'accepted'),
    banned=EXISTS(SELECT 1 FROM sanctions WHERE user_id=$1 AND kind='ban' AND appeal_status IS DISTINCT FROM 'accepted')
    WHERE id=$1`, [uid]);
}
async function applySanction(uid, act, reason, reportId) {
  const kind = act === "rest3" || act === "rest7" ? "rest" : act;
  const hours = act === "restriction" ? 24 : act === "rest3" ? 72 : act === "rest7" ? 168 : 0;
  const until = hours ? new Date(Date.now() + hours * 3600000) : null;
  const pen = PENALTY[act];
  await db.query("INSERT INTO sanctions(user_id,kind,reason,report_id,penalty,until) VALUES($1,$2,$3,$4,$5,$6)", [uid, kind, reason, reportId || null, pen, until]);
  await db.query("UPDATE users SET trust_score=GREATEST(0, trust_score-$2), trust_updated_at=now() WHERE id=$1", [uid, pen]);
  await recompute(uid);
  if (kind === "rest" || kind === "ban") { // sign them out everywhere
    await db.query("DELETE FROM sessions WHERE user_id=$1", [uid]);
    await db.query("UPDATE login_requests SET status='denied' WHERE user_id=$1 AND status='pending'", [uid]);
  }
  if (kind === "ban") // keep the number blocked even if the account is deleted
    await db.query("INSERT INTO blocked_phones(phone,until,reason) SELECT phone, NULL, $2 FROM users WHERE id=$1 ON CONFLICT (phone) DO UPDATE SET until=NULL, reason=EXCLUDED.reason", [uid, reason]);
}

// Trust score slowly recovers: +2 points for every full day without a new problem.
// The clock starts after the last sanction, and after a restriction or resting period has ended. Banned accounts do not recover.
async function healTrust() {
  await db.query(`UPDATE users u SET trust_score=LEAST(100, u.trust_score + 2*d.days), trust_updated_at=d.base + d.days * interval '1 day'
    FROM (SELECT id, base, FLOOR(EXTRACT(EPOCH FROM (now()-base))/86400)::int AS days FROM (
            SELECT id, GREATEST(trust_updated_at, COALESCE(rest_until, trust_updated_at), COALESCE(restricted_until, trust_updated_at)) AS base
            FROM users WHERE trust_score<100 AND NOT banned) x) d
    WHERE u.id=d.id AND d.days>=1`);
}
setInterval(() => healTrust().catch(() => {}), 10 * 60000);

// What the user sees: trust score, history, and appeals.
app.get("/api/account", need, wrap(async (req, res) => {
  const u = (await db.query("SELECT trust_score, restricted_until FROM users WHERE id=$1", [req.uid])).rows[0];
  const r = await db.query("SELECT id, kind, reason, created_at, until, appeal_status FROM sanctions WHERE user_id=$1 ORDER BY id DESC LIMIT 20", [req.uid]);
  res.json({ trust: u.trust_score, restricted_until: u.restricted_until, sanctions: r.rows });
}));
app.post("/api/notices/:id/seen", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  await db.query("UPDATE sanctions SET seen=true WHERE id=$1 AND user_id=$2", [req.params.id, req.uid]);
  res.json({ ok: true });
}));
app.post("/api/appeal", need, wrap(async (req, res) => {
  const text = String(req.body.text || "").trim().slice(0, 500);
  if (!/^\d+$/.test(String(req.body.sanction_id || ""))) return bad(res, "Invalid request.");
  if (!text) return bad(res, "Please write why you are appealing.");
  const r = await db.query("UPDATE sanctions SET appeal_status='pending', appeal_text=$3, appealed_at=now() WHERE id=$1 AND user_id=$2 AND kind<>'warning' AND appeal_status IS NULL RETURNING id", [req.body.sanction_id, req.uid, text]);
  if (!r.rowCount) return bad(res, "This cannot be appealed, or you already appealed.", 409);
  res.json({ ok: true });
}));
// Someone who is locked out (resting or banned) appeals with their number and password.
app.post("/api/appeal-login", authLimit, wrap(async (req, res) => {
  const u = (await db.query("SELECT * FROM users WHERE phone=$1", [phoneOf(req.body.phone)])).rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.pass_hash))) return bad(res, "Wrong number or password.", 401);
  const text = String(req.body.text || "").trim().slice(0, 500);
  if (!text) return bad(res, "Please write why you are appealing.");
  const r = await db.query("UPDATE sanctions SET appeal_status='pending', appeal_text=$2, appealed_at=now() WHERE id=(SELECT id FROM sanctions WHERE user_id=$1 AND kind IN ('rest','ban') AND appeal_status IS NULL AND (until IS NULL OR until > now()) ORDER BY id DESC LIMIT 1) RETURNING id", [u.id, text]);
  if (!r.rowCount) return bad(res, "There is nothing to appeal, or you already appealed.", 409);
  res.json({ ok: true });
}));

// Admin (you): protected by the ADMIN_KEY environment variable. Used by admin.html.
const adminLimit = rateLimit({ windowMs: 15 * 60000, max: 200 });
const adminOnly = (req, res, next) => {
  const k = Buffer.from(String(req.headers["x-admin-key"] || "")), a = Buffer.from(process.env.ADMIN_KEY || "");
  if (a.length < 16 || k.length !== a.length || !crypto.timingSafeEqual(k, a)) return res.status(401).json({ error: "Admin key required." });
  next();
};
// Admin check of the AI connection: shows what the AI answers to each request shape (never shows the key).
app.get("/api/admin/ai-test", adminLimit, adminOnly, wrap(async (req, res) => {
  const out = [];
  for (const fmt of AI_FORMATS) {
    const r = await aiCall(fmt, [{ role: "user", content: "Say hello in one short sentence." }]);
    let j; try { j = JSON.parse(r.raw); } catch (e) { j = r.raw; }
    out.push({ format: fmt, status: r.status, ok: r.ok, error: r.error || null, reply: pickReply(j).slice(0, 200), body: r.raw.slice(0, 400) });
  }
  res.json({ node: process.version, fetch: typeof fetch === "function", url: AI_URL, key_set: !!process.env.AI_KEY, system_prompt_sent: !!AI_SYSTEM, results: out });
}));
app.get("/api/admin/reports", adminLimit, adminOnly, wrap(async (req, res) => {
  const r = await db.query(`SELECT r.id, r.reason, r.note, r.evidence, r.created_at,
      rp.id AS reported_id, rp.name AS reported_name, rp.phone AS reported_phone, rp.trust_score, rp.banned,
      rr.name AS reporter_name, rr.phone AS reporter_phone,
      (SELECT count(*) FROM reports x WHERE x.reported=r.reported)::int AS total_reports,
      (SELECT count(*) FROM sanctions s WHERE s.user_id=r.reported)::int AS past_sanctions
    FROM reports r JOIN users rp ON rp.id=r.reported JOIN users rr ON rr.id=r.reporter
    WHERE r.status='open' ORDER BY r.created_at LIMIT 100`);
  res.json({ reports: r.rows });
}));
app.post("/api/admin/reports/:id", adminLimit, adminOnly, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  const act = String(req.body.action || "");
  if (!["dismiss", "warning", "restriction", "rest3", "rest7", "ban"].includes(act)) return bad(res, "Unknown action.");
  const rep = (await db.query("SELECT * FROM reports WHERE id=$1 AND status='open'", [req.params.id])).rows[0];
  if (!rep) return bad(res, "Report not found or already handled.", 404);
  if (act === "dismiss") await db.query("UPDATE reports SET status='dismissed' WHERE id=$1", [rep.id]);
  else {
    const reason = String(req.body.message || "").trim().slice(0, 300) || "Reported for: " + rep.reason;
    await applySanction(rep.reported, act, reason, rep.id);
    await db.query("UPDATE reports SET status='actioned' WHERE id=$1", [rep.id]);
  }
  res.json({ ok: true });
}));
app.get("/api/admin/singles/photos", adminLimit, adminOnly, wrap(async (req, res) => {
  const r = await db.query("SELECT user_id, nick, photo, date_part('year', age(birth_date))::int AS age FROM singles WHERE photo_review AND photo IS NOT NULL ORDER BY updated_at LIMIT 30");
  res.json({ photos: r.rows });
}));
app.post("/api/admin/singles/:uid", adminLimit, adminOnly, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  const act = String(req.body.action || "");
  if (act === "approve") await db.query("UPDATE singles SET photo_review=false WHERE user_id=$1", [req.params.uid]);
  else if (act === "remove") await db.query("UPDATE singles SET photo=NULL, photo_review=false WHERE user_id=$1", [req.params.uid]);
  else if (act === "hide") await db.query("UPDATE singles SET active=false, photo_review=false WHERE user_id=$1", [req.params.uid]);
  else return bad(res, "Unknown action.");
  res.json({ ok: true });
}));
app.get("/api/admin/appeals", adminLimit, adminOnly, wrap(async (req, res) => {
  const r = await db.query("SELECT s.id, s.kind, s.reason, s.appeal_text, s.appealed_at, s.until, u.name, u.phone, u.trust_score FROM sanctions s JOIN users u ON u.id=s.user_id WHERE s.appeal_status='pending' ORDER BY s.appealed_at LIMIT 100");
  res.json({ appeals: r.rows });
}));
app.post("/api/admin/appeals/:id", adminLimit, adminOnly, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  if (req.body.decision === "reject") {
    const r = await db.query("UPDATE sanctions SET appeal_status='rejected' WHERE id=$1 AND appeal_status='pending' RETURNING id", [req.params.id]);
    if (!r.rowCount) return bad(res, "Appeal not found.", 404);
    return res.json({ ok: true });
  }
  const s = (await db.query("UPDATE sanctions SET appeal_status='accepted' WHERE id=$1 AND appeal_status='pending' RETURNING *", [req.params.id])).rows[0];
  if (!s) return bad(res, "Appeal not found.", 404);
  await db.query("UPDATE users SET trust_score=LEAST(100, trust_score+$2), trust_updated_at=now() WHERE id=$1", [s.user_id, s.penalty]);
  await recompute(s.user_id);
  await db.query("DELETE FROM blocked_phones WHERE until IS NULL AND phone=(SELECT phone FROM users WHERE id=$1) AND NOT (SELECT banned FROM users WHERE id=$1)", [s.user_id]);
  res.json({ ok: true });
}));

// ---- Status views ----
app.get("/api/status/:id/image", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  const r = await db.query(
    `SELECT s.image FROM statuses s WHERE s.id=$2 AND s.image IS NOT NULL AND s.created_at > now() - interval '24 hours'
       AND (s.user_id=$1 OR (EXISTS (SELECT 1 FROM contacts c WHERE c.owner=$1 AND c.contact=s.user_id)
            AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=s.user_id AND b.blocked=$1) OR (b.blocker=$1 AND b.blocked=s.user_id))))`, [req.uid, req.params.id]);
  if (!r.rows[0]) return bad(res, "Not found.", 404);
  res.json({ image: r.rows[0].image });
}));
app.post("/api/status/:id/view", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  const s = (await db.query(
    `SELECT s.id, s.user_id FROM statuses s WHERE s.id=$2 AND s.user_id<>$1 AND s.created_at > now() - interval '24 hours'
       AND EXISTS (SELECT 1 FROM contacts c WHERE c.owner=$1 AND c.contact=s.user_id)
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=s.user_id AND b.blocked=$1) OR (b.blocker=$1 AND b.blocked=s.user_id))`, [req.uid, req.params.id])).rows[0];
  if (s) {
    const ins = await db.query("INSERT INTO status_views(status_id,viewer_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING status_id", [s.id, req.uid]);
    if (ins.rowCount && webpush) {
      const q = (await db.query("SELECT COALESCE(NULLIF(c.alias,''), CASE WHEN c.contact IS NOT NULL THEN u.name ELSE u.phone END) AS n FROM users u LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE u.id=$1", [req.uid, s.user_id])).rows[0];
      notify(s.user_id, "views", { title: (q && q.n) || "Orivoclass", body: "viewed your status", tag: "v" + s.id });
    }
  }
  res.json({ ok: true });
}));
app.get("/api/status/:id/views", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  if (!(await db.query("SELECT 1 FROM statuses WHERE id=$1 AND user_id=$2", [req.params.id, req.uid])).rowCount) return bad(res, "Not found.", 404);
  const r = await db.query("SELECT u.id, COALESCE(NULLIF(c.alias,''), CASE WHEN c.contact IS NOT NULL THEN u.name ELSE u.phone END) AS name, v.viewed_at FROM status_views v JOIN users u ON u.id=v.viewer_id LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE v.status_id=$1 ORDER BY v.viewed_at DESC", [req.params.id, req.uid]);
  res.json({ views: r.rows });
}));
setInterval(() => db.query("DELETE FROM statuses WHERE created_at < now() - interval '2 days'").catch(() => {}), 3600000); // views go with them

// ---- Notifications (web push) ----
async function notify(uid, kind, payload) {
  if (!webpush) return;
  try {
    const col = { msg: "n_msg", status: "n_status", views: "n_views", calls: "n_calls" }[kind];
    const u = (await db.query(`SELECT ${col} AS enabled FROM users WHERE id=$1`, [uid])).rows[0];
    if (!u || !u.enabled) return;
    const subs = (await db.query("SELECT endpoint, p256dh, auth FROM push_subs WHERE user_id=$1", [uid])).rows;
    await Promise.all(subs.map(async (x) => {
      try { await webpush.sendNotification({ endpoint: x.endpoint, keys: { p256dh: x.p256dh, auth: x.auth } }, JSON.stringify(payload), { TTL: 3600 }); }
      catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await db.query("DELETE FROM push_subs WHERE endpoint=$1", [x.endpoint]); }
    }));
  } catch (e) { console.error("push:", e.message); }
}
app.get("/api/push/key", need, (req, res) => webpush ? res.json({ key: VAPID_PUB }) : bad(res, "Notifications are not set up on the server yet.", 503));
app.post("/api/push/subscribe", need, wrap(async (req, res) => {
  const sub = req.body.subscription || {};
  const ep = String(sub.endpoint || ""), k = sub.keys || {};
  if (!webpush) return bad(res, "Notifications are not set up on the server yet.", 503);
  if (!req.sid || !/^https:\/\//.test(ep) || ep.length > 700 || !k.p256dh || !k.auth) return bad(res, "Invalid subscription.");
  await db.query("INSERT INTO push_subs(endpoint,user_id,session_id,p256dh,auth) VALUES($1,$2,$3,$4,$5) ON CONFLICT (endpoint) DO UPDATE SET user_id=EXCLUDED.user_id, session_id=EXCLUDED.session_id, p256dh=EXCLUDED.p256dh, auth=EXCLUDED.auth", [ep, req.uid, req.sid, String(k.p256dh).slice(0, 200), String(k.auth).slice(0, 100)]);
  res.json({ ok: true });
}));
app.post("/api/push/unsubscribe", need, wrap(async (req, res) => {
  await db.query("DELETE FROM push_subs WHERE endpoint=$1 AND user_id=$2", [String(req.body.endpoint || ""), req.uid]);
  res.json({ ok: true });
}));
app.get("/api/notifications", need, wrap(async (req, res) => {
  const u = (await db.query("SELECT n_msg, n_status, n_views, n_calls FROM users WHERE id=$1", [req.uid])).rows[0];
  const d = req.sid ? (await db.query("SELECT 1 FROM push_subs WHERE session_id=$1", [req.sid])).rowCount > 0 : false;
  res.json({ available: !!webpush, msg: u.n_msg, status: u.n_status, views: u.n_views, calls: u.n_calls, this_device: d });
}));
app.put("/api/notifications", need, wrap(async (req, res) => {
  await db.query("UPDATE users SET n_msg=$2, n_status=$3, n_views=$4, n_calls=$5 WHERE id=$1", [req.uid, req.body.msg === true, req.body.status === true, req.body.views === true, req.body.calls === true]);
  res.json({ ok: true });
}));

// ---- Backup: a file the user downloads (chats without View Once or expired messages, plus their status updates and who viewed them) ----
const backupLimit = rateLimit({ windowMs: 60 * 60000, max: 6 });
app.get("/api/backup", need, backupLimit, wrap(async (req, res) => {
  const me = (await db.query("SELECT name, phone FROM users WHERE id=$1", [req.uid])).rows[0];
  const m = await db.query(
    `SELECT from_id, to_id, body, reply, forwarded, reaction, created_at, expires_at FROM messages
     WHERE ((from_id=$1 AND NOT del_from) OR (to_id=$1 AND NOT del_to)) AND NOT view_once AND (expires_at IS NULL OR expires_at > now())
     ORDER BY id LIMIT 20000`, [req.uid]);
  const ids = [...new Set(m.rows.map((x) => (x.from_id === req.uid ? x.to_id : x.from_id)))];
  const p = ids.length ? await db.query("SELECT u.id, u.phone, COALESCE(NULLIF(c.alias,''), u.name) AS name FROM users u LEFT JOIN contacts c ON c.owner=$1 AND c.contact=u.id WHERE u.id = ANY($2::uuid[])", [req.uid, ids]) : { rows: [] };
  const info = {}; for (const x of p.rows) info[x.id] = x;
  const chats = {};
  for (const x of m.rows) {
    const pid = x.from_id === req.uid ? x.to_id : x.from_id;
    if (!chats[pid]) chats[pid] = { name: (info[pid] && info[pid].name) || "Unknown", phone: (info[pid] && info[pid].phone) || "", messages: [] };
    chats[pid].messages.push({ me: x.from_id === req.uid, body: x.body, at: x.created_at, reply: x.reply, fwd: x.forwarded, reaction: x.reaction, expires_at: x.expires_at });
  }
  const st = await db.query("SELECT id, body, created_at FROM statuses WHERE user_id=$1 AND created_at > now() - interval '24 hours' ORDER BY created_at", [req.uid]);
  const vs = st.rows.length ? await db.query("SELECT v.status_id, v.viewed_at, COALESCE(NULLIF(c.alias,''), u.name) AS name FROM status_views v JOIN users u ON u.id=v.viewer_id LEFT JOIN contacts c ON c.owner=$1 AND c.contact=u.id WHERE v.status_id = ANY($2::bigint[]) ORDER BY v.viewed_at", [req.uid, st.rows.map((x) => x.id)]) : { rows: [] };
  const gs = await db.query("SELECT g.id, g.name FROM group_members gm JOIN chat_groups g ON g.id=gm.group_id WHERE gm.user_id=$1", [req.uid]);
  const gm = gs.rows.length ? await db.query(
    `SELECT m.group_id, m.from_id, m.body, m.reply, m.created_at, COALESCE(NULLIF(c.alias,''), u.name) AS from_name
     FROM group_messages m JOIN group_members x ON x.group_id=m.group_id AND x.user_id=$1 JOIN users u ON u.id=m.from_id LEFT JOIN contacts c ON c.owner=$1 AND c.contact=m.from_id
     WHERE m.kind='text' AND m.created_at >= x.joined_at AND (m.expires_at IS NULL OR m.expires_at > now()) ORDER BY m.id LIMIT 20000`, [req.uid]) : { rows: [] };
  const groups = gs.rows.map((g) => ({ name: g.name, messages: gm.rows.filter((m) => m.group_id === g.id).map((m) => ({ me: m.from_id === req.uid, from: m.from_name, body: m.body, at: m.created_at, reply: m.reply })) }));
  res.json({
    exported_at: new Date(), me, chats: Object.values(chats), groups,
    statuses: st.rows.map((x) => ({ body: x.body, created_at: x.created_at, views: vs.rows.filter((v) => String(v.status_id) === String(x.id)).map((v) => ({ name: v.name, at: v.viewed_at })) })),
  });
}));
// END OF PART 4
// ---- Orivoclass AI: the app talks to the AI through this server, so the AI address and key stay private and each person is rate limited ----
// Env (all optional): AI_URL, AI_KEY (sent as "Authorization: Bearer"), AI_SYSTEM (instructions; set empty to send none), AI_FORMAT = messages | message | prompt.
const AI_URL = process.env.AI_URL || "https://superb-owl-342.convex.site/v1/chat";
const AI_SYSTEM = process.env.AI_SYSTEM !== undefined ? process.env.AI_SYSTEM : "You are Orivoclass AI, a friendly assistant inside the Orivoclass messaging app. Keep answers short and clear. Reply in the language the person writes in (Swahili, English or Sheng).";
const AI_FORMAT = process.env.AI_FORMAT || "messages";
const aiLimit = rateLimit({ windowMs: 10 * 60000, max: 20, keyGenerator: (req) => String(req.uid) });
function pickReply(j) {
  if (typeof j === "string") return j.trim();
  if (!j || typeof j !== "object") return "";
  const c = j.choices && j.choices[0], d = j.data && typeof j.data === "object" ? j.data : {};
  const cands = [j.reply, j.response, j.answer, j.text, j.output, j.content, j.message && (j.message.content || j.message), d.reply, d.response, d.text, d.content, d.message, c && c.message && c.message.content, c && c.text];
  for (const x of cands) if (typeof x === "string" && x.trim()) return x.trim();
  return "";
}
const AI_FORMATS = ["messages", "message", "prompt"];
let aiGood = null; // the request format that worked last, tried first next time
const aiBody = (fmt, msgs) => {
  const last = msgs[msgs.length - 1].content;
  return fmt === "message" ? { message: last, history: msgs.slice(0, -1) }
    : fmt === "prompt" ? { prompt: last }
    : { messages: (AI_SYSTEM ? [{ role: "system", content: AI_SYSTEM }] : []).concat(msgs) };
};
async function aiCall(fmt, msgs) {
  const ac = new AbortController(), timer = setTimeout(() => ac.abort(), 30000);
  try {
    const r = await fetch(AI_URL, { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, process.env.AI_KEY ? { Authorization: "Bearer " + process.env.AI_KEY } : {}), body: JSON.stringify(aiBody(fmt, msgs)), signal: ac.signal });
    return { ok: r.ok, status: r.status, raw: await r.text() };
  } catch (e) { return { ok: false, status: 0, raw: "", error: e.name === "AbortError" ? "timeout" : e.message }; }
  finally { clearTimeout(timer); }
}
app.post("/api/ai", need, aiLimit, wrap(async (req, res) => {
  if (typeof fetch !== "function") return bad(res, "The server needs Node 18 or newer for the AI.", 500);
  const msgs = (Array.isArray(req.body.messages) ? req.body.messages : [])
    .filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string" && m.content.trim())
    .slice(-12).map((m) => ({ role: m.role, content: m.content.slice(0, 2000) }));
  if (!msgs.length || msgs[msgs.length - 1].role !== "user") return bad(res, "Type a message first.");
  const first = aiGood || AI_FORMAT, order = [first].concat(AI_FORMATS.filter((f) => f !== first));
  let last = null;
  for (const fmt of order) { // if the AI rejects one request shape (400/415/422), try the next shape
    const r = await aiCall(fmt, msgs); last = r;
    if (r.ok) {
      let j; try { j = JSON.parse(r.raw); } catch (e) { j = r.raw; }
      const reply = pickReply(j).slice(0, 4000);
      if (reply) {
        aiGood = fmt;
        const kp = (await db.query("SELECT ai_keep FROM users WHERE id=$1", [req.uid])).rows[0];
        if (kp && kp.ai_keep !== 0) await db.query("INSERT INTO ai_messages(user_id,role,content) VALUES($1,'user',$2),($1,'assistant',$3)", [req.uid, msgs[msgs.length - 1].content, reply]);
        return res.json({ reply });
      }
      console.error("AI reply format not recognised:", r.raw.slice(0, 300));
      return bad(res, "The AI answered in a way the app does not understand yet.", 502);
    }
    console.error("AI upstream error", fmt, r.status, r.error || r.raw.slice(0, 300));
    if (![400, 415, 422].includes(r.status)) break;
  }
  if (last.status === 401 || last.status === 403) return bad(res, "The AI needs a key. Ask the app owner to set AI_KEY.", 502);
  const why = last.status ? "error " + last.status : last.error === "timeout" ? "it took too long" : "no connection";
  return bad(res, "The AI is not available right now (" + why + ").", 502);
}));

// Saved AI chats: off by default. The person chooses how long to keep them (or deletes them whenever they want).
setInterval(() => db.query("DELETE FROM ai_messages m USING users u WHERE m.user_id=u.id AND u.ai_keep > 0 AND m.created_at < now() - make_interval(secs => u.ai_keep::double precision)").catch(() => {}), 3600000);
app.get("/api/ai/history", need, wrap(async (req, res) => {
  const u = (await db.query("SELECT ai_keep FROM users WHERE id=$1", [req.uid])).rows[0];
  const keep = u ? u.ai_keep : 0;
  if (keep === 0) return res.json({ keep, messages: [] });
  const r = await db.query("SELECT * FROM (SELECT id, role, content, created_at FROM ai_messages WHERE user_id=$1 AND ($2::int < 0 OR created_at > now() - make_interval(secs => $2::double precision)) ORDER BY id DESC LIMIT 60) t ORDER BY id", [req.uid, keep]);
  res.json({ keep, messages: r.rows });
}));
app.put("/api/ai/settings", need, wrap(async (req, res) => {
  const k = Number(req.body.keep);
  if (![0, 86400, 604800, 2592000, -1].includes(k)) return bad(res, "Choose how long to keep your AI chats.");
  await db.query("UPDATE users SET ai_keep=$2 WHERE id=$1", [req.uid, k]);
  if (k === 0) await db.query("DELETE FROM ai_messages WHERE user_id=$1", [req.uid]);
  else if (k > 0) await db.query("DELETE FROM ai_messages WHERE user_id=$1 AND created_at < now() - make_interval(secs => $2::double precision)", [req.uid, k]);
  res.json({ ok: true, keep: k });
}));
app.delete("/api/ai/history", need, wrap(async (req, res) => {
  await db.query("DELETE FROM ai_messages WHERE user_id=$1", [req.uid]);
  res.json({ ok: true });
}));

// ---- Calls (voice and video, WebRTC). The server only passes the set-up messages; the call itself goes phone to phone, or through a TURN relay. ----
// Optional env: TURN_URLS (comma list, e.g. turn:turn.example.com:3478,turns:turn.example.com:5349) with either TURN_SECRET (coturn "REST" auth) or TURN_USERNAME + TURN_CREDENTIAL.
const callPoll = rateLimit({ windowMs: 60000, max: 200 });
const callStart = rateLimit({ windowMs: 60 * 60000, max: 30 });
async function expireCalls() {
  await db.query("UPDATE calls SET status='missed', ended_at=now() WHERE status='ringing' AND created_at < now() - interval '45 seconds'");
  await db.query("UPDATE calls SET status='ended', ended_at=now() WHERE status='active' AND answered_at < now() - interval '6 hours'");
}
setInterval(() => {
  expireCalls().catch(() => {});
  db.query("DELETE FROM call_signals WHERE created_at < now() - interval '2 hours'").catch(() => {});
  db.query("DELETE FROM calls WHERE created_at < now() - interval '90 days'").catch(() => {});
}, 15000);

app.get("/api/calls/ice", need, (req, res) => {
  const servers = [{ urls: (process.env.STUN_URLS || "stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302").split(",").map((x) => x.trim()).filter(Boolean) }];
  const urls = (process.env.TURN_URLS || "").split(",").map((x) => x.trim()).filter(Boolean);
  if (urls.length) {
    if (process.env.TURN_SECRET) {
      const user = (Math.floor(Date.now() / 1000) + 3600) + ":" + req.uid;
      servers.push({ urls, username: user, credential: crypto.createHmac("sha1", process.env.TURN_SECRET).update(user).digest("base64") });
    } else if (process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) servers.push({ urls, username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL });
  }
  res.json({ iceServers: servers, relay: servers.length > 1 });
});

app.post("/api/calls", need, callStart, wrap(async (req, res) => {
  if (!isId(req.body.to) || req.body.to.toLowerCase() === req.uid) return bad(res, "Invalid id.");
  const to = req.body.to.toLowerCase(), kind = req.body.kind === "video" ? "video" : "voice";
  if (!(await db.query("SELECT 1 FROM users WHERE id=$1 AND NOT banned", [to])).rowCount) return bad(res, "Not found.", 404);
  if (await sgBlocked(req.uid, to)) return bad(res, "This person cannot be called right now.", 403);
  if (!(await db.query("SELECT 1 FROM contacts WHERE owner=$1 AND contact=$2", [to, req.uid])).rowCount) return bad(res, "You can only call people who have saved your number.", 403);
  await expireCalls();
  if ((await db.query("SELECT 1 FROM calls WHERE (caller=$1 OR callee=$1) AND status IN ('ringing','active')", [req.uid])).rowCount) return bad(res, "You are already in a call.", 409);
  if ((await db.query("SELECT 1 FROM calls WHERE (caller=$1 OR callee=$1) AND status IN ('ringing','active')", [to])).rowCount) {
    const b = await db.query("INSERT INTO calls(caller,callee,kind,status,ended_at) VALUES($1,$2,$3,'busy',now()) RETURNING id", [req.uid, to, kind]);
    return res.json({ id: b.rows[0].id, busy: true });
  }
  const c = await db.query("INSERT INTO calls(caller,callee,kind) VALUES($1,$2,$3) RETURNING id", [req.uid, to, kind]);
  if (webpush) {
    const q = (await db.query("SELECT COALESCE(NULLIF(k.alias,''), u.name) AS n FROM users u LEFT JOIN contacts k ON k.owner=$2 AND k.contact=u.id WHERE u.id=$1", [req.uid, to])).rows[0];
    notify(to, "calls", { title: (q && q.n) || "Orivoclass", body: "Incoming " + kind + " call", tag: "call" + c.rows[0].id });
  }
  res.json({ id: c.rows[0].id });
}));

app.post("/api/calls/:id/answer", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const st = req.body.accept === true ? "active" : "declined";
  const r = await db.query("UPDATE calls SET status=$3::text, answered_at=CASE WHEN $3::text='active' THEN now() ELSE NULL END, ended_at=CASE WHEN $3::text='active' THEN NULL ELSE now() END WHERE id=$1 AND callee=$2 AND status='ringing' AND created_at > now() - interval '60 seconds' RETURNING id", [req.params.id, req.uid, st]);
  if (!r.rowCount) return bad(res, "This call has ended.", 410);
  res.json({ ok: true });
}));

app.post("/api/calls/:id/signal", need, callPoll, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const kind = String(req.body.kind || ""), payload = String(req.body.payload || "");
  if (!["offer", "answer", "ice"].includes(kind) || !payload || payload.length > 20000) return bad(res, "Invalid signal.");
  const c = (await db.query("SELECT caller, callee FROM calls WHERE id=$1 AND (caller=$2 OR callee=$2) AND status IN ('ringing','active')", [req.params.id, req.uid])).rows[0];
  if (!c) return bad(res, "This call has ended.", 410);
  await db.query("INSERT INTO call_signals(call_id,to_id,kind,payload) VALUES($1,$2,$3,$4)", [req.params.id, c.caller === req.uid ? c.callee : c.caller, kind, payload]);
  res.json({ ok: true });
}));

app.get("/api/calls/:id/signals", need, callPoll, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  await expireCalls();
  const c = (await db.query("SELECT status FROM calls WHERE id=$1 AND (caller=$2 OR callee=$2)", [req.params.id, req.uid])).rows[0];
  if (!c) return bad(res, "Not found.", 404);
  const s = await db.query("SELECT id, kind, payload FROM call_signals WHERE call_id=$1 AND to_id=$2 AND id > $3 ORDER BY id LIMIT 100", [req.params.id, req.uid, parseInt(req.query.since, 10) || 0]);
  res.json({ status: c.status, signals: s.rows.map((x) => ({ id: Number(x.id), kind: x.kind, payload: x.payload })) });
}));

app.post("/api/calls/:id/end", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const c = (await db.query("UPDATE calls SET status=CASE WHEN status='ringing' THEN 'missed' ELSE 'ended' END, ended_at=now() WHERE id=$1 AND (caller=$2 OR callee=$2) AND status IN ('ringing','active') RETURNING *", [req.params.id, req.uid])).rows[0];
  if (c && c.status === "missed" && c.caller === req.uid && webpush) {
    const q = (await db.query("SELECT COALESCE(NULLIF(k.alias,''), u.name) AS n FROM users u LEFT JOIN contacts k ON k.owner=$2 AND k.contact=u.id WHERE u.id=$1", [req.uid, c.callee])).rows[0];
    notify(c.callee, "calls", { title: (q && q.n) || "Orivoclass", body: "Missed " + c.kind + " call", tag: "call" + c.id });
  }
  res.json({ ok: true });
}));

app.get("/api/calls", need, wrap(async (req, res) => {
  await expireCalls();
  const r = await db.query(
    `SELECT c.id, c.kind, c.status, c.created_at, c.answered_at, c.ended_at, (c.caller=$1) AS outgoing, u.id AS peer_id,
            COALESCE(NULLIF(k.alias,''), CASE WHEN k.contact IS NOT NULL THEN u.name ELSE u.phone END) AS peer_name
     FROM calls c JOIN users u ON u.id = CASE WHEN c.caller=$1 THEN c.callee ELSE c.caller END
     LEFT JOIN contacts k ON k.owner=$1 AND k.contact=u.id
     WHERE c.caller=$1 OR c.callee=$1 ORDER BY c.created_at DESC LIMIT 50`, [req.uid]);
  res.json({ calls: r.rows });
}));
// END OF PART 5
// ---- Singles: ONE shared room for everyone, with limits on how much people see and how much they can be reached ----
const SG = { VIEW_CAP: 30, LIKE_CAP: 15, EXPOSURE_CAP: 40, REACH_CAP: 20 }; // per day (Nairobi time)
const DAY = "(now() AT TIME ZONE 'Africa/Nairobi')::date";
const LIKE_DAY = "(created_at AT TIME ZONE 'Africa/Nairobi')::date";
const looksLikeContact = (t) => /(\d[\s().\-]*){8,}/.test(t) || /@\w+\.\w+/.test(t);
const SG_COLS = "s.user_id, s.nick, s.gender, s.show_me, s.age_min, s.age_max, s.town, s.bio, s.photo, s.active, date_part('year', age(s.birth_date))::int AS age";
const sgBlocked = (a, b) => db.query("SELECT 1 FROM blocks WHERE (blocker=$1 AND blocked=$2) OR (blocker=$2 AND blocked=$1)", [a, b]).then((r) => r.rowCount > 0);
async function sgLimits(uid) {
  const v = (await db.query(`SELECT count(*)::int AS n FROM singles_views WHERE viewer=$1 AND day=${DAY}`, [uid])).rows[0].n;
  const l = (await db.query(`SELECT count(*)::int AS n FROM singles_likes WHERE liker=$1 AND ${LIKE_DAY}=${DAY}`, [uid])).rows[0].n;
  return { views_left: Math.max(0, SG.VIEW_CAP - v), likes_left: Math.max(0, SG.LIKE_CAP - l), view_cap: SG.VIEW_CAP, like_cap: SG.LIKE_CAP };
}
async function sgProfile(uid) { return (await db.query(`SELECT ${SG_COLS} FROM singles s WHERE s.user_id=$1`, [uid])).rows[0] || null; }
setInterval(() => db.query("DELETE FROM singles_views WHERE day < (now() AT TIME ZONE 'Africa/Nairobi')::date - 2").catch(() => {}), 3600000);

app.get("/api/singles/me", need, wrap(async (req, res) => res.json({ profile: await sgProfile(req.uid), limits: await sgLimits(req.uid) })));

app.put("/api/singles/me", need, wrap(async (req, res) => {
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot change your Singles profile for now.", 403);
  const b = req.body || {};
  const nick = String(b.nick || "").trim().slice(0, 20), town = String(b.town || "").trim().slice(0, 40), bio = String(b.bio || "").trim().slice(0, 200);
  if (nick.length < 2) return bad(res, "Your nickname needs at least 2 characters.");
  if ([nick, town, bio].some(looksLikeContact)) return bad(res, "Please do not put phone numbers or emails in your profile.");
  if (!["man", "woman", "other"].includes(b.gender)) return bad(res, "Choose who you are.");
  const show = ["everyone", "men", "women"].includes(b.show_me) ? b.show_me : "everyone";
  const amin = Math.max(18, Math.min(99, parseInt(b.age_min, 10) || 18)), amax = Math.max(amin, Math.min(99, parseInt(b.age_max, 10) || 99));
  const exists = (await db.query("SELECT 1 FROM singles WHERE user_id=$1", [req.uid])).rowCount > 0;
  if (!exists) {
    if ((await db.query("SELECT 1 FROM singles_blocked WHERE user_id=$1 AND (until IS NULL OR until > now())", [req.uid])).rowCount) return bad(res, "Singles is not available for this account right now.", 403);
    const bd = new Date(String(b.birth_date || "") + "T00:00:00Z");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(b.birth_date || "")) || isNaN(bd)) return bad(res, "Enter your date of birth.");
    const now = new Date(); let age = now.getUTCFullYear() - bd.getUTCFullYear();
    if (now.getUTCMonth() < bd.getUTCMonth() || (now.getUTCMonth() === bd.getUTCMonth() && now.getUTCDate() < bd.getUTCDate())) age--;
    if (age < 18) { await db.query("INSERT INTO singles_blocked(user_id,until,reason) VALUES($1,NULL,'underage') ON CONFLICT (user_id) DO UPDATE SET until=NULL, reason='underage'", [req.uid]); return bad(res, "Singles is for adults only (18+).", 403); }
    if (age > 99) return bad(res, "Enter a valid date of birth.");
    if (b.accept !== true) return bad(res, "Please confirm that you are 18 or older.");
    await db.query("INSERT INTO singles(user_id,nick,birth_date,gender,show_me,age_min,age_max,town,bio) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", [req.uid, nick, b.birth_date, b.gender, show, amin, amax, town, bio]);
  } else {
    await db.query("UPDATE singles SET nick=$2, gender=$3, show_me=$4, age_min=$5, age_max=$6, town=$7, bio=$8, active=$9, updated_at=now() WHERE user_id=$1", [req.uid, nick, b.gender, show, amin, amax, town, bio, b.active !== false]);
  }
  res.json({ profile: await sgProfile(req.uid) });
}));

app.put("/api/singles/photo", need, wrap(async (req, res) => {
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot change your Singles profile for now.", 403);
  const p = String(req.body.photo || "");
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+\/]+={0,2})$/.exec(p);
  if (!m || p.length > 90000) return bad(res, "Please choose a smaller picture.");
  const buf = Buffer.from(m[1], "base64");
  if (buf.length < 100 || buf[0] !== 0xff || buf[1] !== 0xd8) return bad(res, "That is not a JPEG picture.");
  const r = await db.query("UPDATE singles SET photo=$2, photo_review=true, updated_at=now() WHERE user_id=$1 RETURNING user_id", [req.uid, p]);
  if (!r.rowCount) return bad(res, "Create your Singles profile first.", 404);
  res.json({ ok: true });
}));
app.delete("/api/singles/photo", need, wrap(async (req, res) => {
  await db.query("UPDATE singles SET photo=NULL, photo_review=false WHERE user_id=$1", [req.uid]);
  res.json({ ok: true });
}));

// Deleting the profile erases everything about it. You cannot create a new one for 24 hours (so limits cannot be reset by deleting).
app.delete("/api/singles/me", need, wrap(async (req, res) => {
  await db.query("DELETE FROM singles_messages WHERE from_id=$1 OR to_id=$1", [req.uid]);
  await db.query("DELETE FROM singles_matches WHERE a=$1 OR b=$1", [req.uid]);
  await db.query("DELETE FROM singles_likes WHERE liker=$1 OR liked=$1", [req.uid]);
  await db.query("DELETE FROM singles_passes WHERE user_id=$1 OR profile=$1", [req.uid]);
  await db.query("DELETE FROM singles_views WHERE viewer=$1 OR profile=$1", [req.uid]);
  await db.query("DELETE FROM singles WHERE user_id=$1", [req.uid]);
  await db.query("INSERT INTO singles_blocked(user_id,until,reason) VALUES($1, now() + interval '24 hours', 'deleted') ON CONFLICT (user_id) DO UPDATE SET until=CASE WHEN singles_blocked.until IS NULL THEN NULL ELSE EXCLUDED.until END", [req.uid]);
  res.json({ ok: true });
}));

app.get("/api/singles/deck", need, wrap(async (req, res) => {
  const me = (await db.query("SELECT *, date_part('year', age(birth_date))::int AS age FROM singles WHERE user_id=$1", [req.uid])).rows[0];
  if (!me) return bad(res, "Create your Singles profile first.", 404);
  const lim = await sgLimits(req.uid);
  if (!me.active) return res.json({ profiles: [], limits: lim });
  const q = await db.query(
    `SELECT s.user_id, s.nick, s.gender, s.town, s.bio, s.photo, date_part('year', age(s.birth_date))::int AS age,
            EXISTS (SELECT 1 FROM singles_views v WHERE v.viewer=$1 AND v.profile=s.user_id AND v.day=${DAY}) AS seen_today
     FROM singles s JOIN users u ON u.id=s.user_id
     WHERE s.user_id<>$1 AND s.active AND NOT u.banned AND (u.rest_until IS NULL OR u.rest_until < now())
       AND ($2::text='everyone' OR ($2::text='men' AND s.gender='man') OR ($2::text='women' AND s.gender='woman'))
       AND (s.show_me='everyone' OR (s.show_me='men' AND $3::text='man') OR (s.show_me='women' AND $3::text='woman'))
       AND date_part('year', age(s.birth_date)) BETWEEN $4::int AND $5::int
       AND $6::int BETWEEN s.age_min AND s.age_max
       AND NOT EXISTS (SELECT 1 FROM singles_likes l WHERE l.liker=$1 AND l.liked=s.user_id)
       AND NOT EXISTS (SELECT 1 FROM singles_passes p WHERE p.user_id=$1 AND p.profile=s.user_id)
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=s.user_id) OR (b.blocker=s.user_id AND b.blocked=$1))
       AND (EXISTS (SELECT 1 FROM singles_views v WHERE v.viewer=$1 AND v.profile=s.user_id AND v.day=${DAY})
            OR (SELECT count(*) FROM singles_views v WHERE v.profile=s.user_id AND v.day=${DAY}) < $7::int)
       AND (SELECT count(*) FROM singles_likes l WHERE l.liked=s.user_id AND (l.created_at AT TIME ZONE 'Africa/Nairobi')::date=${DAY}) < $8::int
     ORDER BY seen_today DESC, (SELECT count(*) FROM singles_views v WHERE v.profile=s.user_id AND v.day=${DAY}) ASC, random()
     LIMIT 60`, [req.uid, me.show_me, me.gender, me.age_min, me.age_max, me.age, SG.EXPOSURE_CAP, SG.REACH_CAP]);
  let left = lim.views_left; const out = [];
  for (const r of q.rows) {
    if (out.length >= 10) break;
    if (r.seen_today) out.push(r);
    else if (left > 0) { out.push(r); left--; await db.query(`INSERT INTO singles_views(day,viewer,profile) VALUES(${DAY},$1,$2) ON CONFLICT DO NOTHING`, [req.uid, r.user_id]); }
  }
  res.json({ profiles: out.map(({ seen_today, ...p }) => p), limits: { ...lim, views_left: left } });
}));

app.post("/api/singles/like/:id", need, wrap(async (req, res) => {
  if (!isId(req.params.id) || req.params.id.toLowerCase() === req.uid) return bad(res, "Invalid id.");
  const target = req.params.id.toLowerCase();
  if (!(await sgProfile(req.uid))) return bad(res, "Create your Singles profile first.", 404);
  const t = (await db.query("SELECT 1 FROM singles WHERE user_id=$1 AND active", [target])).rowCount;
  if (!t || (await sgBlocked(req.uid, target))) return bad(res, "This profile is no longer available.", 404);
  if (req.body.like !== true) {
    await db.query("INSERT INTO singles_passes(user_id,profile) VALUES($1,$2) ON CONFLICT DO NOTHING", [req.uid, target]);
    return res.json({ ok: true });
  }
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot use Singles for now.", 403);
  if ((await sgLimits(req.uid)).likes_left <= 0) return bad(res, "You have used today's likes. Come back tomorrow.", 429);
  const got = (await db.query(`SELECT count(*)::int AS n FROM singles_likes WHERE liked=$1 AND ${LIKE_DAY}=${DAY}`, [target])).rows[0].n;
  if (got >= SG.REACH_CAP) return bad(res, "This person has received a lot of attention today. Try again tomorrow.", 429);
  await db.query("INSERT INTO singles_likes(liker,liked) VALUES($1,$2) ON CONFLICT DO NOTHING", [req.uid, target]);
  const back = (await db.query("SELECT 1 FROM singles_likes WHERE liker=$1 AND liked=$2", [target, req.uid])).rowCount > 0;
  if (back) {
    const [a, b] = pair(req.uid, target);
    await db.query("INSERT INTO singles_matches(a,b) VALUES($1,$2) ON CONFLICT DO NOTHING", [a, b]);
    if (webpush) { notify(target, "msg", { title: "Singles", body: "You have a new match", tag: "sgm" }); }
  }
  res.json({ ok: true, match: back });
}));

app.get("/api/singles/matches", need, wrap(async (req, res) => {
  const r = await db.query(
    `SELECT s.user_id, s.nick, date_part('year', age(s.birth_date))::int AS age, l.body AS last_body, l.from_id AS last_from, l.created_at AS last_at, mt.created_at AS matched_at
     FROM singles_matches mt JOIN singles s ON s.user_id = CASE WHEN mt.a=$1 THEN mt.b ELSE mt.a END
     LEFT JOIN LATERAL (SELECT body, from_id, created_at FROM singles_messages m WHERE (m.from_id=$1 AND m.to_id=s.user_id) OR (m.from_id=s.user_id AND m.to_id=$1) ORDER BY m.id DESC LIMIT 1) l ON true
     WHERE (mt.a=$1 OR mt.b=$1) AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=s.user_id) OR (b.blocker=s.user_id AND b.blocked=$1))
     ORDER BY COALESCE(l.created_at, mt.created_at) DESC`, [req.uid]);
  res.json({ matches: r.rows });
}));

async function sgCanChat(uid, peer) {
  const [a, b] = pair(uid, peer);
  if (!(await db.query("SELECT 1 FROM singles_matches WHERE a=$1 AND b=$2", [a, b])).rowCount) return false;
  return !(await sgBlocked(uid, peer));
}
app.get("/api/singles/chat/:peer", need, wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  const peer = req.params.peer.toLowerCase();
  if (!(await sgCanChat(req.uid, peer))) return bad(res, "You are not matched with this person.", 403);
  const p = await sgProfile(peer);
  const m = await db.query("SELECT * FROM (SELECT id, from_id, body, created_at FROM singles_messages WHERE (from_id=$1 AND to_id=$2) OR (from_id=$2 AND to_id=$1) ORDER BY id DESC LIMIT 200) t ORDER BY id", [req.uid, peer]);
  res.json({ peer: p ? { user_id: p.user_id, nick: p.nick, age: p.age } : null, messages: m.rows });
}));
app.post("/api/singles/chat/:peer", need, wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  const peer = req.params.peer.toLowerCase();
  if (!(await sgCanChat(req.uid, peer))) return bad(res, "You are not matched with this person.", 403);
  const body = String(req.body.body || "").trim().slice(0, 2000);
  if (!body) return bad(res, "Message is empty.");
  await db.query("INSERT INTO singles_messages(from_id,to_id,body) VALUES($1,$2,$3)", [req.uid, peer, body]);
  if (webpush) notify(peer, "msg", { title: "Singles", body: "New message", tag: "sg" + req.uid });
  res.json({ ok: true });
}));
app.delete("/api/singles/match/:peer", need, wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  const peer = req.params.peer.toLowerCase(), [a, b] = pair(req.uid, peer);
  await db.query("DELETE FROM singles_matches WHERE a=$1 AND b=$2", [a, b]);
  await db.query("DELETE FROM singles_messages WHERE (from_id=$1 AND to_id=$2) OR (from_id=$2 AND to_id=$1)", [req.uid, peer]);
  await db.query("DELETE FROM singles_likes WHERE (liker=$1 AND liked=$2) OR (liker=$2 AND liked=$1)", [req.uid, peer]);
  await db.query("INSERT INTO singles_passes(user_id,profile) VALUES($1,$2),($2,$1) ON CONFLICT DO NOTHING", [req.uid, peer]);
  res.json({ ok: true });
}));
// END OF PART 6
// ---- Groups ----
// Messages in a group are visible to a member only from the time they joined. A person removed or leaving loses access.
const MAXG = 30;
const groupLimit = rateLimit({ windowMs: 60 * 60000, max: 30 });
const gMember = async (gid, uid) => (await db.query("SELECT role, joined_at FROM group_members WHERE group_id=$1 AND user_id=$2", [gid, uid])).rows[0];
const isRestricted = async (uid) => { const r = (await db.query("SELECT restricted_until FROM users WHERE id=$1", [uid])).rows[0]; return !!(r && r.restricted_until && new Date(r.restricted_until) > new Date()); };
async function checkAddable(uid, ids) {
  ids = [...new Set(ids.filter(isId).map((x) => x.toLowerCase()))].filter((x) => x !== uid);
  if (!ids.length) return { error: "Choose at least one contact." };
  const ok = await db.query("SELECT contact FROM contacts WHERE owner=$1 AND contact = ANY($2::uuid[]) AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=contacts.contact) OR (b.blocker=contacts.contact AND b.blocked=$1))", [uid, ids]);
  if (ok.rowCount !== ids.length) return { error: "You can only add your own contacts, and only people who have not blocked you." };
  return { ids };
}
async function leaveGroup(gid, uid, silent) {
  if (!(await gMember(gid, uid))) return;
  await db.query("DELETE FROM group_members WHERE group_id=$1 AND user_id=$2", [gid, uid]);
  const left = (await db.query("SELECT user_id, role FROM group_members WHERE group_id=$1 ORDER BY (role='admin') DESC, joined_at", [gid])).rows;
  if (!left.length) return void (await db.query("DELETE FROM chat_groups WHERE id=$1", [gid]));
  if (!left.some((x) => x.role === "admin")) await db.query("UPDATE group_members SET role='admin' WHERE group_id=$1 AND user_id=$2", [gid, left[0].user_id]);
  if (!silent) await db.query("INSERT INTO group_messages(group_id,from_id,kind) VALUES($1,$2,'left')", [gid, uid]);
}
const notifyGroup = async (gid, fromId, title, body) => {
  if (!webpush) return;
  const m = await db.query("SELECT user_id FROM group_members WHERE group_id=$1 AND user_id<>$2", [gid, fromId]);
  m.rows.forEach((r) => notify(r.user_id, "msg", { title, body, tag: "g" + gid }));
};
setInterval(() => db.query("DELETE FROM group_messages WHERE expires_at IS NOT NULL AND expires_at < now()").catch(() => {}), 60000);

app.post("/api/groups", need, groupLimit, wrap(async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 40);
  if (!name) return bad(res, "Give the group a name.");
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot add people to groups for now.", 403);
  const v = await checkAddable(req.uid, Array.isArray(req.body.members) ? req.body.members : []);
  if (v.error) return bad(res, v.error);
  if (v.ids.length + 1 > MAXG) return bad(res, "A group can have up to " + MAXG + " people.");
  const g = (await db.query("INSERT INTO chat_groups(name,created_by) VALUES($1,$2) RETURNING id", [name, req.uid])).rows[0];
  await db.query("INSERT INTO group_members(group_id,user_id,role) VALUES($1,$2,'admin')", [g.id, req.uid]);
  for (const id of v.ids) await db.query("INSERT INTO group_members(group_id,user_id) VALUES($1,$2)", [g.id, id]);
  await db.query("INSERT INTO group_messages(group_id,from_id,kind) VALUES($1,$2,'created')", [g.id, req.uid]);
  const me = (await db.query("SELECT name FROM users WHERE id=$1", [req.uid])).rows[0];
  notifyGroup(g.id, req.uid, name, me.name + " added you to a group").catch(() => {});
  res.json({ id: g.id });
}));

app.get("/api/groups", need, wrap(async (req, res) => {
  const r = await db.query(
    `SELECT g.id, g.name, g.ttl, g.created_at, gm.role,
            (SELECT count(*)::int FROM group_members x WHERE x.group_id=g.id) AS members,
            l.created_at AS last_at, l.kind AS last_kind, l.body AS last_body, l.from_id AS last_from, COALESCE(NULLIF(c.alias,''), lu.name) AS last_name
     FROM group_members gm JOIN chat_groups g ON g.id=gm.group_id
     LEFT JOIN LATERAL (SELECT * FROM group_messages m WHERE m.group_id=g.id AND m.created_at >= gm.joined_at AND (m.expires_at IS NULL OR m.expires_at > now()) ORDER BY m.id DESC LIMIT 1) l ON true
     LEFT JOIN users lu ON lu.id=l.from_id
     LEFT JOIN contacts c ON c.owner=$1 AND c.contact=l.from_id
     WHERE gm.user_id=$1`, [req.uid]);
  res.json({ groups: r.rows });
}));

app.get("/api/groups/:id", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  if (!me) return bad(res, "You are not in this group.", 403);
  const g = (await db.query("SELECT id, name, ttl, created_at, description, invite_on, invite_token, only_admins_send, members_can_add FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  const m = await db.query("SELECT u.id, COALESCE(NULLIF(c.alias,''), u.name) AS name, gm.role FROM group_members gm JOIN users u ON u.id=gm.user_id LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE gm.group_id=$1 ORDER BY (gm.role='admin') DESC, gm.joined_at", [req.params.id, req.uid]);
  const { invite_token, ...pubg } = g;
  res.json({ ...pubg, role: me.role, members: m.rows, invite_token: me.role === "admin" && g.invite_on ? invite_token : null });
}));

app.get("/api/groups/:id/messages", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  if (!me) return bad(res, "You are not in this group.", 403);
  const r = await db.query(
    `SELECT * FROM (
       SELECT m.id, m.kind, m.body, m.reply, m.created_at, m.expires_at, m.from_id, m.target_id,
              COALESCE(NULLIF(c.alias,''), u.name) AS from_name, COALESCE(NULLIF(c2.alias,''), t.name) AS target_name
       FROM group_messages m JOIN users u ON u.id=m.from_id LEFT JOIN contacts c ON c.owner=$1 AND c.contact=m.from_id
       LEFT JOIN users t ON t.id=m.target_id LEFT JOIN contacts c2 ON c2.owner=$1 AND c2.contact=m.target_id
       WHERE m.group_id=$2 AND m.created_at >= $3 AND (m.expires_at IS NULL OR m.expires_at > now())
       ORDER BY m.id DESC LIMIT 200) t ORDER BY id`, [req.uid, req.params.id, me.joined_at]);
  const g = (await db.query("SELECT ttl, only_admins_send FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  const pids = r.rows.filter((x) => x.kind === "poll").map((x) => x.id);
  if (pids.length) {
    const P = await db.query("SELECT message_id, multi, options FROM group_polls WHERE message_id = ANY($1::bigint[])", [pids]);
    const Vt = await db.query("SELECT message_id, opt, count(*)::int AS n, bool_or(user_id=$2::uuid) AS mine FROM group_poll_votes WHERE message_id = ANY($1::bigint[]) GROUP BY message_id, opt", [pids, req.uid]);
    const Tv = await db.query("SELECT message_id, count(DISTINCT user_id)::int AS n FROM group_poll_votes WHERE message_id = ANY($1::bigint[]) GROUP BY message_id", [pids]);
    for (const x of r.rows) {
      if (x.kind !== "poll") continue;
      const p = P.rows.find((y) => String(y.message_id) === String(x.id)); if (!p) continue;
      x.poll = {
        multi: p.multi,
        options: p.options.map((t, i) => { const v = Vt.rows.find((y) => String(y.message_id) === String(x.id) && y.opt === i); return { text: t, votes: v ? v.n : 0, mine: !!(v && v.mine) }; }),
        voters: (Tv.rows.find((y) => String(y.message_id) === String(x.id)) || { n: 0 }).n,
      };
    }
  }
  res.json({ messages: r.rows, ttl: g ? g.ttl : 0, only_admins_send: g ? g.only_admins_send : false });
}));

app.post("/api/groups/:id/messages", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const mem = await gMember(req.params.id, req.uid);
  if (!mem) return bad(res, "You are not in this group.", 403);
  const body = String(req.body.body || "").trim().slice(0, 4000);
  const reply = req.body.reply ? String(req.body.reply).slice(0, 120) : null;
  if (!body) return bad(res, "Message is empty.");
  const g = (await db.query("SELECT name, ttl, only_admins_send FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  if (g.only_admins_send && mem.role !== "admin") return bad(res, "Only admins can send messages in this group.", 403);
  const r = await db.query("INSERT INTO group_messages(group_id,from_id,body,reply,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id", [req.params.id, req.uid, body, reply, g.ttl ? new Date(Date.now() + g.ttl * 1000) : null]);
  const me = (await db.query("SELECT name FROM users WHERE id=$1", [req.uid])).rows[0];
  notifyGroup(req.params.id, req.uid, g.name, me.name + " sent a message").catch(() => {}); // never the message text
  res.json({ id: r.rows[0].id });
}));

app.post("/api/groups/:id/members", need, groupLimit, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  const gs = (await db.query("SELECT members_can_add FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  if (!me || (me.role !== "admin" && !(gs && gs.members_can_add))) return bad(res, "Only admins can add people.", 403);
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot add people to groups for now.", 403);
  const v = await checkAddable(req.uid, Array.isArray(req.body.members) ? req.body.members : []);
  if (v.error) return bad(res, v.error);
  const have = new Set((await db.query("SELECT user_id FROM group_members WHERE group_id=$1", [req.params.id])).rows.map((x) => x.user_id));
  const add = v.ids.filter((x) => !have.has(x));
  if (!add.length) return bad(res, "They are already in this group.");
  if (have.size + add.length > MAXG) return bad(res, "A group can have up to " + MAXG + " people.");
  const g = (await db.query("SELECT name FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  for (const id of add) {
    await db.query("INSERT INTO group_members(group_id,user_id) VALUES($1,$2)", [req.params.id, id]);
    await db.query("INSERT INTO group_messages(group_id,from_id,kind,target_id) VALUES($1,$2,'added',$3)", [req.params.id, req.uid, id]);
    if (webpush) notify(id, "msg", { title: g.name, body: "You were added to a group", tag: "g" + req.params.id });
  }
  res.json({ ok: true });
}));

app.delete("/api/groups/:id/members/:uid", need, wrap(async (req, res) => {
  if (!isId(req.params.id) || !isId(req.params.uid)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  if (!me || me.role !== "admin") return bad(res, "Only admins can remove people.", 403);
  const t = await gMember(req.params.id, req.params.uid);
  if (!t) return bad(res, "Not found.", 404);
  if (t.role === "admin") return bad(res, "Admins cannot be removed. They can leave on their own.", 403);
  await db.query("DELETE FROM group_members WHERE group_id=$1 AND user_id=$2", [req.params.id, req.params.uid]);
  await db.query("INSERT INTO group_messages(group_id,from_id,kind,target_id) VALUES($1,$2,'removed',$3)", [req.params.id, req.uid, req.params.uid]);
  res.json({ ok: true });
}));

app.post("/api/groups/:id/admins/:uid", need, wrap(async (req, res) => {
  if (!isId(req.params.id) || !isId(req.params.uid)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  if (!me || me.role !== "admin") return bad(res, "Only admins can do this.", 403);
  const r = await db.query("UPDATE group_members SET role='admin' WHERE group_id=$1 AND user_id=$2 AND role<>'admin' RETURNING user_id", [req.params.id, req.params.uid]);
  if (!r.rowCount) return bad(res, "Not found.", 404);
  await db.query("INSERT INTO group_messages(group_id,from_id,kind,target_id) VALUES($1,$2,'admin',$3)", [req.params.id, req.uid, req.params.uid]);
  res.json({ ok: true });
}));

app.put("/api/groups/:id", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  if (!me || me.role !== "admin") return bad(res, "Only admins can rename the group.", 403);
  const name = String(req.body.name || "").trim().slice(0, 40);
  if (!name) return bad(res, "Give the group a name.");
  await db.query("UPDATE chat_groups SET name=$2 WHERE id=$1", [req.params.id, name]);
  await db.query("INSERT INTO group_messages(group_id,from_id,kind,body) VALUES($1,$2,'renamed',$3)", [req.params.id, req.uid, name]);
  res.json({ ok: true });
}));

app.post("/api/groups/:id/disappear", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  if (!me || me.role !== "admin") return bad(res, "Only admins can change this.", 403);
  const sec = Number(req.body.seconds);
  if (![0, 86400, 604800].includes(sec)) return bad(res, "Choose Off, 24 hours or 7 days.");
  await db.query("UPDATE chat_groups SET ttl=$2 WHERE id=$1", [req.params.id, sec]);
  await db.query("INSERT INTO group_messages(group_id,from_id,kind,body) VALUES($1,$2,'timer',$3)", [req.params.id, req.uid, String(sec)]);
  res.json({ ok: true, ttl: sec });
}));

const joinLimit = rateLimit({ windowMs: 10 * 60000, max: 30, keyGenerator: (req) => String(req.uid) });
const adminOfGroup = async (req, res) => {
  if (!isId(req.params.id)) { bad(res, "Invalid id."); return false; }
  const me = await gMember(req.params.id, req.uid);
  if (!me || me.role !== "admin") { bad(res, "Only admins can do this.", 403); return false; }
  return true;
};
app.put("/api/groups/:id/description", need, wrap(async (req, res) => {
  if (!(await adminOfGroup(req, res))) return;
  await db.query("UPDATE chat_groups SET description=$2 WHERE id=$1", [req.params.id, String(req.body.description || "").trim().slice(0, 300)]);
  await db.query("INSERT INTO group_messages(group_id,from_id,kind) VALUES($1,$2,'desc')", [req.params.id, req.uid]);
  res.json({ ok: true });
}));
app.put("/api/groups/:id/settings", need, wrap(async (req, res) => {
  if (!(await adminOfGroup(req, res))) return;
  const b = req.body || {}, id = req.params.id;
  if (typeof b.only_admins_send === "boolean") await db.query("UPDATE chat_groups SET only_admins_send=$2 WHERE id=$1", [id, b.only_admins_send]);
  if (typeof b.members_can_add === "boolean") await db.query("UPDATE chat_groups SET members_can_add=$2 WHERE id=$1", [id, b.members_can_add]);
  if (typeof b.invite_on === "boolean") {
    await db.query("UPDATE chat_groups SET invite_on=$2, invite_token=CASE WHEN $2 AND invite_token IS NULL THEN $3 ELSE invite_token END WHERE id=$1", [id, b.invite_on, crypto.randomBytes(16).toString("base64url")]);
  }
  res.json({ ok: true });
}));
app.post("/api/groups/:id/invite/reset", need, wrap(async (req, res) => {
  if (!(await adminOfGroup(req, res))) return;
  await db.query("UPDATE chat_groups SET invite_token=$2, invite_on=true WHERE id=$1", [req.params.id, crypto.randomBytes(16).toString("base64url")]);
  res.json({ ok: true });
}));
const tokenOk = (t) => /^[A-Za-z0-9_-]{16,40}$/.test(String(t));
app.get("/api/groups/join/:token", need, joinLimit, wrap(async (req, res) => {
  if (!tokenOk(req.params.token)) return bad(res, "This invite link is not valid.", 404);
  const g = (await db.query("SELECT id, name, description FROM chat_groups WHERE invite_token=$1 AND invite_on", [req.params.token])).rows[0];
  if (!g) return bad(res, "This invite link is not valid.", 404);
  const n = (await db.query("SELECT count(*)::int AS n FROM group_members WHERE group_id=$1", [g.id])).rows[0].n;
  res.json({ id: g.id, name: g.name, description: g.description, members: n, full: n >= MAXG, already: !!(await gMember(g.id, req.uid)) });
}));
app.post("/api/groups/join/:token", need, joinLimit, wrap(async (req, res) => {
  if (!tokenOk(req.params.token)) return bad(res, "This invite link is not valid.", 404);
  const g = (await db.query("SELECT id FROM chat_groups WHERE invite_token=$1 AND invite_on", [req.params.token])).rows[0];
  if (!g) return bad(res, "This invite link is not valid.", 404);
  if (await gMember(g.id, req.uid)) return res.json({ id: g.id });
  const n = (await db.query("SELECT count(*)::int AS n FROM group_members WHERE group_id=$1", [g.id])).rows[0].n;
  if (n >= MAXG) return bad(res, "This group is full.", 409);
  await db.query("INSERT INTO group_members(group_id,user_id) VALUES($1,$2)", [g.id, req.uid]);
  await db.query("INSERT INTO group_messages(group_id,from_id,kind) VALUES($1,$2,'joined')", [g.id, req.uid]);
  res.json({ id: g.id });
}));

app.post("/api/groups/:id/polls", need, groupLimit, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const mem = await gMember(req.params.id, req.uid);
  if (!mem) return bad(res, "You are not in this group.", 403);
  const g = (await db.query("SELECT name, ttl, only_admins_send FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  if (g.only_admins_send && mem.role !== "admin") return bad(res, "Only admins can send messages in this group.", 403);
  const q = String(req.body.question || "").trim().slice(0, 200);
  const opts = [...new Set((Array.isArray(req.body.options) ? req.body.options : []).map((x) => String(x || "").trim().slice(0, 100)).filter(Boolean))].slice(0, 6);
  if (!q) return bad(res, "Write the question.");
  if (opts.length < 2) return bad(res, "Add at least 2 different options.");
  const m = await db.query("INSERT INTO group_messages(group_id,from_id,kind,body,expires_at) VALUES($1,$2,'poll',$3,$4) RETURNING id", [req.params.id, req.uid, q, g.ttl ? new Date(Date.now() + g.ttl * 1000) : null]);
  await db.query("INSERT INTO group_polls(message_id,multi,options) VALUES($1,$2,$3::text[])", [m.rows[0].id, req.body.multi === true, opts]);
  const me = (await db.query("SELECT name FROM users WHERE id=$1", [req.uid])).rows[0];
  notifyGroup(req.params.id, req.uid, g.name, me.name + " created a poll").catch(() => {});
  res.json({ id: m.rows[0].id });
}));
app.post("/api/polls/:id/vote", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  const row = (await db.query(
    `SELECT m.id, p.multi, p.options FROM group_messages m JOIN group_polls p ON p.message_id=m.id
     JOIN group_members gm ON gm.group_id=m.group_id AND gm.user_id=$2
     WHERE m.id=$1 AND m.created_at >= gm.joined_at AND (m.expires_at IS NULL OR m.expires_at > now())`, [req.params.id, req.uid])).rows[0];
  if (!row) return bad(res, "This poll is not available.", 404);
  let sel = [...new Set((Array.isArray(req.body.options) ? req.body.options : []).map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n < row.options.length))];
  if (!row.multi) sel = sel.slice(0, 1);
  const cl = await db.connect();
  try {
    await cl.query("BEGIN");
    await cl.query("DELETE FROM group_poll_votes WHERE message_id=$1 AND user_id=$2", [row.id, req.uid]);
    for (const o of sel) await cl.query("INSERT INTO group_poll_votes(message_id,user_id,opt) VALUES($1,$2,$3)", [row.id, req.uid, o]);
    await cl.query("COMMIT");
  } catch (e) { await cl.query("ROLLBACK").catch(() => {}); throw e; } finally { cl.release(); }
  res.json({ ok: true });
}));

app.post("/api/groups/:id/leave", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  await leaveGroup(req.params.id, req.uid, false);
  res.json({ ok: true });
}));
// END OF PART 7
const schema = `
CREATE TABLE IF NOT EXISTS users(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), phone text UNIQUE NOT NULL, name text NOT NULL, about text NOT NULL DEFAULT 'Hey there! I am using Orivoclass.', pass_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS contacts(owner uuid REFERENCES users(id) ON DELETE CASCADE, contact uuid REFERENCES users(id) ON DELETE CASCADE, alias text, PRIMARY KEY(owner,contact));
CREATE TABLE IF NOT EXISTS messages(id bigserial PRIMARY KEY, from_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, to_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, body text NOT NULL, reply text, reaction text, del_from boolean NOT NULL DEFAULT false, del_to boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS msg_pair ON messages(from_id,to_id,id);
CREATE TABLE IF NOT EXISTS statuses(id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, body text NOT NULL, color text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS seen_privacy text NOT NULL DEFAULT 'everyone';
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hash text;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at timestamptz;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS view_once boolean NOT NULL DEFAULT false;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS opened_at timestamptz;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS forwarded boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS blocks(blocker uuid REFERENCES users(id) ON DELETE CASCADE, blocked uuid REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(blocker,blocked));
CREATE TABLE IF NOT EXISTS reports(id bigserial PRIMARY KEY, reporter uuid REFERENCES users(id) ON DELETE CASCADE, reported uuid REFERENCES users(id) ON DELETE CASCADE, reason text NOT NULL, note text, evidence jsonb, status text NOT NULL DEFAULT 'open', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS chat_prefs(owner uuid REFERENCES users(id) ON DELETE CASCADE, peer uuid REFERENCES users(id) ON DELETE CASCADE, pinned boolean NOT NULL DEFAULT false, archived boolean NOT NULL DEFAULT false, PRIMARY KEY(owner,peer));
CREATE TABLE IF NOT EXISTS otps(phone text PRIMARY KEY, code_hash text NOT NULL, expires_at timestamptz NOT NULL, attempts int NOT NULL DEFAULT 0, last_sent timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, device text, created_at timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS login_requests(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, secret_hash text NOT NULL, status text NOT NULL DEFAULT 'pending', device text, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);
ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_score int NOT NULL DEFAULT 100;
ALTER TABLE users ADD COLUMN IF NOT EXISTS restricted_until timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS rest_until timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS photo text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_privacy text NOT NULL DEFAULT 'everyone';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS expires_at timestamptz;
CREATE INDEX IF NOT EXISTS msg_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS chat_settings(user_a uuid REFERENCES users(id) ON DELETE CASCADE, user_b uuid REFERENCES users(id) ON DELETE CASCADE, ttl int NOT NULL DEFAULT 0, set_by uuid, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(user_a,user_b));
ALTER TABLE users ADD COLUMN IF NOT EXISTS n_msg boolean NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS n_status boolean NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS n_views boolean NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS cover int NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS n_calls boolean NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ai_keep int NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS posts(id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, body text NOT NULL DEFAULT '', image text, removed boolean NOT NULL DEFAULT false, removed_reason text, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS posts_recent ON posts(id DESC) WHERE NOT removed;
CREATE INDEX IF NOT EXISTS posts_user ON posts(user_id, id DESC);
CREATE TABLE IF NOT EXISTS post_likes(post_id bigint NOT NULL REFERENCES posts(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(post_id,user_id));
CREATE TABLE IF NOT EXISTS post_comments(id bigserial PRIMARY KEY, post_id bigint NOT NULL REFERENCES posts(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, body text NOT NULL, removed boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS post_comments_post ON post_comments(post_id, id);
CREATE TABLE IF NOT EXISTS post_views(post_id bigint NOT NULL REFERENCES posts(id) ON DELETE CASCADE, viewer uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(post_id,viewer));
CREATE TABLE IF NOT EXISTS follows(follower uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, followee uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(follower,followee));
CREATE INDEX IF NOT EXISTS follows_followee ON follows(followee, created_at DESC);
ALTER TABLE post_likes ADD COLUMN IF NOT EXISTS emoji text NOT NULL DEFAULT '❤️';
ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS parent_id bigint;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS no_suggest boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS follow_requests(follower uuid REFERENCES users(id) ON DELETE CASCADE, followee uuid REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(follower,followee));
CREATE TABLE IF NOT EXISTS post_boosts(post_id bigint PRIMARY KEY REFERENCES posts(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, until timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS boosts_user ON post_boosts(user_id, created_at DESC);
ALTER TABLE posts ADD COLUMN IF NOT EXISTS audience text NOT NULL DEFAULT 'public';
CREATE TABLE IF NOT EXISTS boost_orders(reference text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, post_id bigint NOT NULL REFERENCES posts(id) ON DELETE CASCADE, days int NOT NULL, amount int NOT NULL, status text NOT NULL DEFAULT 'pending', created_at timestamptz NOT NULL DEFAULT now(), paid_at timestamptz);
CREATE TABLE IF NOT EXISTS boost_campaigns(id bigserial PRIMARY KEY, post_id bigint NOT NULL REFERENCES posts(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, days int NOT NULL, reach_max int NOT NULL, repeat_hours int NOT NULL, starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL, reference text, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS boost_campaigns_live ON boost_campaigns(ends_at);
CREATE TABLE IF NOT EXISTS boost_views(campaign_id bigint NOT NULL REFERENCES boost_campaigns(id) ON DELETE CASCADE, viewer uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, shown_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS boost_views_c ON boost_views(campaign_id, viewer);
ALTER TABLE boost_orders ADD COLUMN IF NOT EXISTS reach int NOT NULL DEFAULT 200;
ALTER TABLE boost_orders ADD COLUMN IF NOT EXISTS repeat_hours int NOT NULL DEFAULT 24;
CREATE TABLE IF NOT EXISTS app_settings(key text PRIMARY KEY, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE post_comments ADD COLUMN IF NOT EXISTS image text;
CREATE TABLE IF NOT EXISTS post_comment_likes(comment_id bigint NOT NULL REFERENCES post_comments(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(comment_id,user_id));
CREATE TABLE IF NOT EXISTS ai_messages(id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, role text NOT NULL, content text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS ai_user ON ai_messages(user_id, id);
ALTER TABLE statuses ADD COLUMN IF NOT EXISTS image text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mood text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS status_views(status_id bigint REFERENCES statuses(id) ON DELETE CASCADE, viewer_id uuid REFERENCES users(id) ON DELETE CASCADE, viewed_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(status_id,viewer_id));
CREATE TABLE IF NOT EXISTS push_subs(endpoint text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, session_id uuid REFERENCES sessions(id) ON DELETE CASCADE, p256dh text NOT NULL, auth text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS chat_groups(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, created_by uuid REFERENCES users(id) ON DELETE SET NULL, ttl int NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS group_members(group_id uuid REFERENCES chat_groups(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id) ON DELETE CASCADE, role text NOT NULL DEFAULT 'member', joined_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(group_id,user_id));
CREATE INDEX IF NOT EXISTS gm_user ON group_members(user_id);
CREATE TABLE IF NOT EXISTS group_messages(id bigserial PRIMARY KEY, group_id uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE, from_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind text NOT NULL DEFAULT 'text', target_id uuid REFERENCES users(id) ON DELETE CASCADE, body text, reply text, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz);
CREATE INDEX IF NOT EXISTS gmsg_group ON group_messages(group_id,id);
ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';
ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS invite_token text;
ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS invite_on boolean NOT NULL DEFAULT false;
ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS only_admins_send boolean NOT NULL DEFAULT false;
ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS members_can_add boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS chat_groups_token ON chat_groups(invite_token) WHERE invite_token IS NOT NULL;
CREATE TABLE IF NOT EXISTS group_polls(message_id bigint PRIMARY KEY REFERENCES group_messages(id) ON DELETE CASCADE, multi boolean NOT NULL DEFAULT false, options text[] NOT NULL);
CREATE TABLE IF NOT EXISTS group_poll_votes(message_id bigint REFERENCES group_messages(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id) ON DELETE CASCADE, opt int NOT NULL, PRIMARY KEY(message_id,user_id,opt));
CREATE TABLE IF NOT EXISTS calls(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), caller uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, callee uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind text NOT NULL DEFAULT 'voice', status text NOT NULL DEFAULT 'ringing', created_at timestamptz NOT NULL DEFAULT now(), answered_at timestamptz, ended_at timestamptz);
CREATE INDEX IF NOT EXISTS calls_caller ON calls(caller, created_at DESC);
CREATE INDEX IF NOT EXISTS calls_callee ON calls(callee, created_at DESC);
CREATE TABLE IF NOT EXISTS call_signals(id bigserial PRIMARY KEY, call_id uuid NOT NULL REFERENCES calls(id) ON DELETE CASCADE, to_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind text NOT NULL, payload text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS callsig_to ON call_signals(call_id, to_id, id);
CREATE TABLE IF NOT EXISTS singles(user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, nick text NOT NULL, birth_date date NOT NULL, gender text NOT NULL, show_me text NOT NULL DEFAULT 'everyone', age_min int NOT NULL DEFAULT 18, age_max int NOT NULL DEFAULT 99, town text, bio text, photo text, photo_review boolean NOT NULL DEFAULT false, active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS singles_views(day date NOT NULL, viewer uuid REFERENCES users(id) ON DELETE CASCADE, profile uuid REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(day,viewer,profile));
CREATE TABLE IF NOT EXISTS singles_likes(liker uuid REFERENCES users(id) ON DELETE CASCADE, liked uuid REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(liker,liked));
CREATE TABLE IF NOT EXISTS singles_passes(user_id uuid REFERENCES users(id) ON DELETE CASCADE, profile uuid REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(user_id,profile));
CREATE TABLE IF NOT EXISTS singles_matches(a uuid REFERENCES users(id) ON DELETE CASCADE, b uuid REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(a,b));
CREATE TABLE IF NOT EXISTS singles_messages(id bigserial PRIMARY KEY, from_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, to_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS sgmsg_pair ON singles_messages(from_id,to_id,id);
CREATE TABLE IF NOT EXISTS singles_blocked(user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, until timestamptz, reason text);
CREATE TABLE IF NOT EXISTS sanctions(id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind text NOT NULL, reason text NOT NULL, report_id bigint, penalty int NOT NULL DEFAULT 0, until timestamptz, seen boolean NOT NULL DEFAULT false, appeal_status text, appeal_text text, appealed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS blocked_phones(phone text PRIMARY KEY, until timestamptz, reason text, created_at timestamptz NOT NULL DEFAULT now());`;

db.query(schema)
  .then(() => app.listen(Number(process.env.PORT) || 3000, () => console.log("Orivoclass API running")))
  .catch((e) => { console.error("Database setup failed:", e.message); process.exit(1); });
// END OF PART 8
// ---- Public content: posts (memes and thoughts), likes, comments, followers and a creator dashboard ----
// Posts are visible to everyone who has an Orivoclass account (not to the open web). Blocked people never see each other's posts.
const POST_LIMIT = 20; // new posts per person in 24 hours
const postLimit = rateLimit({ windowMs: 60 * 60000, max: 30, keyGenerator: (req) => String(req.uid) });
const socialLimit = rateLimit({ windowMs: 60 * 60000, max: 200, keyGenerator: (req) => String(req.uid) });
const commentLimit = rateLimit({ windowMs: 60 * 60000, max: 60, keyGenerator: (req) => String(req.uid) });
const jpegOk = (p, max) => {
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+\/]+={0,2})$/.exec(String(p || ""));
  if (!m || String(p).length > max) return false;
  const b = Buffer.from(m[1], "base64");
  return b.length > 100 && b[0] === 0xff && b[1] === 0xd8;
};
const REACTIONS = ["❤️", "😂", "😭", "🥰", "😮", "👍", "🔥"];
const POST_COLS = `p.id, p.user_id, u.name, p.body, p.audience, (p.image IS NOT NULL) AS has_image, p.created_at,
  (SELECT count(*)::int FROM post_likes l WHERE l.post_id=p.id) AS likes,
  (SELECT COALESCE(json_agg(t.e), '[]'::json) FROM (SELECT l.emoji AS e FROM post_likes l WHERE l.post_id=p.id GROUP BY l.emoji ORDER BY count(*) DESC LIMIT 3) t) AS top_reactions,
  (SELECT count(*)::int FROM post_comments c WHERE c.post_id=p.id AND NOT c.removed) AS comments,
  (SELECT l.emoji FROM post_likes l WHERE l.post_id=p.id AND l.user_id=$1) AS my_reaction,
  EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=p.user_id) AS following,
  EXISTS (SELECT 1 FROM post_boosts b WHERE b.post_id=p.id AND b.until > now()) AS boosted`;
const POST_OK = `NOT p.removed AND NOT u.banned AND (u.rest_until IS NULL OR u.rest_until < now())
  AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=p.user_id) OR (b.blocker=p.user_id AND b.blocked=$1))
  AND (NOT u.locked OR p.user_id=$1 OR EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=p.user_id))
  AND (p.audience='public' OR p.user_id=$1 OR EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=p.user_id))`;
const numId = (s) => /^\d+$/.test(String(s || ""));
async function visiblePost(uid, id) {
  return (await db.query(
    `SELECT p.id, p.user_id, p.body, (p.image IS NOT NULL) AS has_image, p.created_at FROM posts p JOIN users u ON u.id=p.user_id
     WHERE p.id=$2 AND ${POST_OK}`, [uid, id])).rows[0];
}

app.post("/api/posts", need, postLimit, wrap(async (req, res) => {
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot post for now.", 403);
  const body = String(req.body.body || "").trim().slice(0, 500);
  const image = req.body.image || null;
  if (image && !jpegOk(image, 160000)) return bad(res, "Please choose a smaller picture.");
  if (!body && !image) return bad(res, "Write something or add a photo first.");
  const n = (await db.query("SELECT count(*)::int AS n FROM posts WHERE user_id=$1 AND created_at > now() - interval '24 hours'", [req.uid])).rows[0].n;
  if (n >= POST_LIMIT) return bad(res, "You have reached today's limit of " + POST_LIMIT + " posts. Try again tomorrow.", 429);
  const r = await db.query("INSERT INTO posts(user_id,body,image,audience) VALUES($1,$2,$3,$4) RETURNING id", [req.uid, body, image, req.body.audience === "followers" ? "followers" : "public"]);
  res.json({ id: r.rows[0].id });
}));

app.get("/api/feed", need, wrap(async (req, res) => {
  const following = req.query.scope === "following";
  const off = Math.max(0, Math.min(100000, parseInt(req.query.offset, 10) || 0));
  if (following) {
    const r = await db.query(`SELECT ${POST_COLS} FROM posts p JOIN users u ON u.id=p.user_id
      WHERE ${POST_OK} AND (p.user_id=$1 OR EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=p.user_id))
      ORDER BY p.id DESC LIMIT 15 OFFSET $2`, [req.uid, off]);
    return res.json({ posts: r.rows });
  }
  // For you: a mix of the strongest posts (of today and of the days before) and the newest ones.
  // Posts set to Followers only appear here for the people who follow the author (POST_OK checks that).
  // Posts this person already scrolled past go to the back of the line, not out of the feed.
  const score = `((SELECT count(*) FROM post_likes l WHERE l.post_id=p.id) + 2*(SELECT count(*) FROM post_comments c WHERE c.post_id=p.id AND NOT c.removed) + 0.2*(SELECT count(*) FROM post_views v WHERE v.post_id=p.id) + 1)::float8 / power((extract(epoch FROM (now() - p.created_at))/3600.0 + 2)::float8, 1.2)`;
  const base = `SELECT ${POST_COLS} FROM posts p JOIN users u ON u.id=p.user_id WHERE ${POST_OK}`;
  const unseen = `AND NOT EXISTS (SELECT 1 FROM post_views v WHERE v.post_id=p.id AND v.viewer=$1)`;
  const [top, fresh, old] = await Promise.all([
    db.query(`${base} ${unseen} ORDER BY ${score} DESC, p.id DESC LIMIT 300`, [req.uid]),
    db.query(`${base} ${unseen} ORDER BY p.id DESC LIMIT 300`, [req.uid]),
    db.query(`${base} ORDER BY ${score} DESC, p.id DESC LIMIT 300`, [req.uid])]);
  const seen = new Set(), list = [];
  const add = (x) => { if (x && !seen.has(x.id)) { seen.add(x.id); list.push(x); } };
  for (let i = 0; i < Math.max(top.rows.length, fresh.rows.length); i++) { add(top.rows[i]); add(fresh.rows[i]); }
  // Everything else (already seen, and older posts) comes after, so the feed keeps going and never ends.
  for (const x of old.rows) add(x);
  if (off === 0) {
    const paid = await boostsFor(req.uid);
    let n = 0;
    for (const sp of paid) {
      const at = Math.min(list.length, 1 + 5 * n); n++;
      const i = list.findIndex((x) => x.id === sp.id); if (i >= 0) list.splice(i, 1);
      list.splice(at, 0, { ...sp, sponsored: true });
      await db.query("INSERT INTO boost_views(campaign_id,viewer) VALUES($1,$2)", [sp.cid, req.uid]);
    }
  }
  if (off + 15 > list.length) { // a little more from anywhere, so scrolling never runs out
    const more = await db.query(`${base} ORDER BY random() LIMIT 40`, [req.uid]);
    for (const x of more.rows) add(x);
  }
  res.json({ posts: list.slice(off, off + 15) });
}));

app.get("/api/users/:id/posts", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const before = numId(req.query.before) ? req.query.before : null;
  const r = await db.query(
    `SELECT ${POST_COLS} FROM posts p JOIN users u ON u.id=p.user_id
     WHERE ${POST_OK} AND p.user_id=$3 AND ($2::bigint IS NULL OR p.id < $2::bigint) ORDER BY p.id DESC LIMIT 15`, [req.uid, before, req.params.id.toLowerCase()]);
  res.json({ posts: r.rows });
}));

app.get("/api/posts/:id/image", need, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const r = await db.query(
    `SELECT p.image FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=$2 AND p.image IS NOT NULL AND ${POST_OK}`, [req.uid, req.params.id]);
  if (!r.rows[0]) return bad(res, "Not found.", 404);
  res.json({ image: r.rows[0].image });
}));

app.delete("/api/posts/:id", need, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  await db.query("DELETE FROM posts WHERE id=$1 AND user_id=$2", [req.params.id, req.uid]);
  res.json({ ok: true });
}));

app.post("/api/posts/views", need, socialLimit, wrap(async (req, res) => { // counts each person once per post
  const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).filter(numId).slice(0, 30);
  if (ids.length) await db.query("INSERT INTO post_views(post_id,viewer) SELECT p.id, $1 FROM posts p WHERE p.id = ANY($2::bigint[]) AND p.user_id<>$1 ON CONFLICT DO NOTHING", [req.uid, ids]);
  res.json({ ok: true });
}));

app.post("/api/posts/:id/like", need, socialLimit, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  if (!(await visiblePost(req.uid, req.params.id))) return bad(res, "This post is not available.", 404);
  if (req.body.like === false) await db.query("DELETE FROM post_likes WHERE post_id=$1 AND user_id=$2", [req.params.id, req.uid]);
  else {
    const emoji = REACTIONS.includes(req.body.emoji) ? req.body.emoji : "❤️";
    await db.query("INSERT INTO post_likes(post_id,user_id,emoji) VALUES($1,$2,$3) ON CONFLICT (post_id,user_id) DO UPDATE SET emoji=EXCLUDED.emoji", [req.params.id, req.uid, emoji]);
  }
  const mine = (await db.query("SELECT emoji FROM post_likes WHERE post_id=$1 AND user_id=$2", [req.params.id, req.uid])).rows[0];
  res.json({ ok: true, my_reaction: mine ? mine.emoji : null });
}));

app.get("/api/posts/:id/comments", need, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const p = await visiblePost(req.uid, req.params.id);
  if (!p) return bad(res, "This post is not available.", 404);
  const r = await db.query(
    `SELECT * FROM (SELECT c.id, c.user_id, u.name, c.body, c.created_at, c.parent_id, (c.image IS NOT NULL) AS has_image, (SELECT count(*)::int FROM post_comment_likes l WHERE l.comment_id=c.id) AS likes, EXISTS (SELECT 1 FROM post_comment_likes l WHERE l.comment_id=c.id AND l.user_id=$1) AS liked FROM post_comments c JOIN users u ON u.id=c.user_id
       WHERE c.post_id=$2 AND NOT c.removed AND NOT u.banned
         AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=c.user_id) OR (b.blocker=c.user_id AND b.blocked=$1))
       ORDER BY c.id DESC LIMIT 60) t ORDER BY id`, [req.uid, req.params.id]);
  res.json({ comments: r.rows, post_owner: p.user_id });
}));
app.post("/api/posts/:id/comments", need, commentLimit, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot comment for now.", 403);
  const body = String(req.body.body || "").trim().slice(0, 300);
  const image = req.body.image || null;
  if (image && !jpegOk(image, 160000)) return bad(res, "Please choose a smaller picture.");
  if (!body && !image) return bad(res, "Write a comment or add a photo first.");
  if (!(await visiblePost(req.uid, req.params.id))) return bad(res, "This post is not available.", 404);
  let parent = null;
  if (numId(req.body.parent_id)) {
    const pc = (await db.query("SELECT id, parent_id FROM post_comments WHERE id=$1 AND post_id=$2 AND NOT removed", [req.body.parent_id, req.params.id])).rows[0];
    if (!pc) return bad(res, "That comment is no longer there.", 404);
    parent = pc.parent_id || pc.id; // replies sit under the main comment (one level)
  }
  await db.query("INSERT INTO post_comments(post_id,user_id,body,parent_id,image) VALUES($1,$2,$3,$4,$5)", [req.params.id, req.uid, body, parent, image]);
  res.json({ ok: true });
}));
app.delete("/api/comments/:id", need, wrap(async (req, res) => { // your own comment, or any comment on your own post
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  await db.query("UPDATE post_comments SET removed=true WHERE id=$1 AND (user_id=$2 OR post_id IN (SELECT id FROM posts WHERE user_id=$2))", [req.params.id, req.uid]);
  res.json({ ok: true });
}));

app.post("/api/follow/:uid", need, socialLimit, wrap(async (req, res) => {
  if (!isId(req.params.uid) || req.params.uid.toLowerCase() === req.uid) return bad(res, "Invalid id.");
  const t = req.params.uid.toLowerCase();
  if (!(await db.query("SELECT 1 FROM users WHERE id=$1 AND NOT banned", [t])).rowCount || (await sgBlocked(req.uid, t))) return bad(res, "This person is not available.", 404);
  const lk = (await db.query("SELECT locked FROM users WHERE id=$1", [t])).rows[0];
  if (lk && lk.locked) { // private account: they approve the request first
    await db.query("INSERT INTO follow_requests(follower,followee) VALUES($1,$2) ON CONFLICT DO NOTHING", [req.uid, t]);
    return res.json({ ok: true, requested: true });
  }
  await db.query("INSERT INTO follows(follower,followee) VALUES($1,$2) ON CONFLICT DO NOTHING", [req.uid, t]);
  res.json({ ok: true });
}));
app.delete("/api/follow/:uid", need, socialLimit, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  await db.query("DELETE FROM follows WHERE follower=$1 AND followee=$2", [req.uid, req.params.uid.toLowerCase()]);
  await db.query("DELETE FROM follow_requests WHERE follower=$1 AND followee=$2", [req.uid, req.params.uid.toLowerCase()]);
  res.json({ ok: true });
}));

app.get("/api/profile/:uid", need, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  const r = await db.query(
    `SELECT u.id, u.name, u.about, u.cover, u.mood, u.created_at, u.locked,
       (SELECT count(*)::int FROM posts p WHERE p.user_id=u.id AND NOT p.removed) AS posts,
       (SELECT count(*)::int FROM follows f WHERE f.followee=u.id) AS followers,
       (SELECT count(*)::int FROM follows f WHERE f.follower=u.id) AS following,
       EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=u.id) AS am_following,
       EXISTS (SELECT 1 FROM follows f WHERE f.follower=u.id AND f.followee=$1) AS follows_me,
       EXISTS (SELECT 1 FROM follow_requests fr WHERE fr.follower=$1 AND fr.followee=u.id) AS requested
     FROM users u WHERE u.id=$2 AND NOT u.banned
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=u.id) OR (b.blocker=u.id AND b.blocked=$1))`, [req.uid, req.params.uid.toLowerCase()]);
  if (!r.rows[0]) return bad(res, "This profile is not available.", 404);
  res.json(r.rows[0]);
}));

// Creator dashboard: only the owner sees these numbers.
app.get("/api/me/dashboard", need, wrap(async (req, res) => {
  const s = (await db.query(
    `SELECT
       (SELECT count(*)::int FROM follows WHERE followee=$1) AS followers,
       (SELECT count(*)::int FROM follows WHERE follower=$1) AS following,
       (SELECT count(*)::int FROM posts WHERE user_id=$1 AND NOT removed) AS posts,
       (SELECT count(*)::int FROM post_likes l JOIN posts p ON p.id=l.post_id WHERE p.user_id=$1 AND NOT p.removed) AS likes,
       (SELECT count(*)::int FROM post_comments c JOIN posts p ON p.id=c.post_id WHERE p.user_id=$1 AND NOT p.removed AND NOT c.removed AND c.user_id<>$1) AS comments,
       (SELECT count(*)::int FROM post_views v JOIN posts p ON p.id=v.post_id WHERE p.user_id=$1 AND NOT p.removed) AS views,
       (SELECT count(*)::int FROM follows WHERE followee=$1 AND created_at > now() - interval '7 days') AS new_followers`, [req.uid])).rows[0];
  const posts = await db.query(
    `SELECT p.id, p.body, (p.image IS NOT NULL) AS has_image, p.created_at,
       (SELECT count(*)::int FROM post_likes l WHERE l.post_id=p.id) AS likes,
       (SELECT count(*)::int FROM post_comments c WHERE c.post_id=p.id AND NOT c.removed) AS comments,
       (SELECT count(*)::int FROM post_views v WHERE v.post_id=p.id) AS views,
       EXISTS (SELECT 1 FROM post_boosts b WHERE b.post_id=p.id AND b.until > now()) AS boosted
     FROM posts p WHERE p.user_id=$1 AND NOT p.removed ORDER BY p.id DESC LIMIT 20`, [req.uid]);
  const fl = await db.query("SELECT u.id, u.name FROM follows f JOIN users u ON u.id=f.follower WHERE f.followee=$1 ORDER BY f.created_at DESC LIMIT 50", [req.uid]);
  const fg = await db.query("SELECT u.id, u.name FROM follows f JOIN users u ON u.id=f.followee WHERE f.follower=$1 ORDER BY f.created_at DESC LIMIT 50", [req.uid]);
  res.json({ ...s, recent: posts.rows, followers_list: fl.rows, following_list: fg.rows });
}));

// Reporting a public post. The post is checked by the admin, who can remove it and restrict the author.
app.post("/api/posts/:id/report", need, reportLimit, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const p = await visiblePost(req.uid, req.params.id);
  if (!p) return bad(res, "This post is not available.", 404);
  if (p.user_id === req.uid) return bad(res, "You cannot report your own post.");
  const reason = REASONS.includes(req.body.reason) ? req.body.reason : "Other";
  const note = "[Post #" + p.id + "] " + String(req.body.note || "").trim().slice(0, 450);
  await db.query("INSERT INTO reports(reporter,reported,reason,note,evidence) VALUES($1,$2,$3,$4,$5)", [req.uid, p.user_id, reason, note, JSON.stringify([{ post_id: p.id, body: p.body, has_image: p.has_image, created_at: p.created_at }])]);
  res.json({ ok: true });
}));

// Admin: look at a post (with its picture) and take it down.
app.get("/api/admin/posts", adminLimit, adminOnly, wrap(async (req, res) => {
  const r = await db.query("SELECT p.id, p.user_id, u.name, p.body, (p.image IS NOT NULL) AS has_image, p.removed, p.created_at FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 30");
  res.json({ posts: r.rows });
}));
app.get("/api/admin/posts/:id", adminLimit, adminOnly, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const r = await db.query("SELECT p.id, p.user_id, u.name, p.body, p.image, p.removed, p.created_at FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=$1", [req.params.id]);
  if (!r.rows[0]) return bad(res, "Post not found.", 404);
  res.json(r.rows[0]);
}));
app.post("/api/admin/posts/:id/remove", adminLimit, adminOnly, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const reason = String(req.body.reason || "Removed by an admin").slice(0, 200);
  const r = await db.query("UPDATE posts SET removed=true, removed_reason=$2 WHERE id=$1 RETURNING id, user_id", [req.params.id, reason]);
  if (!r.rowCount) return bad(res, "Post not found.", 404);
  const restrict = req.body.restrict === true;
  if (restrict) await applySanction(r.rows[0].user_id, "restriction", "Posted content that breaks the rules: " + reason); // 24 hours without posting
  res.json({ ok: true, restricted: restrict });
}));
// END OF PART 9
// ---- Private accounts, follow requests, boosting a post, suggestions and privacy settings ----
const privacyLimit = rateLimit({ windowMs: 60 * 60000, max: 60, keyGenerator: (req) => String(req.uid) });
const boostLimit = rateLimit({ windowMs: 60 * 60000, max: 20, keyGenerator: (req) => String(req.uid) });

// Everything the Me and Dashboard screens need that is not in the basic profile.
app.get("/api/me/extras", need, wrap(async (req, res) => {
  const u = (await db.query("SELECT locked, no_suggest FROM users WHERE id=$1", [req.uid])).rows[0];
  const reqs = await db.query(
    `SELECT u.id, COALESCE(NULLIF(c.alias,''), u.name) AS name, fr.created_at FROM follow_requests fr
     JOIN users u ON u.id=fr.follower LEFT JOIN contacts c ON c.owner=$1 AND c.contact=u.id
     WHERE fr.followee=$1 ORDER BY fr.created_at DESC LIMIT 50`, [req.uid]);
  res.json({ locked: !!(u && u.locked), suggest: !(u && u.no_suggest), requests: reqs.rows });
}));

app.put("/api/me/privacy", need, privacyLimit, wrap(async (req, res) => {
  const b = req.body || {};
  if (typeof b.locked === "boolean") {
    await db.query("UPDATE users SET locked=$2 WHERE id=$1", [req.uid, b.locked]);
    if (b.locked) await db.query("UPDATE post_boosts SET until=now() WHERE user_id=$1 AND until > now()", [req.uid]); // a private account stops boosting at once
    else await db.query("DELETE FROM follow_requests WHERE followee=$1", [req.uid]); // turning the lock off clears waiting requests
  }
  if (typeof b.suggest === "boolean") await db.query("UPDATE users SET no_suggest=$2 WHERE id=$1", [req.uid, !b.suggest]);
  res.json({ ok: true });
}));

app.post("/api/follow-requests/:uid/approve", need, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  const f = req.params.uid.toLowerCase();
  const r = await db.query("DELETE FROM follow_requests WHERE follower=$1 AND followee=$2 RETURNING follower", [f, req.uid]);
  if (!r.rowCount) return bad(res, "This request is no longer there.", 404);
  await db.query("INSERT INTO follows(follower,followee) VALUES($1,$2) ON CONFLICT DO NOTHING", [f, req.uid]);
  res.json({ ok: true });
}));
app.delete("/api/follow-requests/:uid", need, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  await db.query("DELETE FROM follow_requests WHERE follower=$1 AND followee=$2", [req.params.uid.toLowerCase(), req.uid]);
  res.json({ ok: true });
}));

// ---- Paid boosts (Paystack). Money first, then reach. Reach counts people who do not follow the author. ----
const BOOST_DEFAULT = { 1: { price: 50, reach: 200, repeat: 24 }, 2: { price: 90, reach: 300, repeat: 12 }, 3: { price: 120, reach: 400, repeat: 8 }, 4: { price: 150, reach: 500, repeat: 6 }, 5: { price: 180, reach: 600, repeat: 3 } };
// Plans can be changed by the admin (admin.html). They are kept in the database.
async function boostPlans() {
  const r = await db.query("SELECT value FROM app_settings WHERE key='boost_plans'");
  return r.rows[0] ? r.rows[0].value : BOOST_DEFAULT;
}
const APP_URL = process.env.APP_URL || "https://orivoclass.onrender.com/";
const paystack = async (method, path, body) => {
  const r = await fetch("https://api.paystack.co" + path, { method, headers: { Authorization: "Bearer " + process.env.PAYSTACK_SECRET_KEY, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { ok: r.ok, json: await r.json().catch(() => ({})) };
};
app.get("/api/boosts/plans", need, wrap(async (req, res) => { const P = await boostPlans(); res.json({ paid: !!process.env.PAYSTACK_SECRET_KEY, plans: Object.entries(P).map(([d, p]) => ({ days: +d, ...p })) }); }));
app.post("/api/boosts/checkout", need, boostLimit, wrap(async (req, res) => {
  if (!process.env.PAYSTACK_SECRET_KEY) return bad(res, "Payments are not set up yet.", 503);
  const plan = (await boostPlans())[String(Number(req.body.days))];
  if (!plan) return bad(res, "Choose 1 to 5 days.");
  if (!numId(req.body.post_id)) return bad(res, "Invalid id.");
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot boost posts for now.", 403);
  const me = (await db.query("SELECT locked FROM users WHERE id=$1", [req.uid])).rows[0];
  if (me && me.locked) return bad(res, "Private accounts cannot boost. Turn off Private account in Privacy to boost posts.", 403);
  const p = (await db.query("SELECT id FROM posts WHERE id=$1 AND user_id=$2 AND NOT removed", [req.body.post_id, req.uid])).rows[0];
  if (!p) return bad(res, "Post not found.", 404);
  if ((await db.query("SELECT 1 FROM boost_campaigns WHERE post_id=$1 AND ends_at > now()", [p.id])).rowCount) return bad(res, "This post is already boosted.", 409);
  const ref = "ORB" + crypto.randomBytes(9).toString("hex");
  await db.query("INSERT INTO boost_orders(reference,user_id,post_id,days,amount,status,reach,repeat_hours) VALUES($1,$2,$3,$4,$5,'pending',$6,$7)", [ref, req.uid, p.id, Number(req.body.days), plan.price, plan.reach, plan.repeat]);
  const email = "u" + req.uid.replace(/-/g, "").slice(0, 16) + "@orivoclass.app"; // Paystack needs an email; replace with the real one if you collect it
  const r = await paystack("POST", "/transaction/initialize", { email, amount: plan.price * 100, currency: "KES", reference: ref, callback_url: APP_URL, metadata: { kind: "boost", post_id: p.id, days: Number(req.body.days) } });
  if (!r.ok || !r.json.status) { await db.query("UPDATE boost_orders SET status='failed' WHERE reference=$1", [ref]); return bad(res, "Could not start the payment. Try again.", 502); }
  res.json({ reference: ref, authorization_url: r.json.data.authorization_url });
}));
// Called when the person comes back from Paystack: checks the payment with Paystack itself before turning the boost on.
app.post("/api/boosts/verify", need, wrap(async (req, res) => {
  const ref = String(req.body.reference || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 40);
  const o = (await db.query("SELECT * FROM boost_orders WHERE reference=$1 AND user_id=$2", [ref, req.uid])).rows[0];
  if (!o) return bad(res, "Payment not found.", 404);
  if (o.status === "paid") return res.json({ ok: true, status: "paid" });
  const r = await paystack("GET", "/transaction/verify/" + ref);
  const d = (r.json && r.json.data) || {};
  if (!r.ok || d.status !== "success") return res.json({ ok: false, status: d.status || "pending" });
  if (Number(d.amount) !== o.amount * 100 || d.currency !== "KES") { await db.query("UPDATE boost_orders SET status='mismatch' WHERE reference=$1", [ref]); return bad(res, "The payment does not match this plan.", 400); }
  const done = await db.query("UPDATE boost_orders SET status='paid', paid_at=now() WHERE reference=$1 AND status<>'paid' RETURNING reference", [ref]);
  if (done.rowCount) { // turn the boost on exactly once
    await db.query("INSERT INTO boost_campaigns(post_id,user_id,days,reach_max,repeat_hours,starts_at,ends_at,reference) VALUES($1,$2,$3,$4,$5,now(), now() + make_interval(days => $3), $6)", [o.post_id, o.user_id, o.days, o.reach, o.repeat_hours, ref]);
    await db.query("INSERT INTO post_boosts(post_id,user_id,until) VALUES($1,$2,now() + make_interval(days => $3)) ON CONFLICT (post_id) DO UPDATE SET until=EXCLUDED.until, user_id=EXCLUDED.user_id", [o.post_id, o.user_id, o.days]);
  }
  res.json({ ok: true, status: "paid" });
}));
// Your boosts: how many people outside your followers they reached, and until when.
app.get("/api/boosts/mine", need, wrap(async (req, res) => {
  const r = await db.query(
    `SELECT c.id, c.post_id, c.days, c.reach_max, c.ends_at, p.body,
       (SELECT count(DISTINCT bv.viewer) FROM boost_views bv WHERE bv.campaign_id=c.id)::int AS reach_used
     FROM boost_campaigns c JOIN posts p ON p.id=c.post_id WHERE c.user_id=$1 ORDER BY c.id DESC LIMIT 20`, [req.uid]);
  res.json({ campaigns: r.rows });
}));
// Which paid boosts should this person see right now (at most 2 boosted posts; each person sees a boost at most twice).
async function boostsFor(uid) {
  const r = await db.query(
    `SELECT ${POST_COLS}, c.id AS cid FROM boost_campaigns c JOIN posts p ON p.id=c.post_id JOIN users u ON u.id=p.user_id
     WHERE ${POST_OK} AND p.audience='public' AND c.starts_at <= now() AND c.ends_at > now() AND c.user_id<>$1
       AND NOT EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=p.user_id)
       AND (SELECT count(DISTINCT bv.viewer) FROM boost_views bv WHERE bv.campaign_id=c.id) < c.reach_max
       AND (SELECT count(*) FROM boost_views bv WHERE bv.campaign_id=c.id AND bv.viewer=$1) < 2
       AND NOT EXISTS (SELECT 1 FROM boost_views bv WHERE bv.campaign_id=c.id AND bv.viewer=$1 AND bv.shown_at > now() - make_interval(hours => c.repeat_hours))
     ORDER BY c.starts_at DESC LIMIT 2`, [uid]);
  return r.rows;
}

// Search for accounts by name (shown in the Feed search bar).
app.get("/api/search", need, wrap(async (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 40);
  if (q.length < 2) return res.json({ people: [] });
  const like = "%" + q.replace(/[\\%_]/g, (m) => "\\" + m) + "%";
  const r = await db.query(
    `SELECT u.id, u.name, u.locked, (SELECT count(*)::int FROM follows f WHERE f.followee=u.id) AS followers,
       EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=u.id) AS am_following
     FROM users u WHERE u.id<>$1 AND NOT u.banned AND u.name ILIKE $2
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=u.id) OR (b.blocker=u.id AND b.blocked=$1))
     ORDER BY followers DESC, u.name LIMIT 20`, [req.uid, like]);
  res.json({ people: r.rows });
}));
// "Suggested for you": people with public accounts who posted in the last week, who you do not follow yet.
// Nobody is suggested to a person they have blocked or who blocked them, and nobody with suggestions turned off or a private account.
app.get("/api/suggestions", need, wrap(async (req, res) => {
  const r = await db.query(
    `SELECT u.id, u.name, (SELECT count(*)::int FROM follows f WHERE f.followee=u.id) AS followers
     FROM users u
     WHERE u.id<>$1 AND NOT u.banned AND NOT u.locked AND NOT u.no_suggest
       AND (u.rest_until IS NULL OR u.rest_until < now())
       AND EXISTS (SELECT 1 FROM posts p WHERE p.user_id=u.id AND NOT p.removed AND p.created_at > now() - interval '7 days')
       AND NOT EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=u.id)
       AND NOT EXISTS (SELECT 1 FROM follow_requests fr WHERE fr.follower=$1 AND fr.followee=u.id)
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=u.id) OR (b.blocker=u.id AND b.blocked=$1))
     ORDER BY followers DESC, random() LIMIT 8`, [req.uid]);
  res.json({ people: r.rows });
}));
// Admin: read and change the boost plans (price in KSh, reach = people outside followers, repeat = hours before a person sees the same boost again).
app.get("/api/admin/boost-plans", adminLimit, adminOnly, wrap(async (req, res) => res.json({ plans: await boostPlans() })));
app.put("/api/admin/boost-plans", adminLimit, adminOnly, wrap(async (req, res) => {
  const out = {};
  for (let d = 1; d <= 5; d++) {
    const p = (req.body.plans || {})[String(d)] || {};
    const price = Math.round(Number(p.price)), reach = Math.round(Number(p.reach)), repeat = Math.round(Number(p.repeat));
    if (!(price >= 10 && price <= 100000) || !(reach >= 10 && reach <= 100000) || !(repeat >= 1 && repeat <= 168)) return bad(res, "Day " + d + ": check the price (10 to 100000), reach (10 to 100000) and repeat hours (1 to 168).");
    out[String(d)] = { price, reach, repeat };
  }
  await db.query("INSERT INTO app_settings(key,value,updated_at) VALUES('boost_plans',$1,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()", [JSON.stringify(out)]);
  res.json({ ok: true, plans: out });
}));
// ---- Push notifications: the server makes its own keys once and keeps them in the database. Nothing has to be typed into Render. ----
let VAPID_PUB = process.env.VAPID_PUBLIC || "";
async function setupPush() {
  let wp;
  try { wp = require("web-push"); } catch (e) { console.warn("web-push is not installed yet (add it to package.json and redeploy)."); return; }
  try {
    let pub = process.env.VAPID_PUBLIC, priv = process.env.VAPID_PRIVATE;
    if (!pub || !priv) {
      let row = (await db.query("SELECT value FROM app_settings WHERE key='vapid'")).rows[0];
      if (!row) {
        const k = wp.generateVAPIDKeys();
        await db.query("INSERT INTO app_settings(key,value) VALUES('vapid',$1) ON CONFLICT (key) DO NOTHING", [JSON.stringify({ pub: k.publicKey, priv: k.privateKey })]);
        row = (await db.query("SELECT value FROM app_settings WHERE key='vapid'")).rows[0];
      }
      pub = row.value.pub; priv = row.value.priv;
    }
    wp.setVapidDetails(process.env.VAPID_SUBJECT || "mailto:admin@orivoclass.app", pub, priv);
    webpush = wp; VAPID_PUB = pub;
    console.log("Push notifications are on.");
  } catch (e) { console.error("Push setup failed:", e.message); }
}
(async function waitForDatabase(tries) { // the database tables are created at start-up, so wait until they exist
  try { await db.query("SELECT 1 FROM app_settings LIMIT 1"); await setupPush(); }
  catch (e) { if (tries < 40) setTimeout(() => waitForDatabase(tries + 1), 2000); }
})(0);
// Like a comment (only on posts you are allowed to see).
app.post("/api/comments/:id/like", need, socialLimit, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const c = (await db.query(`SELECT c.id FROM post_comments c JOIN posts p ON p.id=c.post_id JOIN users u ON u.id=p.user_id
    WHERE c.id=$2 AND NOT c.removed AND ${POST_OK}`, [req.uid, req.params.id])).rows[0];
  if (!c) return bad(res, "This comment is not available.", 404);
  const on = req.body.like !== false;
  if (on) await db.query("INSERT INTO post_comment_likes(comment_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING", [c.id, req.uid]);
  else await db.query("DELETE FROM post_comment_likes WHERE comment_id=$1 AND user_id=$2", [c.id, req.uid]);
  const n = (await db.query("SELECT count(*)::int AS n FROM post_comment_likes WHERE comment_id=$1", [c.id])).rows[0].n;
  res.json({ liked: on, likes: n });
}));
// The photo of a comment (fetched when the comment is on screen).
app.get("/api/comments/:id/image", need, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const r = (await db.query(`SELECT c.image FROM post_comments c JOIN posts p ON p.id=c.post_id JOIN users u ON u.id=p.user_id
    WHERE c.id=$2 AND c.image IS NOT NULL AND NOT c.removed AND ${POST_OK}`, [req.uid, req.params.id])).rows[0];
  if (!r) return bad(res, "Not found.", 404);
  res.json({ image: r.image });
}));
// Test: sends one notification to every device this person turned notifications on for, and says what happened.
app.post("/api/push/test", need, wrap(async (req, res) => {
  if (!webpush) return bad(res, "Notifications are not set up on the server yet. Check the Render logs for 'Push notifications are on.'", 503);
  const subs = (await db.query("SELECT endpoint, p256dh, auth FROM push_subs WHERE user_id=$1", [req.uid])).rows;
  if (!subs.length) return res.json({ subscriptions: 0, sent: 0, failed: [], message: "This device is not subscribed. Turn notifications on first." });
  let sent = 0; const failed = [];
  for (const x of subs) {
    try {
      await webpush.sendNotification({ endpoint: x.endpoint, keys: { p256dh: x.p256dh, auth: x.auth } }, JSON.stringify({ title: "Orivoclass", body: "Test notification. It works!", tag: "test" }), { TTL: 300 });
      sent++;
    } catch (e) {
      failed.push(String(e.statusCode || e.message));
      if (e.statusCode === 404 || e.statusCode === 410) await db.query("DELETE FROM push_subs WHERE endpoint=$1", [x.endpoint]);
    }
  }
  res.json({ subscriptions: subs.length, sent, failed });
}));
// END OF PART 10

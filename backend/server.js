require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
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
app.use(helmet());
app.use(cors({ origin: FRONTEND_ORIGIN ? FRONTEND_ORIGIN.split(",") : false }));
app.use(express.json({ limit: "100kb" }));
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

app.get("/health", (req, res) => res.json({ service: "orivoclass-api", status: "ok" }));

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
  res.json({ request: r.rows[0] || null, notice: n.rows[0] || null });
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

// ---- Chats and messages ----
app.get("/api/chats", need, wrap(async (req, res) => {
  const r = await db.query(
    `WITH m AS (
       SELECT DISTINCT ON (peer) peer, id, body, from_id, created_at FROM (
         SELECT CASE WHEN from_id=$1 THEN to_id ELSE from_id END AS peer, id, CASE WHEN view_once THEN 'View once message' ELSE body END AS body, from_id, created_at
         FROM messages WHERE ((from_id=$1 AND NOT del_from) OR (to_id=$1 AND NOT del_to)) AND (expires_at IS NULL OR expires_at > now())
       ) x ORDER BY peer, id DESC)
     SELECT m.*, u.phone, u.last_seen, u.seen_privacy, COALESCE(NULLIF(c.alias,''), u.name) AS display,
            EXISTS (SELECT 1 FROM contacts k WHERE k.owner=m.peer AND k.contact=$1) AS theirs,
            COALESCE(p.pinned, false) AS pinned, COALESCE(p.archived, false) AS archived,
            EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=m.peer) OR (b.blocker=m.peer AND b.blocked=$1)) AS blk
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
    db.query("SELECT COALESCE(NULLIF(c.alias,''), u.name) AS n FROM users u LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE u.id=$1", [req.uid, req.body.to])
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
    `SELECT s.id, s.user_id, s.body, s.color, s.created_at, u.name,
            (SELECT count(*)::int FROM status_views v WHERE v.status_id=s.id AND s.user_id=$1) AS views
     FROM statuses s JOIN users u ON u.id = s.user_id
     WHERE s.created_at > now() - interval '24 hours'
       AND (s.user_id=$1 OR EXISTS (SELECT 1 FROM contacts c WHERE c.owner=s.user_id AND c.contact=$1))
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=s.user_id AND b.blocked=$1) OR (b.blocker=$1 AND b.blocked=s.user_id))
     ORDER BY s.created_at DESC`, [req.uid]);
  res.json({ status: r.rows });
}));

app.post("/api/status", need, wrap(async (req, res) => {
  const body = String(req.body.body || "").trim().slice(0, 140);
  const color = /^#[0-9a-f]{6}$/i.test(req.body.color || "") ? req.body.color : "#5A3FD6";
  if (!body) return bad(res, "Write something first.");
  await db.query("INSERT INTO statuses(user_id,body,color) VALUES($1,$2,$3)", [req.uid, body, color]);
  if (webpush) { // tell the people who can see it (fire and forget)
    const me = (await db.query("SELECT name FROM users WHERE id=$1", [req.uid])).rows[0];
    const to = await db.query("SELECT contact FROM contacts WHERE owner=$1 AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=contacts.contact) OR (b.blocker=contacts.contact AND b.blocked=$1))", [req.uid]);
    to.rows.forEach((r) => notify(r.contact, "status", { title: me.name, body: "posted a status", tag: "s" + req.uid }));
  }
  res.json({ ok: true });
}));

app.delete("/api/status/:id", need, wrap(async (req, res) => {
  await db.query("DELETE FROM statuses WHERE id=$1 AND user_id=$2", [req.params.id, req.uid]);
  res.json({ ok: true });
}));

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
app.post("/api/status/:id/view", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  const s = (await db.query(
    `SELECT s.id, s.user_id FROM statuses s WHERE s.id=$2 AND s.user_id<>$1 AND s.created_at > now() - interval '24 hours'
       AND EXISTS (SELECT 1 FROM contacts c WHERE c.owner=s.user_id AND c.contact=$1)
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=s.user_id AND b.blocked=$1) OR (b.blocker=$1 AND b.blocked=s.user_id))`, [req.uid, req.params.id])).rows[0];
  if (s) {
    const ins = await db.query("INSERT INTO status_views(status_id,viewer_id) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING status_id", [s.id, req.uid]);
    if (ins.rowCount && webpush) {
      const q = (await db.query("SELECT COALESCE(NULLIF(c.alias,''), u.name) AS n FROM users u LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE u.id=$1", [req.uid, s.user_id])).rows[0];
      notify(s.user_id, "views", { title: (q && q.n) || "Orivoclass", body: "viewed your status", tag: "v" + s.id });
    }
  }
  res.json({ ok: true });
}));
app.get("/api/status/:id/views", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  if (!(await db.query("SELECT 1 FROM statuses WHERE id=$1 AND user_id=$2", [req.params.id, req.uid])).rowCount) return bad(res, "Not found.", 404);
  const r = await db.query("SELECT u.id, COALESCE(NULLIF(c.alias,''), u.name) AS name, v.viewed_at FROM status_views v JOIN users u ON u.id=v.viewer_id LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE v.status_id=$1 ORDER BY v.viewed_at DESC", [req.params.id, req.uid]);
  res.json({ views: r.rows });
}));
setInterval(() => db.query("DELETE FROM statuses WHERE created_at < now() - interval '2 days'").catch(() => {}), 3600000); // views go with them

// ---- Notifications (web push) ----
async function notify(uid, kind, payload) {
  if (!webpush) return;
  try {
    const col = { msg: "n_msg", status: "n_status", views: "n_views" }[kind];
    const u = (await db.query(`SELECT ${col} AS enabled FROM users WHERE id=$1`, [uid])).rows[0];
    if (!u || !u.enabled) return;
    const subs = (await db.query("SELECT endpoint, p256dh, auth FROM push_subs WHERE user_id=$1", [uid])).rows;
    await Promise.all(subs.map(async (x) => {
      try { await webpush.sendNotification({ endpoint: x.endpoint, keys: { p256dh: x.p256dh, auth: x.auth } }, JSON.stringify(payload), { TTL: 3600 }); }
      catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await db.query("DELETE FROM push_subs WHERE endpoint=$1", [x.endpoint]); }
    }));
  } catch (e) { console.error("push:", e.message); }
}
app.get("/api/push/key", need, (req, res) => webpush ? res.json({ key: process.env.VAPID_PUBLIC }) : bad(res, "Notifications are not set up on the server yet.", 503));
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
  const u = (await db.query("SELECT n_msg, n_status, n_views FROM users WHERE id=$1", [req.uid])).rows[0];
  const d = req.sid ? (await db.query("SELECT 1 FROM push_subs WHERE session_id=$1", [req.sid])).rowCount > 0 : false;
  res.json({ available: !!webpush, msg: u.n_msg, status: u.n_status, views: u.n_views, this_device: d });
}));
app.put("/api/notifications", need, wrap(async (req, res) => {
  await db.query("UPDATE users SET n_msg=$2, n_status=$3, n_views=$4 WHERE id=$1", [req.uid, req.body.msg === true, req.body.status === true, req.body.views === true]);
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
  const g = (await db.query("SELECT id, name, ttl, created_at FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  const m = await db.query("SELECT u.id, COALESCE(NULLIF(c.alias,''), u.name) AS name, gm.role FROM group_members gm JOIN users u ON u.id=gm.user_id LEFT JOIN contacts c ON c.owner=$2 AND c.contact=u.id WHERE gm.group_id=$1 ORDER BY (gm.role='admin') DESC, gm.joined_at", [req.params.id, req.uid]);
  res.json({ ...g, role: me.role, members: m.rows });
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
  const g = (await db.query("SELECT ttl FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  res.json({ messages: r.rows, ttl: g ? g.ttl : 0 });
}));

app.post("/api/groups/:id/messages", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  if (!(await gMember(req.params.id, req.uid))) return bad(res, "You are not in this group.", 403);
  const body = String(req.body.body || "").trim().slice(0, 4000);
  const reply = req.body.reply ? String(req.body.reply).slice(0, 120) : null;
  if (!body) return bad(res, "Message is empty.");
  const g = (await db.query("SELECT name, ttl FROM chat_groups WHERE id=$1", [req.params.id])).rows[0];
  const r = await db.query("INSERT INTO group_messages(group_id,from_id,body,reply,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id", [req.params.id, req.uid, body, reply, g.ttl ? new Date(Date.now() + g.ttl * 1000) : null]);
  const me = (await db.query("SELECT name FROM users WHERE id=$1", [req.uid])).rows[0];
  notifyGroup(req.params.id, req.uid, g.name, me.name + " sent a message").catch(() => {}); // never the message text
  res.json({ id: r.rows[0].id });
}));

app.post("/api/groups/:id/members", need, groupLimit, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const me = await gMember(req.params.id, req.uid);
  if (!me || me.role !== "admin") return bad(res, "Only admins can add people.", 403);
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

app.post("/api/groups/:id/leave", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  await leaveGroup(req.params.id, req.uid, false);
  res.json({ ok: true });
}));

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
ALTER TABLE users ADD COLUMN IF NOT EXISTS mood text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS status_views(status_id bigint REFERENCES statuses(id) ON DELETE CASCADE, viewer_id uuid REFERENCES users(id) ON DELETE CASCADE, viewed_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(status_id,viewer_id));
CREATE TABLE IF NOT EXISTS push_subs(endpoint text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, session_id uuid REFERENCES sessions(id) ON DELETE CASCADE, p256dh text NOT NULL, auth text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS chat_groups(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, created_by uuid REFERENCES users(id) ON DELETE SET NULL, ttl int NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS group_members(group_id uuid REFERENCES chat_groups(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id) ON DELETE CASCADE, role text NOT NULL DEFAULT 'member', joined_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(group_id,user_id));
CREATE INDEX IF NOT EXISTS gm_user ON group_members(user_id);
CREATE TABLE IF NOT EXISTS group_messages(id bigserial PRIMARY KEY, group_id uuid NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE, from_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind text NOT NULL DEFAULT 'text', target_id uuid REFERENCES users(id) ON DELETE CASCADE, body text, reply text, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz);
CREATE INDEX IF NOT EXISTS gmsg_group ON group_messages(group_id,id);
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

require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
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
  try {
    req.uid = jwt.verify(h.replace(/^Bearer /, ""), JWT_SECRET).uid;
    db.query("UPDATE users SET last_seen=now() WHERE id=$1 AND (last_seen IS NULL OR last_seen < now() - interval '10 seconds')", [req.uid]).catch(() => {});
    next();
  } catch {
    res.status(401).json({ error: "Please log in again." });
  }
};
const isId = (s) => /^[0-9a-f-]{36}$/i.test(String(s || ""));
const pub = (u) => ({ id: u.id, name: u.name, phone: u.phone, about: u.about, seen_privacy: u.seen_privacy });
const sign = (u) => jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: "30d" });
const phoneOf = (p) => "+" + String(p || "").replace(/\D/g, "");
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

app.get("/health", (req, res) => res.json({ service: "belvia-api", status: "ok" }));

// ---- Auth ----
app.post("/api/signup", authLimit, wrap(async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 60);
  const phone = phoneOf(req.body.phone);
  const password = String(req.body.password || "");
  if (!name) return bad(res, "Please enter your name.");
  if (phone.length < 10 || phone.length > 16) return bad(res, "Enter a valid phone number.");
  if (password.length < 8) return bad(res, "Password must be at least 8 characters.");
  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await db.query(
      "INSERT INTO users(phone,name,pass_hash) VALUES($1,$2,$3) RETURNING *",
      [phone, name, hash]
    );
    res.json({ token: sign(r.rows[0]), user: pub(r.rows[0]) });
  } catch (e) {
    if (e.code === "23505") return bad(res, "This number is already registered.", 409);
    throw e;
  }
}));

app.post("/api/login", authLimit, wrap(async (req, res) => {
  const r = await db.query("SELECT * FROM users WHERE phone=$1", [phoneOf(req.body.phone)]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.pass_hash)))
    return bad(res, "Wrong number or password.", 401);
  res.json({ token: sign(u), user: pub(u) });
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
  const r = await db.query("UPDATE users SET name=$2, about=$3, seen_privacy=COALESCE($4, seen_privacy) WHERE id=$1 RETURNING *", [req.uid, name, about, sp]);
  res.json({ user: pub(r.rows[0]) });
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
  if (!u) return bad(res, "This number is not on Belvia yet.", 404);
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

// ---- Chats and messages ----
app.get("/api/chats", need, wrap(async (req, res) => {
  const r = await db.query(
    `WITH m AS (
       SELECT DISTINCT ON (peer) peer, id, body, from_id, created_at FROM (
         SELECT CASE WHEN from_id=$1 THEN to_id ELSE from_id END AS peer, id, CASE WHEN view_once THEN 'View once message' ELSE body END AS body, from_id, created_at
         FROM messages WHERE (from_id=$1 AND NOT del_from) OR (to_id=$1 AND NOT del_to)
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
       SELECT id, from_id, to_id, CASE WHEN view_once THEN NULL ELSE body END AS body, view_once, opened_at, forwarded, reply, reaction, read_at, created_at FROM messages
       WHERE (from_id=$1 AND to_id=$2 AND NOT del_from) OR (from_id=$2 AND to_id=$1 AND NOT del_to)
       ORDER BY id DESC LIMIT 200) t ORDER BY id`, [req.uid, req.params.peer]);
  res.json({ messages: r.rows });
}));

app.post("/api/messages", need, wrap(async (req, res) => {
  const body = String(req.body.body || "").trim().slice(0, 4000);
  const reply = req.body.reply ? String(req.body.reply).slice(0, 120) : null;
  if (!body) return bad(res, "Message is empty.");
  if (!isId(req.body.to) || req.body.to === req.uid) return bad(res, "Invalid recipient.");
  const ok = await db.query("SELECT 1 FROM users WHERE id=$1", [req.body.to]);
  if (!ok.rowCount) return bad(res, "Recipient not found.", 404);
  const bl = (await db.query("SELECT blocker FROM blocks WHERE (blocker=$1 AND blocked=$2) OR (blocker=$2 AND blocked=$1)", [req.uid, req.body.to])).rows;
  if (bl.some((x) => x.blocker === req.uid)) return bad(res, "Unblock this person to send messages.", 403);
  const hideFromThem = bl.length > 0; // if they blocked you, the message is saved for you but never delivered
  const r = await db.query(
    "INSERT INTO messages(from_id,to_id,body,reply,view_once,forwarded,del_to) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id",
    [req.uid, req.body.to, body, reply, !!req.body.once && !req.body.fwd, !!req.body.fwd, hideFromThem]);
  await db.query("UPDATE chat_prefs SET archived=false WHERE (owner=$1 AND peer=$2) OR (owner=$2 AND peer=$1)", [req.uid, req.body.to]);
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
  const note = String(req.body.note || "").trim().slice(0, 500);
  // Evidence: the last messages this person sent to the reporter. View once messages are never included.
  const m = await db.query(
    "SELECT id, body, created_at FROM messages WHERE from_id=$1 AND to_id=$2 AND NOT view_once AND NOT del_to ORDER BY id DESC LIMIT 5",
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
    `SELECT s.id, s.user_id, s.body, s.color, s.created_at, u.name
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
  res.json({ ok: true });
}));

app.delete("/api/status/:id", need, wrap(async (req, res) => {
  await db.query("DELETE FROM statuses WHERE id=$1 AND user_id=$2", [req.params.id, req.uid]);
  res.json({ ok: true });
}));

const schema = `
CREATE TABLE IF NOT EXISTS users(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), phone text UNIQUE NOT NULL, name text NOT NULL, about text NOT NULL DEFAULT 'Hey there! I am using Belvia.', pass_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS contacts(owner uuid REFERENCES users(id) ON DELETE CASCADE, contact uuid REFERENCES users(id) ON DELETE CASCADE, alias text, PRIMARY KEY(owner,contact));
CREATE TABLE IF NOT EXISTS messages(id bigserial PRIMARY KEY, from_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, to_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, body text NOT NULL, reply text, reaction text, del_from boolean NOT NULL DEFAULT false, del_to boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS msg_pair ON messages(from_id,to_id,id);
CREATE TABLE IF NOT EXISTS statuses(id bigserial PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, body text NOT NULL, color text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS seen_privacy text NOT NULL DEFAULT 'everyone';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at timestamptz;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS view_once boolean NOT NULL DEFAULT false;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS opened_at timestamptz;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS forwarded boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS blocks(blocker uuid REFERENCES users(id) ON DELETE CASCADE, blocked uuid REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(blocker,blocked));
CREATE TABLE IF NOT EXISTS reports(id bigserial PRIMARY KEY, reporter uuid REFERENCES users(id) ON DELETE CASCADE, reported uuid REFERENCES users(id) ON DELETE CASCADE, reason text NOT NULL, note text, evidence jsonb, status text NOT NULL DEFAULT 'open', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS chat_prefs(owner uuid REFERENCES users(id) ON DELETE CASCADE, peer uuid REFERENCES users(id) ON DELETE CASCADE, pinned boolean NOT NULL DEFAULT false, archived boolean NOT NULL DEFAULT false, PRIMARY KEY(owner,peer));`;

db.query(schema)
  .then(() => app.listen(Number(process.env.PORT) || 3000, () => console.log("Belvia API running")))
  .catch((e) => { console.error("Database setup failed:", e.message); process.exit(1); });

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
  const rs = (await db.query("SELECT id, user_id FROM account_resets WHERE phone=$1 AND expires_at > now()", [phone])).rows[0];
  if (rs && req.body.restore === undefined) return res.json({ restore_available: true }); // ask the person first
  try {
    let r;
    if (rs && req.body.restore === true) { // keep the old chats, contacts and posts; only the login details are new
      r = await db.query("UPDATE users SET phone=$2, name=$3, pass_hash=$4, recovery_hash=$5 WHERE id=$1 RETURNING *", [rs.user_id, phone, name, hash, hashCode(code)]);
      await db.query("DELETE FROM account_resets WHERE id=$1", [rs.id]);
    } else {
      if (rs) { await db.query("DELETE FROM users WHERE id=$1", [rs.user_id]); await db.query("DELETE FROM account_resets WHERE id=$1", [rs.id]); } // start fresh
      r = await db.query(
        "INSERT INTO users(phone,name,pass_hash,recovery_hash) VALUES($1,$2,$3,$4) RETURNING *",
        [phone, name, hash, hashCode(code)]
      );
    }
    await db.query("DELETE FROM otps WHERE phone=$1", [phone]);
    await trustDevice(r.rows[0].id, cleanDev(req.body.device), deviceName(req));
    res.json({ ...(await newSession(r.rows[0], req)), recovery_code: code });
  } catch (e) {
    if (e.code === "23505") return bad(res, "This number is already registered.", 409);
    throw e;
  }
}));

const pollLimit = rateLimit({ windowMs: 60000, max: 90 });
const sha = (x) => crypto.createHash("sha256").update(String(x || "")).digest("hex");

// Only the phone that opened the account (the first trusted device) can approve a new device.
// Sessions made before devices were remembered count as approved (they cannot be checked).
async function canApprove(uid, sid) {
  const first = (await db.query("SELECT device_id FROM trusted_devices WHERE user_id=$1 ORDER BY created_at LIMIT 1", [uid])).rows[0];
  if (!first) return true;
  const s = (await db.query("SELECT device_id FROM sessions WHERE id=$1 AND user_id=$2", [sid, uid])).rows[0];
  if (!s) return false;
  return !s.device_id || s.device_id === first.device_id;
}
const cleanDev = (v) => String(v || "").replace(/[^A-Za-z0-9-]/g, "").slice(0, 80);
async function trustDevice(uid, dev, name) {
  if (!dev) return;
  await db.query("INSERT INTO trusted_devices(user_id,device_id,name) VALUES($1,$2,$3) ON CONFLICT (user_id,device_id) DO UPDATE SET last_used=now(), name=EXCLUDED.name", [uid, dev, name || ""]);
}
app.post("/api/login", authLimit, wrap(async (req, res) => {
  const r = await db.query("SELECT * FROM users WHERE phone=$1", [phoneOf(req.body.phone)]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.pass_hash)))
    return bad(res, "Wrong number or password.", 401);
  const lm = await lockMsg(u);
  if (lm) return res.status(403).json({ error: lm, appeal: true });
  const dev = cleanDev(req.body.device);
  // A device that is already known (any tab of this browser, or a phone used before) signs in without approval.
  if (dev && (await db.query("SELECT 1 FROM trusted_devices WHERE user_id=$1 AND device_id=$2", [u.id, dev])).rowCount) {
    await db.query("UPDATE trusted_devices SET last_used=now() WHERE user_id=$1 AND device_id=$2", [u.id, dev]);
    return res.json(await newSession(u, req));
  }
  // A new device: if the account has no other device signed in, it is simply the first one.
  const active = await db.query("SELECT 1 FROM sessions WHERE user_id=$1 AND last_seen > now() - interval '30 days' LIMIT 1", [u.id]);
  if (!active.rowCount) { await trustDevice(u.id, dev, deviceName(req)); return res.json(await newSession(u, req)); }
  if ((await db.query("SELECT 1 FROM login_requests WHERE user_id=$1 AND status='denied' AND created_at > now() - interval '1 hour'", [u.id])).rowCount)
    return bad(res, "A login to this account was blocked by its owner. Try again later, or use your recovery code.", 403);
  const many = await db.query("SELECT count(*)::int AS n FROM login_requests WHERE user_id=$1 AND created_at > now() - interval '1 hour'", [u.id]);
  if (many.rows[0].n >= 3) return bad(res, "Too many login requests for this account. Try again later.", 429);
  const secret = crypto.randomBytes(24).toString("hex");
  // Phones are approved with Yes / No. A computer also gets an 8-digit code, which the approving phone types in to link it.
  const isComputer = /^(Windows|Mac|Linux)/.test(deviceName(req));
  const code = isComputer ? String(crypto.randomInt(0, 100000000)).padStart(8, "0") : null;
  const q = await db.query("INSERT INTO login_requests(user_id,secret_hash,device,expires_at,device_id,code) VALUES($1,$2,$3,now()+interval '5 minutes',$4,$5) RETURNING id", [u.id, sha(secret), deviceName(req), dev, code]);
  res.json({ pending: true, request_id: q.rows[0].id, secret, code, computer: isComputer, expires_in: 300 });
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
    await trustDevice(u.id, r.device_id, r.device);
    return res.json({ status: "approved", ...(await newSession(u, req, r.device_id || null)) });
  }
  res.json({ status: r.status });
}));

// The owner's logged-in device checks for waiting requests and answers them.
app.get("/api/login-requests", need, wrap(async (req, res) => {
  if (!(await canApprove(req.uid, req.sid))) return res.json({ request: null, notice: null, call: null, can_approve: false });
  const r = await db.query("SELECT id, device, created_at, code FROM login_requests WHERE user_id=$1 AND status='pending' AND expires_at > now() ORDER BY created_at DESC LIMIT 1", [req.uid]);
  const n = await db.query("SELECT id, kind, reason, until, created_at FROM sanctions WHERE user_id=$1 AND seen=false AND kind IN ('warning','restriction') ORDER BY id LIMIT 1", [req.uid]);
  await expireCalls();
  const cl = await db.query(`SELECT c.id, c.kind, c.caller AS from_id, COALESCE(NULLIF(k.alias,''), u.name) AS name FROM calls c JOIN users u ON u.id=c.caller LEFT JOIN contacts k ON k.owner=$1 AND k.contact=c.caller WHERE c.callee=$1 AND c.status='ringing' ORDER BY c.created_at DESC LIMIT 1`, [req.uid]);
  res.json({ request: r.rows[0] || null, notice: n.rows[0] || null, call: cl.rows[0] || null });
}));
app.post("/api/login-requests/:id/answer", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  if (!(await canApprove(req.uid, req.sid))) return bad(res, "Only the phone that opened this account can approve a new device.", 403);
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
  await trustDevice(u.id, cleanDev(req.body.device), deviceName(req));
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

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
    `SELECT s.id, s.user_id FROM statuses s JOIN users su ON su.id=s.user_id WHERE s.id=$2 AND s.user_id<>$1 AND s.created_at > now() - interval '24 hours'
       AND ${STATUS_VIS}`, [req.uid, req.params.id])).rows[0];
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

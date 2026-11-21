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
  try { await db.query("SELECT 1 FROM app_settings LIMIT 1"); await db.query("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_id text"); await setupPush(); }
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
// Mark a chat as unread: the last message from that person counts as unread again.
app.post("/api/chats/:peer/unread", need, wrap(async (req, res) => {
  if (!isId(req.params.peer)) return bad(res, "Invalid id.");
  await db.query("UPDATE messages SET read_at=NULL WHERE id=(SELECT id FROM messages WHERE from_id=$2 AND to_id=$1 ORDER BY id DESC LIMIT 1)", [req.uid, req.params.peer.toLowerCase()]);
  res.json({ ok: true });
}));
// Delete a message for me only (the other person still has it).
app.post("/api/messages/:id/hide", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  await db.query("INSERT INTO message_hidden(message_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING", [req.params.id, req.uid]);
  res.json({ ok: true });
}));
// ---- Admin: help someone who forgot their password or recovery code ----
// Finds an account by phone number. Never shows the password or the recovery code; a new code is shown once.
app.get("/api/admin/accounts", adminLimit, adminOnly, wrap(async (req, res) => {
  const ph = phoneOf(req.query.phone);
  if (ph.length < 10) return bad(res, "Enter the full phone number, with the country code.");
  const u = (await db.query("SELECT id, name, phone, trust_score, banned, rest_until, restricted_until, created_at FROM users WHERE phone=$1", [ph])).rows[0];
  if (!u) return bad(res, "No account uses this number.", 404);
  const s = (await db.query("SELECT count(*)::int AS n FROM sessions WHERE user_id=$1", [u.id])).rows[0].n;
  res.json({ account: { id: u.id, name: u.name, phone: u.phone, trust: u.trust_score, banned: u.banned, created_at: u.created_at, devices: s } });
}));
// New recovery code for this account. Every device is signed out, so the old code and any old login stop working.
app.post("/api/admin/accounts/recovery-code", adminLimit, adminOnly, wrap(async (req, res) => {
  const u = (await db.query("SELECT id FROM users WHERE phone=$1", [phoneOf(req.body.phone)])).rows[0];
  if (!u) return bad(res, "No account uses this number.", 404);
  const code = makeCode();
  await db.query("UPDATE users SET recovery_hash=$2 WHERE id=$1", [u.id, hashCode(code)]);
  await db.query("DELETE FROM sessions WHERE user_id=$1", [u.id]);
  res.json({ recovery_code: code });
}));
// A new password set by the admin. The person should change it after logging in. All devices are signed out.
app.post("/api/admin/accounts/password", adminLimit, adminOnly, wrap(async (req, res) => {
  const password = String(req.body.password || "");
  if (password.length < 8) return bad(res, "The new password needs at least 8 characters.");
  const u = (await db.query("SELECT id FROM users WHERE phone=$1", [phoneOf(req.body.phone)])).rows[0];
  if (!u) return bad(res, "No account uses this number.", 404);
  await db.query("UPDATE users SET pass_hash=$2 WHERE id=$1", [u.id, await bcrypt.hash(password, 10)]);
  await db.query("DELETE FROM sessions WHERE user_id=$1", [u.id]);
  res.json({ ok: true });
}));
// Link a new device: the phone that opened the account types the 8-digit code shown on the new device.
app.post("/api/login-requests/approve-code", need, wrap(async (req, res) => {
  const code = String(req.body.code || "").replace(/\D/g, "");
  if (code.length !== 8) return bad(res, "Enter the 8-digit code.");
  if (!(await canApprove(req.uid, req.sid))) return bad(res, "Only the phone that opened this account can link a new device.", 403);
  const r = await db.query("UPDATE login_requests SET status='approved' WHERE user_id=$1 AND code=$2 AND status='pending' AND expires_at > now() RETURNING id", [req.uid, code]);
  if (!r.rowCount) return bad(res, "This code is wrong or has expired. Ask for a new one on the new device.", 404);
  res.json({ ok: true });
}));
// ---- Link a computer with a code (like WhatsApp Web) ----
// The computer asks for a code and shows it. The person types that code in the app on their phone (Me > Linked devices).
const LINK_ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const makeLinkCode = () => { const b = crypto.randomBytes(8); let s = ""; for (let i = 0; i < 8; i++) s += LINK_ALPHA[b[i] % LINK_ALPHA.length]; return s; };
const normLink = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const linkStart = rateLimit({ windowMs: 15 * 60000, max: 200, keyGenerator: (req) => req.ip || "x" });
const linkPoll = rateLimit({ windowMs: 15 * 60000, max: 3000, keyGenerator: (req) => String(req.body && req.body.id || req.ip) });
const linkApprove = rateLimit({ windowMs: 10 * 60000, max: 30, keyGenerator: (req) => String(req.uid) });
app.post("/api/link/start", linkStart, wrap(async (req, res) => {
  const code = makeLinkCode(), secret = crypto.randomBytes(24).toString("hex");
  const r = await db.query("INSERT INTO link_codes(code_hash,secret_hash,device,expires_at) VALUES($1,$2,$3, now() + interval '3 minutes') RETURNING id",
    [sha(code), sha(secret), deviceName(req)]);
  res.json({ id: r.rows[0].id, secret, code: code.slice(0, 4) + "-" + code.slice(4) });
}));
app.post("/api/link/status", linkPoll, wrap(async (req, res) => {
  if (!isId(req.body.id)) return bad(res, "Code not found.", 404);
  const r = (await db.query("SELECT * FROM link_codes WHERE id=$1", [req.body.id])).rows[0];
  if (!r || r.secret_hash !== sha(req.body.secret)) return bad(res, "Code not found.", 404);
  if (r.status === "pending" && new Date(r.expires_at) < new Date()) return res.json({ status: "expired" });
  if (r.status === "approved") {
    const used = await db.query("UPDATE link_codes SET status='used' WHERE id=$1 AND status='approved' RETURNING user_id", [r.id]);
    if (!used.rowCount) return res.json({ status: "used" });
    const u = (await db.query("SELECT * FROM users WHERE id=$1", [used.rows[0].user_id])).rows[0];
    if (!u) return res.json({ status: "expired" });
    return res.json({ status: "approved", ...(await newSession(u, req)) });
  }
  res.json({ status: r.status === "pending" ? "pending" : "expired" });
}));
// On the phone: type the code shown on the computer.
app.post("/api/link/approve", need, linkApprove, wrap(async (req, res) => {
  const code = normLink(req.body.code);
  if (code.length !== 8) return bad(res, "Enter the 8-character code shown on the computer.");
  const me = (await db.query("SELECT * FROM users WHERE id=$1", [req.uid])).rows[0];
  const lm = me ? await lockMsg(me) : null;
  if (lm) return bad(res, lm, 403);
  const r = await db.query("UPDATE link_codes SET status='approved', user_id=$2 WHERE code_hash=$1 AND status='pending' AND expires_at > now() RETURNING id", [sha(code), req.uid]);
  if (!r.rowCount) return bad(res, "This code is wrong or has expired. Refresh the code on the computer and try again.", 404);
  res.json({ ok: true });
}));
setInterval(() => db.query("DELETE FROM link_codes WHERE created_at < now() - interval '1 day'").catch(() => {}), 3600000);
// Admin: reset an account (number and password are removed, everything else stays). The person can restore it when they register again.
app.post("/api/admin/users/reset", adminLimit, adminOnly, wrap(async (req, res) => {
  const phone = phoneOf(req.body.phone);
  const u = (await db.query("SELECT id FROM users WHERE phone=$1", [phone])).rows[0];
  if (!u) return bad(res, "No account with this number.", 404);
  await db.query("DELETE FROM sessions WHERE user_id=$1", [u.id]);
  await db.query("DELETE FROM login_requests WHERE user_id=$1", [u.id]);
  await db.query("DELETE FROM account_resets WHERE user_id=$1", [u.id]);
  await db.query("INSERT INTO account_resets(user_id,phone,expires_at) VALUES($1,$2, now() + interval '30 days')", [u.id, phone]);
  const junk = await bcrypt.hash(crypto.randomBytes(24).toString("hex"), 10);
  await db.query("UPDATE users SET phone=$2, pass_hash=$3, recovery_hash=NULL WHERE id=$1", [u.id, "reset:" + u.id, junk]);
  res.json({ ok: true });
}));
// END OF PART 10

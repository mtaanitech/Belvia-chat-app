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
// Repost: shares someone's public post to your own profile (one repost per post).
app.post("/api/posts/:id/repost", need, postLimit, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  if (await isRestricted(req.uid)) return bad(res, "Your account is restricted, so you cannot repost for now.", 403);
  const p = await visiblePost(req.uid, req.params.id);
  if (!p) return bad(res, "This post is not available.", 404);
  if (p.user_id === req.uid) return bad(res, "This is already your post.");
  const o = (await db.query("SELECT audience FROM posts WHERE id=$1", [p.id])).rows[0];
  if (!o || o.audience !== "public") return bad(res, "Only public posts can be reposted.", 403);
  if ((await db.query("SELECT 1 FROM posts WHERE user_id=$1 AND repost_of=$2 AND NOT removed", [req.uid, p.id])).rowCount) return res.json({ ok: true, already: true });
  await db.query("INSERT INTO posts(user_id,body,audience,repost_of) VALUES($1,'','public',$2)", [req.uid, p.id]);
  res.json({ ok: true });
}));
// ---- Status: who can see my status (everyone who saved me, all except some, or only some) ----
// Visibility rule for viewer $1 and status s (owner su):
const STATUS_VIS = `(s.user_id=$1 OR (NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=s.user_id AND b.blocked=$1) OR (b.blocker=$1 AND b.blocked=s.user_id))
  AND ((su.status_mode='contacts' AND EXISTS (SELECT 1 FROM contacts c WHERE c.owner=s.user_id AND c.contact=$1))
    OR (su.status_mode='except' AND EXISTS (SELECT 1 FROM contacts c WHERE c.owner=s.user_id AND c.contact=$1)
        AND NOT EXISTS (SELECT 1 FROM status_list l WHERE l.owner=s.user_id AND l.person=$1 AND l.kind='hide'))
    OR (su.status_mode='only' AND EXISTS (SELECT 1 FROM status_list l WHERE l.owner=s.user_id AND l.person=$1 AND l.kind='only')))))`;
// All statuses from the last 24 hours that this person may see, oldest first (so each person's stories play in order).
app.get("/api/status/feed", need, wrap(async (req, res) => {
  const r = await db.query(
    `SELECT s.id, s.user_id, s.body, s.color, s.created_at, (s.image IS NOT NULL) AS has_image,
       COALESCE(NULLIF(k.alias,''), su.name) AS name,
       EXISTS (SELECT 1 FROM status_views v WHERE v.status_id=s.id AND v.viewer_id=$1) AS seen,
       (SELECT count(*)::int FROM status_views v WHERE v.status_id=s.id) AS views
     FROM statuses s JOIN users su ON su.id=s.user_id LEFT JOIN contacts k ON k.owner=$1 AND k.contact=s.user_id
     WHERE s.created_at > now() - interval '24 hours' AND ${STATUS_VIS}
     ORDER BY s.created_at ASC`, [req.uid]);
  res.json({ status: r.rows });
}));
// The picture of one status (only if this person may see it).
app.get("/api/status/:id/photo", need, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const r = (await db.query(
    `SELECT s.image FROM statuses s JOIN users su ON su.id=s.user_id
     WHERE s.id=$2 AND s.image IS NOT NULL AND s.created_at > now() - interval '24 hours' AND ${STATUS_VIS}`, [req.uid, req.params.id])).rows[0];
  if (!r) return bad(res, "Not found.", 404);
  res.json({ image: r.image });
}));
app.get("/api/me/status-privacy", need, wrap(async (req, res) => {
  const u = (await db.query("SELECT status_mode FROM users WHERE id=$1", [req.uid])).rows[0];
  const mode = u ? u.status_mode : "contacts";
  const kind = mode === "except" ? "hide" : mode === "only" ? "only" : null;
  const l = kind ? (await db.query("SELECT person FROM status_list WHERE owner=$1 AND kind=$2", [req.uid, kind])).rows.map((x) => x.person) : [];
  res.json({ mode, list: l });
}));
app.put("/api/me/status-privacy", need, wrap(async (req, res) => {
  const mode = ["contacts", "except", "only"].includes(req.body.mode) ? req.body.mode : "contacts";
  const kind = mode === "except" ? "hide" : mode === "only" ? "only" : null;
  await db.query("UPDATE users SET status_mode=$2 WHERE id=$1", [req.uid, mode]);
  await db.query("DELETE FROM status_list WHERE owner=$1", [req.uid]);
  if (kind) {
    const ids = (Array.isArray(req.body.list) ? req.body.list : []).filter(isId).map((x) => x.toLowerCase()).slice(0, 500);
    for (const id of ids) if (id !== req.uid) await db.query("INSERT INTO status_list(owner,person,kind) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", [req.uid, id, kind]);
  }
  res.json({ ok: true, mode });
}));
// Countries: a country is on unless the admin turns it off.
async function countryOff(iso) {
  const c = String(iso || "").toUpperCase(); if (!c) return false;
  try { const r = await db.query("SELECT value FROM app_settings WHERE key='countries'"); return !!(r.rows[0] && r.rows[0].value[c] === false); }
  catch (e) { return false; }
}
// Admin: list countries with their status and how many accounts each has.
app.get("/api/admin/countries", adminLimit, adminOnly, wrap(async (req, res) => {
  const s = (await db.query("SELECT value FROM app_settings WHERE key='countries'")).rows[0];
  const app = (await db.query("SELECT value FROM app_settings WHERE key='app'")).rows[0];
  const counts = (await db.query("SELECT country, count(*)::int AS n FROM users WHERE country IS NOT NULL GROUP BY country")).rows;
  res.json({ app_on: !app || app.value.on !== false, off: s ? Object.keys(s.value).filter((k) => s.value[k] === false) : [], counts });
}));
app.put("/api/admin/countries", adminLimit, adminOnly, wrap(async (req, res) => {
  const c = String(req.body.code || "").toUpperCase().slice(0, 2);
  if (!/^[A-Z]{2}$/.test(c)) return bad(res, "Invalid country.");
  const cur = (await db.query("SELECT value FROM app_settings WHERE key='countries'")).rows[0];
  const val = cur ? cur.value : {};
  if (req.body.enabled === false) val[c] = false; else delete val[c];
  await db.query("INSERT INTO app_settings(key,value,updated_at) VALUES('countries',$1,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()", [JSON.stringify(val)]);
  res.json({ ok: true });
}));
app.put("/api/admin/app", adminLimit, adminOnly, wrap(async (req, res) => {
  const on = req.body.on !== false;
  await db.query("INSERT INTO app_settings(key,value,updated_at) VALUES('app',$1,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()", [JSON.stringify({ on })]);
  APPFLAG.at = 0;
  res.json({ ok: true, on });
}));
// ---- End-to-end encryption, step 1: each device publishes ONLY its public key. The private key never leaves the device. ----
app.put("/api/keys/device", need, wrap(async (req, res) => {
  const dev = String(req.body.device_id || "").slice(0, 64);
  const pub = req.body.pub || {};
  if (!dev || pub.kty !== "EC" || pub.crv !== "P-256" || typeof pub.x !== "string" || typeof pub.y !== "string" || pub.x.length > 100 || pub.y.length > 100) return bad(res, "Invalid key.");
  await db.query("INSERT INTO device_keys(user_id,device_id,pub) VALUES($1,$2,$3) ON CONFLICT (user_id,device_id) DO UPDATE SET pub=EXCLUDED.pub",
    [req.uid, dev, JSON.stringify({ kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y })]);
  res.json({ ok: true });
}));
app.get("/api/keys/:uid", need, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  const who = req.params.uid.toLowerCase();
  if (await sgBlocked(req.uid, who)) return bad(res, "Not available.", 403);
  const r = await db.query("SELECT device_id, pub FROM device_keys WHERE user_id=$1", [who]);
  res.json({ devices: r.rows });
}));
// Message-key backup: a blob that only the person's PIN can open. The server never sees the PIN or the key.
app.put("/api/keys/backup", need, wrap(async (req, res) => {
  const b = String(req.body.blob || "");
  if (!b || b.length > 20000) return bad(res, "Backup is empty or too large.");
  await db.query("INSERT INTO key_backups(user_id,blob) VALUES($1,$2) ON CONFLICT (user_id) DO UPDATE SET blob=EXCLUDED.blob, updated_at=now()", [req.uid, b]);
  res.json({ ok: true });
}));
app.get("/api/keys/backup", need, wrap(async (req, res) => {
  const r = (await db.query("SELECT blob FROM key_backups WHERE user_id=$1", [req.uid])).rows[0];
  res.json({ blob: r ? r.blob : null });
}));
// ---- Singles lists: Nearby (same town, as the profile says), and who liked me / who I liked. No photos here until a match. ----
const SG_CARD = `s.user_id, s.nick, s.gender, s.town, s.bio, s.photo, date_part('year', age(s.birth_date))::int AS age, to_char(u.created_at, 'Mon YYYY') AS joined, u.last_seen`;
const NOT_MATCHED = (me) => `NOT EXISTS (SELECT 1 FROM singles_matches mt WHERE (mt.a=${me} AND mt.b=s.user_id) OR (mt.a=s.user_id AND mt.b=${me}))`;
app.get("/api/singles/nearby", need, wrap(async (req, res) => {
  const me = (await db.query("SELECT town FROM singles WHERE user_id=$1", [req.uid])).rows[0];
  if (!me || !me.town) return res.json({ profiles: [], note: "Add your town in your Singles profile to see people near you." });
  const r = await db.query(
    `SELECT ${SG_CARD} FROM singles s JOIN users u ON u.id=s.user_id
     WHERE s.user_id<>$1 AND s.active AND NOT u.banned AND lower(s.town)=lower($2)
       AND NOT EXISTS (SELECT 1 FROM singles_likes l WHERE l.liker=$1 AND l.liked=s.user_id)
       AND NOT EXISTS (SELECT 1 FROM singles_passes p WHERE p.user_id=$1 AND p.profile=s.user_id)
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=s.user_id) OR (b.blocker=s.user_id AND b.blocked=$1))
       AND ${NOT_MATCHED("$1")}
     ORDER BY random() LIMIT 30`, [req.uid, me.town]);
  res.json({ profiles: r.rows });
}));
app.get("/api/singles/likes", need, wrap(async (req, res) => {
  const liked_you = await db.query(
    `SELECT ${SG_CARD}, l.created_at FROM singles_likes l JOIN singles s ON s.user_id=l.liker JOIN users u ON u.id=s.user_id
     WHERE l.liked=$1 AND NOT u.banned AND s.active AND ${NOT_MATCHED("$1")}
       AND NOT EXISTS (SELECT 1 FROM singles_passes p WHERE p.user_id=$1 AND p.profile=s.user_id)
     ORDER BY l.created_at DESC LIMIT 100`, [req.uid]);
  const you_liked = await db.query(
    `SELECT ${SG_CARD}, l.created_at FROM singles_likes l JOIN singles s ON s.user_id=l.liked JOIN users u ON u.id=s.user_id
     WHERE l.liker=$1 AND NOT u.banned AND ${NOT_MATCHED("$1")}
     ORDER BY l.created_at DESC LIMIT 100`, [req.uid]);
  res.json({ liked_you: liked_you.rows, you_liked: you_liked.rows });
}));
// Edit my own post (its text), and edit my own message.
app.put("/api/posts/:id/edit", need, wrap(async (req, res) => {
  if (!numId(req.params.id)) return bad(res, "Invalid id.");
  const body = String(req.body.body || "").trim().slice(0, 500);
  if (!body) return bad(res, "Write something first.");
  const r = await db.query("UPDATE posts SET body=$3, edited=true WHERE id=$1 AND user_id=$2 AND NOT removed RETURNING id", [req.params.id, req.uid, body]);
  if (!r.rowCount) return bad(res, "You can only edit your own posts.", 403);
  res.json({ ok: true });
}));
app.put("/api/messages/:id/edit", need, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return bad(res, "Invalid id.");
  const raw = String(req.body.body || "").trim();
  const body = raw.startsWith("e2e1:") ? raw.slice(0, 40000) : raw.slice(0, 4000);
  if (!body) return bad(res, "Write something first.");
  const r = await db.query("UPDATE messages SET body=$2, edited=true WHERE id=$1 AND from_id=$3 RETURNING id", [req.params.id, body, req.uid]);
  if (!r.rowCount) return bad(res, "You can only edit your own messages.", 403);
  res.json({ ok: true });
}));
// ---- Verified badge (subscription) ----
const VERIFY_DEFAULT = { price: 300, days: 30 };
async function verifyPlan() {
  const r = await db.query("SELECT value FROM app_settings WHERE key='verify_plan'");
  return r.rows[0] ? r.rows[0].value : VERIFY_DEFAULT;
}
const VPLANS = { trialDays: 30, cardWaitMin: 30, applyFee: 3, recurring: { price: 80, days: 45 }, prepaid: [{ id: "7m", label: "7 months", price: 200, days: 210 }, { id: "1y", label: "1 year", price: 700, days: 365 }] };
app.get("/api/verify/plan", need, wrap(async (req, res) => {
  const me = (await db.query("SELECT verified_until, verified_from, trial_used, verify_renew FROM users WHERE id=$1", [req.uid])).rows[0] || {};
  res.json({ paid: !!process.env.PAYSTACK_SECRET_KEY, plans: VPLANS, until: me.verified_until, from: me.verified_from, trial_used: !!me.trial_used, auto: !!me.verify_renew });
}));
// Free trial: fill in the application form and pay KSh 3 to send it. Approved automatically 30 minutes later.
app.post("/api/verify/trial", need, boostLimit, wrap(async (req, res) => {
  if (!process.env.PAYSTACK_SECRET_KEY) return bad(res, "Payments are not set up yet.", 503);
  const me = (await db.query("SELECT trial_used FROM users WHERE id=$1", [req.uid])).rows[0];
  if (me && me.trial_used) return bad(res, "You have already used the free trial.", 403);
  const name = String(req.body.name || "").trim().slice(0, 80);
  const reason = String(req.body.reason || "").trim().slice(0, 400);
  const contact = String(req.body.contact || "").trim().slice(0, 120);
  if (name.length < 3) return bad(res, "Write your full name.");
  if (reason.length < 10) return bad(res, "Write why you want the badge (at least 10 letters).");
  const ref = "APP" + crypto.randomBytes(9).toString("hex");
  await db.query("INSERT INTO verify_orders(reference,user_id,amount,days,status,kind,plan) VALUES($1,$2,$3,$4,'pending','apply','trial')", [ref, req.uid, VPLANS.applyFee, VPLANS.trialDays]);
  await db.query("INSERT INTO verify_apps(reference,user_id,full_name,reason,contact) VALUES($1,$2,$3,$4,$5)", [ref, req.uid, name, reason, contact]);
  const email = "u" + req.uid.replace(/-/g, "").slice(0, 16) + "@orivoclass.app";
  const r = await paystack("POST", "/transaction/initialize", { email, amount: VPLANS.applyFee * 100, currency: "KES", reference: ref, callback_url: APP_URL, metadata: { kind: "verify_apply" } });
  if (!r.ok || !r.json.status) return bad(res, "Could not send your application. Try again.", 502);
  res.json({ reference: ref, authorization_url: r.json.data.authorization_url });
}));
// Paid plans: recurring (KSh 80 every 45 days, renews automatically), or prepaid 7 months / 1 year.
app.post("/api/verify/buy", need, boostLimit, wrap(async (req, res) => {
  if (!process.env.PAYSTACK_SECRET_KEY) return bad(res, "Payments are not set up yet.", 503);
  const plan = String(req.body.plan || "");
  let amount, days;
  if (plan === "recurring") { amount = VPLANS.recurring.price; days = VPLANS.recurring.days; }
  else { const p = VPLANS.prepaid.find((x) => x.id === plan); if (!p) return bad(res, "Choose a plan."); amount = p.price; days = p.days; }
  const ref = "VER" + crypto.randomBytes(9).toString("hex");
  await db.query("INSERT INTO verify_orders(reference,user_id,amount,days,status,kind,plan) VALUES($1,$2,$3,$4,'pending','plan',$5)", [ref, req.uid, amount, days, plan]);
  const email = "u" + req.uid.replace(/-/g, "").slice(0, 16) + "@orivoclass.app";
  const r = await paystack("POST", "/transaction/initialize", { email, amount: amount * 100, currency: "KES", reference: ref, callback_url: APP_URL, metadata: { kind: "verify", plan } });
  if (!r.ok || !r.json.status) return bad(res, "Could not start the payment. Try again.", 502);
  res.json({ reference: ref, authorization_url: r.json.data.authorization_url });
}));
// After Paystack confirms the money, the badge is switched on (once per payment).
app.post("/api/verify/confirm", need, wrap(async (req, res) => {
  const ref = String(req.body.reference || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 40);
  const o = (await db.query("SELECT * FROM verify_orders WHERE reference=$1 AND user_id=$2", [ref, req.uid])).rows[0];
  if (!o) return bad(res, "Payment not found.", 404);
  if (o.status === "paid") return res.json({ ok: true, status: "paid" });
  const r = await paystack("GET", "/transaction/verify/" + ref);
  const d = (r.json && r.json.data) || {};
  if (!r.ok || d.status !== "success") return res.json({ ok: false, status: d.status || "pending" });
  if (Number(d.amount) !== o.amount * 100 || d.currency !== "KES") { await db.query("UPDATE verify_orders SET status='mismatch' WHERE reference=$1", [ref]); return bad(res, "The payment does not match.", 400); }
  const done = await db.query("UPDATE verify_orders SET status='paid' WHERE reference=$1 AND status<>'paid' RETURNING reference", [ref]);
  if (!done.rowCount) return res.json({ ok: true, status: "paid" });
  const auth = d.authorization && d.authorization.reusable ? d.authorization.authorization_code : null;
  if (o.kind === "apply") {
    await db.query(`UPDATE users SET trial_used=true, verify_renew=false, verified_from = now() + make_interval(mins => $2),
      verified_until = now() + make_interval(mins => $2) + make_interval(days => $3) WHERE id=$1`,
      [req.uid, VPLANS.cardWaitMin, o.days]);
  } else if (o.plan === "recurring") {
    // paid by hand each time, no card is kept
    await db.query("UPDATE users SET verified_until = GREATEST(COALESCE(verified_until, now()), now()) + make_interval(days => $2), verified_from = COALESCE(verified_from, now()), verify_renew = false WHERE id=$1", [req.uid, o.days]);
  } else {
    await db.query("UPDATE users SET verified_until = GREATEST(COALESCE(verified_until, now()), now()) + make_interval(days => $2), verified_from = COALESCE(verified_from, now()) WHERE id=$1", [req.uid, o.days]);
  }
  res.json({ ok: true, status: "paid", trial: o.kind === "apply" });
}));
// Renewal every 10 minutes: the recurring plan is charged on the saved card when it is due.
async function renewVerified() {
  const due = (await db.query("SELECT id, verify_auth FROM users WHERE verify_renew AND verify_auth IS NOT NULL AND verify_next IS NOT NULL AND verify_next <= now() LIMIT 50")).rows;
  for (const u of due) {
    const r = await paystack("POST", "/transaction/charge_authorization", { authorization_code: u.verify_auth, email: "u" + u.id.replace(/-/g, "").slice(0, 16) + "@orivoclass.app", amount: VPLANS.recurring.price * 100, currency: "KES", reference: "VRN" + crypto.randomBytes(9).toString("hex") });
    if (r.ok && r.json.data && r.json.data.status === "success") {
      await db.query("UPDATE users SET verified_until = GREATEST(COALESCE(verified_until, now()), now()) + make_interval(days => $2) WHERE id=$1", [u.id, VPLANS.recurring.days]);
      await db.query("UPDATE users SET verify_next = verified_until WHERE id=$1", [u.id]);
    } else {
      await db.query("UPDATE users SET verify_renew=false WHERE id=$1", [u.id]);
    }
  }
}
setInterval(() => renewVerified().catch(() => {}), 600000);
app.put("/api/admin/verify", adminLimit, adminOnly, wrap(async (req, res) => {
  const phone = phoneOf(req.body.phone);
  const days = Math.round(Number(req.body.days));
  if (days !== 0) return bad(res, "A badge is given only when a person pays. Admin can only remove a badge (0 days).");
  const u = (await db.query("SELECT id FROM users WHERE phone=$1", [phone])).rows[0];
  if (!u) return bad(res, "No account with this number.", 404);
  await db.query("UPDATE users SET verified_until = CASE WHEN $2::int = 0 THEN NULL ELSE GREATEST(COALESCE(verified_until, now()), now()) + make_interval(days => $2::int) END WHERE id=$1", [u.id, days]);
  res.json({ ok: true });
}));
app.put("/api/admin/verify-plan", adminLimit, adminOnly, wrap(async (req, res) => {
  const price = Math.round(Number(req.body.price)), days = Math.round(Number(req.body.days));
  if (!(price >= 10 && price <= 100000) || !(days >= 1 && days <= 365)) return bad(res, "Check the price (10 to 100000) and the days (1 to 365).");
  await db.query("INSERT INTO app_settings(key,value,updated_at) VALUES('verify_plan',$1,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()", [JSON.stringify({ price, days })]);
  res.json({ ok: true });
}));
// Counts for a Singles profile: likes the person received, and matches.
app.get("/api/singles/stats/:uid", need, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  const who = req.params.uid.toLowerCase();
  if (await sgBlocked(req.uid, who)) return bad(res, "Not available.", 403);
  const likes = (await db.query("SELECT count(*)::int AS n FROM singles_likes WHERE liked=$1", [who])).rows[0].n;
  const matches = (await db.query("SELECT count(*)::int AS n FROM singles_matches WHERE a=$1 OR b=$1", [who])).rows[0].n;
  res.json({ likes_received: likes, matches });
}));
// ---- Message requests: people who are not saved in each other's contacts ("Public" chats) ----
async function savedBetween(a, b) {
  return (await db.query("SELECT 1 FROM contacts WHERE (owner=$1 AND contact=$2) OR (owner=$2 AND contact=$1) LIMIT 1", [a, b])).rowCount > 0;
}
async function requestRow(a, b) {
  return (await db.query("SELECT from_id, to_id, status, sent FROM chat_requests WHERE (from_id=$1 AND to_id=$2) OR (from_id=$2 AND to_id=$1) LIMIT 1", [a, b])).rows[0] || null;
}
// Can I read this chat? Saved people can; others only after the request is accepted.
async function requestAccess(me, peer) {
  if (await savedBetween(me, peer)) return { ok: true };
  const r = await requestRow(me, peer);
  if (r && r.status === "accepted") return { ok: true };
  if (!r) return { ok: false, state: "none" };
  if (r.status === "declined") return { ok: false, state: "declined" };
  return { ok: false, state: r.from_id === me ? "outgoing" : "incoming" };
}
// Can I send to this person? A stranger gets up to 3 messages while the request waits.
async function requestGate(me, to) {
  if (await savedBetween(me, to)) return null;
  const r = await requestRow(me, to);
  if (r && r.status === "accepted") return null;
  if (r && r.status === "declined") return "Message not delivered.";
  if (r && r.from_id !== me) { await db.query("UPDATE chat_requests SET status='accepted', updated_at=now() WHERE from_id=$1 AND to_id=$2", [r.from_id, r.to_id]); return null; }
  if (r) {
    if (r.sent >= 3) return "Wait for them to accept your request. You can send up to 3 messages.";
    await db.query("UPDATE chat_requests SET sent=sent+1, updated_at=now() WHERE from_id=$1 AND to_id=$2", [r.from_id, r.to_id]);
    return null;
  }
  await db.query("INSERT INTO chat_requests(from_id,to_id,status,sent) VALUES($1,$2,'pending',1) ON CONFLICT (from_id,to_id) DO NOTHING", [me, to]);
  return null;
}
app.get("/api/requests", need, wrap(async (req, res) => {
  const incoming = (await db.query("SELECT r.from_id AS id, u.name, r.created_at FROM chat_requests r JOIN users u ON u.id=r.from_id WHERE r.to_id=$1 AND r.status='pending' ORDER BY r.created_at DESC LIMIT 100", [req.uid])).rows;
  const outgoing = (await db.query("SELECT r.to_id AS id, u.name, r.created_at FROM chat_requests r JOIN users u ON u.id=r.to_id WHERE r.from_id=$1 AND r.status='pending' ORDER BY r.created_at DESC LIMIT 100", [req.uid])).rows;
  res.json({ incoming, outgoing });
}));
app.post("/api/requests/:uid/accept", need, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  await db.query("UPDATE chat_requests SET status='accepted', updated_at=now() WHERE from_id=$2 AND to_id=$1 AND status='pending'", [req.uid, req.params.uid.toLowerCase()]);
  res.json({ ok: true });
}));
app.post("/api/requests/:uid/decline", need, wrap(async (req, res) => {
  if (!isId(req.params.uid)) return bad(res, "Invalid id.");
  await db.query("UPDATE chat_requests SET status='declined', updated_at=now() WHERE from_id=$2 AND to_id=$1 AND status='pending'", [req.uid, req.params.uid.toLowerCase()]);
  res.json({ ok: true });
}));
// END OF PART 10

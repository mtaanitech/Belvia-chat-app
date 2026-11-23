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
    `SELECT s.user_id, s.nick, s.gender, s.town, s.bio, NULL::text AS photo, date_part('year', age(s.birth_date))::int AS age, u.last_seen,
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
    `SELECT s.user_id, s.nick, s.photo, date_part('year', age(s.birth_date))::int AS age, l.body AS last_body, l.from_id AS last_from, l.created_at AS last_at, mt.created_at AS matched_at, pu.last_seen
     FROM singles_matches mt JOIN singles s ON s.user_id = CASE WHEN mt.a=$1 THEN mt.b ELSE mt.a END JOIN users pu ON pu.id=s.user_id
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

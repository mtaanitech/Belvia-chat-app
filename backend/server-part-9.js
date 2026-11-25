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
const POST_COLS = `p.id, p.user_id, u.name, p.body, p.audience, (p.image IS NOT NULL) AS has_image, p.created_at, p.repost_of, (u.verified_until > now() AND (u.verified_from IS NULL OR u.verified_from <= now())) AS verified,
  (SELECT json_build_object('id', o.id, 'user_id', o.user_id, 'name', ou.name, 'body', o.body, 'has_image', (o.image IS NOT NULL)) FROM posts o JOIN users ou ON ou.id=o.user_id
     WHERE o.id=p.repost_of AND NOT o.removed AND (o.audience='public' OR o.user_id=$1 OR EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=o.user_id))) AS original,
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
  const score = `((SELECT count(*) FROM post_likes l WHERE l.post_id=p.id) + 2*(SELECT count(*) FROM post_comments c WHERE c.post_id=p.id AND NOT c.removed) + 0.2*(SELECT count(*) FROM post_views v WHERE v.post_id=p.id) + 1)::float8 * (CASE WHEN u.verified_until > now() THEN 1.5 ELSE 1 END) / power((extract(epoch FROM (now() - p.created_at))/3600.0 + 2)::float8, 1.2)`;
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
    `SELECT u.id, u.name, u.about, u.cover, u.mood, u.created_at, u.locked, (u.verified_until > now() AND (u.verified_from IS NULL OR u.verified_from <= now())) AS verified,
       (SELECT count(*)::int FROM posts p WHERE p.user_id=u.id AND NOT p.removed) AS posts,
       (SELECT count(*)::int FROM follows f WHERE f.followee=u.id) AS followers,
       (SELECT count(*)::int FROM follows f WHERE f.follower=u.id) AS following,
       EXISTS (SELECT 1 FROM follows f WHERE f.follower=$1 AND f.followee=u.id) AS am_following,
       EXISTS (SELECT 1 FROM follows f WHERE f.follower=u.id AND f.followee=$1) AS follows_me,
       EXISTS (SELECT 1 FROM follow_requests fr WHERE fr.follower=$1 AND fr.followee=u.id) AS requested
     FROM users u WHERE u.id=$2 AND NOT u.banned
       AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker=$1 AND b.blocked=u.id) OR (b.blocker=u.id AND b.blocked=$1))`, [req.uid, req.params.uid.toLowerCase()]);
  if (!r.rows[0]) return bad(res, "This profile is not available.", 404);
  const P = r.rows[0];
  // A private account hides its posts AND its numbers from people who do not follow it.
  if (P.locked && !P.am_following && P.id !== req.uid) { P.posts = null; P.followers = null; P.following = null; P.hidden = true; }
  res.json(P);
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

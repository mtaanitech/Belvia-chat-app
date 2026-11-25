// ---- Chats and messages ----
app.get("/api/chats", need, wrap(async (req, res) => {
  const r = await db.query(
    `WITH m AS (
       SELECT DISTINCT ON (peer) peer, id, body, from_id, created_at FROM (
         SELECT CASE WHEN from_id=$1 THEN to_id ELSE from_id END AS peer, id, CASE WHEN view_once THEN 'View once message' ELSE body END AS body, from_id, created_at
         FROM messages WHERE ((from_id=$1 AND NOT del_from) OR (to_id=$1 AND NOT del_to)) AND (expires_at IS NULL OR expires_at > now())
       ) x ORDER BY peer, id DESC)
     SELECT m.*, (SELECT count(*)::int FROM messages x WHERE x.from_id=m.peer AND x.to_id=$1 AND x.read_at IS NULL AND NOT x.del_to AND (x.expires_at IS NULL OR x.expires_at > now())) AS unread, CASE WHEN c.contact IS NOT NULL THEN u.phone ELSE NULL END AS phone, u.last_seen, u.seen_privacy, COALESCE(NULLIF(c.alias,''), CASE WHEN c.contact IS NOT NULL THEN u.name ELSE COALESCE(NULLIF(u.name,''), 'Member') END) AS display, (c.contact IS NOT NULL) AS saved, u.name AS pname,
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
  const acc = await requestAccess(req.uid, req.params.peer);
  if (!acc.ok) return res.json({ messages: [], ttl: null, locked: true, request: acc.state });
  await db.query("UPDATE messages SET read_at=now() WHERE to_id=$1 AND from_id=$2 AND read_at IS NULL AND NOT del_to", [req.uid, req.params.peer]);
  const r = await db.query(
    `SELECT * FROM (
       SELECT id, from_id, to_id, CASE WHEN view_once THEN NULL ELSE body END AS body, view_once, opened_at, forwarded, reply, reaction, read_at, created_at, expires_at FROM messages
       WHERE ((from_id=$1 AND to_id=$2 AND NOT del_from) OR (from_id=$2 AND to_id=$1 AND NOT del_to)) AND (expires_at IS NULL OR expires_at > now())
       AND NOT EXISTS (SELECT 1 FROM message_hidden h WHERE h.message_id=messages.id AND h.user_id=$1)
       ORDER BY id DESC LIMIT 200) t ORDER BY id`, [req.uid, req.params.peer]);
  res.json({ messages: r.rows, ttl: await chatTtl(req.uid, req.params.peer) });
}));

app.post("/api/messages", need, wrap(async (req, res) => {
  const raw = String(req.body.body || "").trim();
  const body = raw.startsWith("e2e1:") ? raw.slice(0, 40000) : raw.slice(0, 4000); // encrypted messages are longer
  const reply = req.body.reply ? String(req.body.reply).slice(0, 120) : null;
  if (!body) return bad(res, "Message is empty.");
  if (!isId(req.body.to) || req.body.to === req.uid) return bad(res, "Invalid recipient.");
  if (req.body.once && !req.body.fwd) {
    const ru = (await db.query("SELECT restricted_until FROM users WHERE id=$1", [req.uid])).rows[0];
    if (ru && ru.restricted_until && new Date(ru.restricted_until) > new Date()) return bad(res, "Your account is restricted, so you cannot send View Once messages for now.", 403);
  }
  const ok = await db.query("SELECT 1 FROM users WHERE id=$1", [req.body.to]);
  if (!ok.rowCount) return bad(res, "Recipient not found.", 404);
  const gate = await requestGate(req.uid, req.body.to);
  if (gate) return bad(res, gate, 403);
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
      .then((q) => notify(req.body.to, "msg", { title: (q.rows[0] && q.rows[0].n) || "Orivoclass", body: "New message", tag: "m" + req.uid, type: "msg", peer: req.uid })).catch(() => {});
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

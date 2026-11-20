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

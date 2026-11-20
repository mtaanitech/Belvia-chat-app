// ---- Orivoclass AI: the app talks to the AI through this server, so the AI address and key stay private and each person is rate limited ----
// Env (all optional): AI_URL, AI_KEY (sent as "Authorization: Bearer"), AI_SYSTEM (instructions; set empty to send none), AI_FORMAT = messages | message | prompt.
const AI_URL = process.env.AI_URL || "https://superb-owl-342.convex.site/v1/chat";
// What Orivoclass AI knows about the app. Keep this up to date when the app changes.
const APP_GUIDE = `
ORIVOCLASS (the app): a private messaging app with chats, groups, calls, status, a public feed, Singles (adults 18+), and an AI assistant.
- Sign up: name, phone number and a password, then a 6-digit code is sent to the phone (or shown on screen in test mode). After sign up the app shows a RECOVERY CODE once: the person must copy and save it. It is the only way to reset the password without the phone.
- Log in: phone number and password. If the account is already open on another phone, that phone must tap "Yes, it's me" to approve.
- Forgot password: "Forgot password?" on the log in screen, with the phone number, the recovery code and a new password.
- Feed (home tab): "For you" (a mix of strong and new posts) and "Following". Search bar at the top finds accounts. The + next to the search makes a post (text and/or photo, and "Everyone" or "Followers only"). Hold a post's text for 2 seconds to copy it. Tap the like heart to react; hold it to choose a reaction. The ⋮ on each post has Share, Copy link, and Report (or Boost, Delete for your own posts).
- Boost: on your own post, ⋮ > Boost post. You pay for 1 to 5 days with Paystack. Boosted posts are shown to people who do not follow you, marked "Sponsored".
- Chats: tap a contact to chat. Unread messages show a number. Hold or tap a message for Reply, reactions, Copy, Forward or Delete (delete only hides it for you). The ⋮ in a chat has Mark as unread, pin, archive, disappearing messages (24 hours or 7 days), block, report and delete chat. Add someone by their phone number from the + on the Chats screen; if they are not on Orivoclass you can invite them.
- Calls: 📞 for voice and 🎥 for video, in a chat or on the Calls tab. Incoming calls show Answer and Decline. Missed calls are in the Calls tab.
- Status: the Status tab. Add a text update or a photo with the +. Statuses last 24 hours. The owner can see who viewed them.
- Singles: an adult-only dating space (18+). Create a profile with a nickname and date of birth. Daily limits on how many profiles you see and likes you give keep it calm. A chat opens only after both people like each other.
- Me (the three lines at the top left): Privacy (Private account, last seen, suggestions), Account status (trust score), Linked devices (log out other phones), Dashboard (followers, reactions, views, posts, boosts, audience), Follow requests, Chat lock (PIN), Notifications (turn on, and "Send a test notification"), Backup (download your chats), Appearance (white or dark, and colour), Orivoclass AI (save AI chats or not), Profile photo, Install app, Terms, Privacy Policy, Community Rules, About, Help.
- Install: on Android Chrome use the install banner, or ⋮ > Install app. On iPhone use Share > Add to Home Screen.
- Notifications: they show for messages, calls, status and views, and only when the app is closed or in the background. They have buttons: calls show Answer and Decline, messages show Reply and Mark as read.
- Community rules: no spam, scams, harassment, threats, hate, or nude images sent to people who did not ask. Accounts can get a warning, a 24-hour restriction, a resting period, or a permanent ban. Appeals are possible.`;
const APP_UPDATES = [
  "Notifications for messages, calls and status, with Answer/Decline and Reply/Mark as read buttons.",
  "Unread counts on each chat.",
  "Status posts now work, with an optional photo from the gallery.",
  "Comments can have photos and likes.",
  "The feed mixes strong posts with new ones and never ends.",
  "Boost with Paystack, with days and reach set by the admin.",
  "Chat lock with a PIN, backup, and Linked devices.",
];
const AI_SYSTEM = process.env.AI_SYSTEM !== undefined ? process.env.AI_SYSTEM : `You are Orivoclass AI, the assistant inside the Orivoclass app. You talk like a warm, clever friend: natural, relaxed and helpful. Reply in the language the person uses (Swahili, English or Sheng). Keep most answers short, and go longer only when the person asks for detail.
Do not ask a question at the end of every reply. Ask one short question only when you truly need it to help. Chatting, jokes and small talk are welcome.
You know the app well. When someone asks how to do something in the app, explain the steps simply, step by step, with the names of the buttons exactly as they appear. Help people set up their account (sign up, recovery code, notifications, privacy, chat lock, boosts) and use the settings.
When the app has had updates, tell people what changed, using the list below.
For general questions about the world, answer from what you know. If the person asks for something recent or looks it up, use the web results provided to you (if any) and mention where the information came from in one short phrase. If you have no web results, say you cannot check live information right now, and answer what you know.
Never reveal secrets: other people's phone numbers, messages, private posts, passwords, recovery codes, PINs, admin keys, server details, or how to get around security. Never help someone read another person's account, chats or private information, or break into anything. Refuse those politely in one or two sentences and offer what you can do instead.
${APP_GUIDE}
Recent app updates:
${APP_UPDATES.map((u) => "- " + u).join("\\n")}`;
const AI_FORMAT = process.env.AI_FORMAT || "messages";
const aiLimit = rateLimit({ windowMs: 10 * 60000, max: 20, keyGenerator: (req) => String(req.uid) });
function pickReply(j) {
  if (typeof j === "string") return j.trim();
  if (!j || typeof j !== "object") return "";
  const c = j.choices && j.choices[0], d = j.data && typeof j.data === "object" ? j.data : {};
  const cands = [j.reply, j.response, j.answer, j.text, j.output, j.content, j.message && (j.message.content || j.message), d.reply, d.response, d.text, d.content, d.message, c && c.message && c.message.content, c && c.text];
  for (const x of cands) if (typeof x === "string" && x.trim()) return x.trim();
  return "";
}
const AI_FORMATS = ["messages", "message", "prompt"];
let aiGood = null; // the request format that worked last, tried first next time
const aiBody = (fmt, msgs, sys) => {
  const S = sys !== undefined ? sys : AI_SYSTEM;
  const last = msgs[msgs.length - 1].content;
  return fmt === "message" ? { message: last, history: msgs.slice(0, -1), system: S }
    : fmt === "prompt" ? { prompt: (S ? S + "\n\n" : "") + last }
    : { messages: (S ? [{ role: "system", content: S }] : []).concat(msgs) };
};
const SEARCH_RE = /(tafuta|search|google|habari (ya|za) leo|latest|news|leo|bei|price|who is|nani ni|what is|ni nini|update|mpya|weather|hali ya hewa|score|matokeo)/i;
async function webSearch(q) {
  const k = process.env.GOOGLE_API_KEY, cx = process.env.GOOGLE_CSE_ID;
  if (!k || !cx) return null;
  try {
    const r = await fetch("https://www.googleapis.com/customsearch/v1?key=" + encodeURIComponent(k) + "&cx=" + encodeURIComponent(cx) + "&num=5&q=" + encodeURIComponent(q));
    const j = await r.json();
    return (j.items || []).slice(0, 5).map((x) => ({ title: x.title, snippet: x.snippet, link: x.link }));
  } catch (e) { return null; }
}
async function aiCall(fmt, msgs, sys) {
  const ac = new AbortController(), timer = setTimeout(() => ac.abort(), 30000);
  try {
    const r = await fetch(AI_URL, { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, process.env.AI_KEY ? { Authorization: "Bearer " + process.env.AI_KEY } : {}), body: JSON.stringify(aiBody(fmt, msgs, sys)), signal: ac.signal });
    return { ok: r.ok, status: r.status, raw: await r.text() };
  } catch (e) { return { ok: false, status: 0, raw: "", error: e.name === "AbortError" ? "timeout" : e.message }; }
  finally { clearTimeout(timer); }
}
app.post("/api/ai", need, aiLimit, wrap(async (req, res) => {
  if (typeof fetch !== "function") return bad(res, "The server needs Node 18 or newer for the AI.", 500);
  const msgs = (Array.isArray(req.body.messages) ? req.body.messages : [])
    .filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string" && m.content.trim())
    .slice(-12).map((m) => ({ role: m.role, content: m.content.slice(0, 2000) }));
  if (!msgs.length || msgs[msgs.length - 1].role !== "user") return bad(res, "Type a message first.");
  let sysNow = AI_SYSTEM;
  const q = msgs[msgs.length - 1].content;
  if (SEARCH_RE.test(q)) {
    const found = await webSearch(q);
    if (found && found.length) sysNow = AI_SYSTEM + "\n\nWeb results for the person's latest question (use them, and name the source briefly):\n" + found.map((x, i) => (i + 1) + ". " + x.title + " (" + x.link + "): " + (x.snippet || "")).join("\n");
  }
  const first = aiGood || AI_FORMAT, order = [first].concat(AI_FORMATS.filter((f) => f !== first));
  let last = null;
  for (const fmt of order) { // if the AI rejects one request shape (400/415/422), try the next shape
    const r = await aiCall(fmt, msgs, sysNow); last = r;
    if (r.ok) {
      let j; try { j = JSON.parse(r.raw); } catch (e) { j = r.raw; }
      const reply = pickReply(j).slice(0, 4000);
      if (reply) {
        aiGood = fmt;
        const kp = (await db.query("SELECT ai_keep FROM users WHERE id=$1", [req.uid])).rows[0];
        if (kp && kp.ai_keep !== 0) await db.query("INSERT INTO ai_messages(user_id,role,content) VALUES($1,'user',$2),($1,'assistant',$3)", [req.uid, msgs[msgs.length - 1].content, reply]);
        return res.json({ reply });
      }
      console.error("AI reply format not recognised:", r.raw.slice(0, 300));
      return bad(res, "The AI answered in a way the app does not understand yet.", 502);
    }
    console.error("AI upstream error", fmt, r.status, r.error || r.raw.slice(0, 300));
    if (![400, 415, 422].includes(r.status)) break;
  }
  if (last.status === 401 || last.status === 403) return bad(res, "The AI needs a key. Ask the app owner to set AI_KEY.", 502);
  const why = last.status ? "error " + last.status : last.error === "timeout" ? "it took too long" : "no connection";
  return bad(res, "The AI is not available right now (" + why + ").", 502);
}));

// Saved AI chats: off by default. The person chooses how long to keep them (or deletes them whenever they want).
setInterval(() => db.query("DELETE FROM ai_messages m USING users u WHERE m.user_id=u.id AND u.ai_keep > 0 AND m.created_at < now() - make_interval(secs => u.ai_keep::double precision)").catch(() => {}), 3600000);
app.get("/api/ai/history", need, wrap(async (req, res) => {
  const u = (await db.query("SELECT ai_keep FROM users WHERE id=$1", [req.uid])).rows[0];
  const keep = u ? u.ai_keep : 0;
  if (keep === 0) return res.json({ keep, messages: [] });
  const r = await db.query("SELECT * FROM (SELECT id, role, content, created_at FROM ai_messages WHERE user_id=$1 AND ($2::int < 0 OR created_at > now() - make_interval(secs => $2::double precision)) ORDER BY id DESC LIMIT 60) t ORDER BY id", [req.uid, keep]);
  res.json({ keep, messages: r.rows });
}));
app.put("/api/ai/settings", need, wrap(async (req, res) => {
  const k = Number(req.body.keep);
  if (![0, 86400, 604800, 2592000, -1].includes(k)) return bad(res, "Choose how long to keep your AI chats.");
  await db.query("UPDATE users SET ai_keep=$2 WHERE id=$1", [req.uid, k]);
  if (k === 0) await db.query("DELETE FROM ai_messages WHERE user_id=$1", [req.uid]);
  else if (k > 0) await db.query("DELETE FROM ai_messages WHERE user_id=$1 AND created_at < now() - make_interval(secs => $2::double precision)", [req.uid, k]);
  res.json({ ok: true, keep: k });
}));
app.delete("/api/ai/history", need, wrap(async (req, res) => {
  await db.query("DELETE FROM ai_messages WHERE user_id=$1", [req.uid]);
  res.json({ ok: true });
}));

// ---- Calls (voice and video, WebRTC). The server only passes the set-up messages; the call itself goes phone to phone, or through a TURN relay. ----
// Optional env: TURN_URLS (comma list, e.g. turn:turn.example.com:3478,turns:turn.example.com:5349) with either TURN_SECRET (coturn "REST" auth) or TURN_USERNAME + TURN_CREDENTIAL.
const callPoll = rateLimit({ windowMs: 60000, max: 200 });
const callStart = rateLimit({ windowMs: 60 * 60000, max: 30 });
async function expireCalls() {
  await db.query("UPDATE calls SET status='missed', ended_at=now() WHERE status='ringing' AND created_at < now() - interval '45 seconds'");
  await db.query("UPDATE calls SET status='ended', ended_at=now() WHERE status='active' AND answered_at < now() - interval '6 hours'");
}
setInterval(() => {
  expireCalls().catch(() => {});
  db.query("DELETE FROM call_signals WHERE created_at < now() - interval '2 hours'").catch(() => {});
  db.query("DELETE FROM calls WHERE created_at < now() - interval '90 days'").catch(() => {});
}, 15000);

app.get("/api/calls/ice", need, (req, res) => {
  const servers = [{ urls: (process.env.STUN_URLS || "stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302").split(",").map((x) => x.trim()).filter(Boolean) }];
  const urls = (process.env.TURN_URLS || "").split(",").map((x) => x.trim()).filter(Boolean);
  if (urls.length) {
    if (process.env.TURN_SECRET) {
      const user = (Math.floor(Date.now() / 1000) + 3600) + ":" + req.uid;
      servers.push({ urls, username: user, credential: crypto.createHmac("sha1", process.env.TURN_SECRET).update(user).digest("base64") });
    } else if (process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) servers.push({ urls, username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL });
  }
  res.json({ iceServers: servers, relay: servers.length > 1 });
});

app.post("/api/calls", need, callStart, wrap(async (req, res) => {
  if (!isId(req.body.to) || req.body.to.toLowerCase() === req.uid) return bad(res, "Invalid id.");
  const to = req.body.to.toLowerCase(), kind = req.body.kind === "video" ? "video" : "voice";
  if (!(await db.query("SELECT 1 FROM users WHERE id=$1 AND NOT banned", [to])).rowCount) return bad(res, "Not found.", 404);
  if (await sgBlocked(req.uid, to)) return bad(res, "This person cannot be called right now.", 403);
  if (!(await db.query("SELECT 1 FROM contacts WHERE owner=$1 AND contact=$2", [to, req.uid])).rowCount) return bad(res, "You can only call people who have saved your number.", 403);
  await expireCalls();
  if ((await db.query("SELECT 1 FROM calls WHERE (caller=$1 OR callee=$1) AND status IN ('ringing','active')", [req.uid])).rowCount) return bad(res, "You are already in a call.", 409);
  if ((await db.query("SELECT 1 FROM calls WHERE (caller=$1 OR callee=$1) AND status IN ('ringing','active')", [to])).rowCount) {
    const b = await db.query("INSERT INTO calls(caller,callee,kind,status,ended_at) VALUES($1,$2,$3,'busy',now()) RETURNING id", [req.uid, to, kind]);
    return res.json({ id: b.rows[0].id, busy: true });
  }
  const c = await db.query("INSERT INTO calls(caller,callee,kind) VALUES($1,$2,$3) RETURNING id", [req.uid, to, kind]);
  if (webpush) {
    const q = (await db.query("SELECT COALESCE(NULLIF(k.alias,''), u.name) AS n FROM users u LEFT JOIN contacts k ON k.owner=$2 AND k.contact=u.id WHERE u.id=$1", [req.uid, to])).rows[0];
    notify(to, "calls", { title: (q && q.n) || "Orivoclass", body: "Incoming " + kind + " call", tag: "call" + c.rows[0].id, type: "call", id: c.rows[0].id });
  }
  res.json({ id: c.rows[0].id });
}));

app.post("/api/calls/:id/answer", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const st = req.body.accept === true ? "active" : "declined";
  const r = await db.query("UPDATE calls SET status=$3::text, answered_at=CASE WHEN $3::text='active' THEN now() ELSE NULL END, ended_at=CASE WHEN $3::text='active' THEN NULL ELSE now() END WHERE id=$1 AND callee=$2 AND status='ringing' AND created_at > now() - interval '60 seconds' RETURNING id", [req.params.id, req.uid, st]);
  if (!r.rowCount) return bad(res, "This call has ended.", 410);
  res.json({ ok: true });
}));

app.post("/api/calls/:id/signal", need, callPoll, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const kind = String(req.body.kind || ""), payload = String(req.body.payload || "");
  if (!["offer", "answer", "ice"].includes(kind) || !payload || payload.length > 20000) return bad(res, "Invalid signal.");
  const c = (await db.query("SELECT caller, callee FROM calls WHERE id=$1 AND (caller=$2 OR callee=$2) AND status IN ('ringing','active')", [req.params.id, req.uid])).rows[0];
  if (!c) return bad(res, "This call has ended.", 410);
  await db.query("INSERT INTO call_signals(call_id,to_id,kind,payload) VALUES($1,$2,$3,$4)", [req.params.id, c.caller === req.uid ? c.callee : c.caller, kind, payload]);
  res.json({ ok: true });
}));

app.get("/api/calls/:id/signals", need, callPoll, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  await expireCalls();
  const c = (await db.query("SELECT status FROM calls WHERE id=$1 AND (caller=$2 OR callee=$2)", [req.params.id, req.uid])).rows[0];
  if (!c) return bad(res, "Not found.", 404);
  const s = await db.query("SELECT id, kind, payload FROM call_signals WHERE call_id=$1 AND to_id=$2 AND id > $3 ORDER BY id LIMIT 100", [req.params.id, req.uid, parseInt(req.query.since, 10) || 0]);
  res.json({ status: c.status, signals: s.rows.map((x) => ({ id: Number(x.id), kind: x.kind, payload: x.payload })) });
}));

app.post("/api/calls/:id/end", need, wrap(async (req, res) => {
  if (!isId(req.params.id)) return bad(res, "Invalid id.");
  const c = (await db.query("UPDATE calls SET status=CASE WHEN status='ringing' THEN 'missed' ELSE 'ended' END, ended_at=now() WHERE id=$1 AND (caller=$2 OR callee=$2) AND status IN ('ringing','active') RETURNING *", [req.params.id, req.uid])).rows[0];
  if (c && c.status === "missed" && c.caller === req.uid && webpush) {
    const q = (await db.query("SELECT COALESCE(NULLIF(k.alias,''), u.name) AS n FROM users u LEFT JOIN contacts k ON k.owner=$2 AND k.contact=u.id WHERE u.id=$1", [req.uid, c.callee])).rows[0];
    notify(c.callee, "calls", { title: (q && q.n) || "Orivoclass", body: "Missed " + c.kind + " call", tag: "call" + c.id, type: "missed", id: c.id });
  }
  res.json({ ok: true });
}));

app.get("/api/calls", need, wrap(async (req, res) => {
  await expireCalls();
  const r = await db.query(
    `SELECT c.id, c.kind, c.status, c.created_at, c.answered_at, c.ended_at, (c.caller=$1) AS outgoing, u.id AS peer_id,
            COALESCE(NULLIF(k.alias,''), CASE WHEN k.contact IS NOT NULL THEN u.name ELSE u.phone END) AS peer_name
     FROM calls c JOIN users u ON u.id = CASE WHEN c.caller=$1 THEN c.callee ELSE c.caller END
     LEFT JOIN contacts k ON k.owner=$1 AND k.contact=u.id
     WHERE c.caller=$1 OR c.callee=$1 ORDER BY c.created_at DESC LIMIT 50`, [req.uid]);
  res.json({ calls: r.rows });
}));
// END OF PART 5

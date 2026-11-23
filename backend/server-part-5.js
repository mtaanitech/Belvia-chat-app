// ---- Orivoclass AI: the app talks to the AI through this server, so the AI address and key stay private and each person is rate limited ----
// Env (all optional): AI_URL, AI_KEY (sent as "Authorization: Bearer"), AI_SYSTEM (instructions; set empty to send none), AI_FORMAT = messages | message | prompt.
const AI_URL = process.env.AI_URL || "https://superb-owl-342.convex.site/v1/chat";
// What Orivoclass AI knows about the app. Keep this up to date when the app changes.
const APP_GUIDE = `
ORIVOCLASS: chats, groups, calls, status, Home feed, Singles (18+), and this assistant. Made by Mtaanitech Company Limited (founder Alex Musau). Support: mtaanitech76@gmail.com, WhatsApp +254 703 182 307.
ACCOUNT: Sign up (country, name, phone, password), a code is sent to the phone, then you get a RECOVERY CODE once; save it. Log in with phone and password. Forgot password: use the recovery code. Log in with a code from my phone: on a computer, then on the phone Me > Linked devices > Enter the code.
ME (three lines, top left): Privacy, Account status, Dashboard, Follow requests, Chat lock, Notifications (test), Backup and Message keys (PIN), Appearance (theme, colour, Text size), Orivoclass AI, Profile photo, Install app, Invite friends, Verified badge, Terms, Privacy Policy, Community Rules, About, Help, Log out, Delete account.
HOME: For you and Following tabs. Search accounts. + writes a post (Everyone or Followers only). Tap a post's picture or text to open its comments and reply. Hold the heart to choose a reaction. The post menu: Share, Copy link, Repost to my profile, Report; your own posts: Edit, Boost, Delete. Boost (Paystack, 1-5 days) shows a post to people who do not follow you, marked Sponsored.
CHATS: hold a chat 2 seconds to delete it. The chat menu (three dots) is a list: Pin, Archive, Disappearing messages, Security code, Mark as unread, Block, Report, Delete chat. Messages: tap or hold for Reply, reactions, Copy, Forward, Edit (your text), Delete (for you). One-to-one chats are end-to-end encrypted; groups are not yet. Security code: both phones show the same numbers.
STATUS: one box per person; your box has + to add a status (text or photo, 24 hours). Tap a box to watch; 15 seconds each; tap right or left, or swipe up for the next person. Reply to a status from the viewer. Viewed by shows who saw yours. Gear = status privacy and deleting.
CALLS: voice and video from a chat or the Calls tab.
NOTIFICATIONS: Me > Notifications. Messages (Reply, Mark as read), calls (Answer, Decline), status.
SINGLES (18+): create a profile; Discover cards with a photo (heart to like, cross to pass); Nearby (same town); Liked; Matches; Me. Profiles open only after a mutual like. Message, Call and Video unlock after a match (three dots on the profile).
VERIFIED BADGE: a subscription paid with Paystack from Me, for a set number of days; shows a red-and-black tick with "Verified account" under the name. Verified posts reach more people. No guaranteed likes.
RULES: no spam, scams, harassment, hate, or unwanted nude images. Report or block from the menu.
`;
const APP_UPDATES = [
  "Home: tap a post's picture or text to open its comments, read others' comments, and reply.",
  "Chats: the menu is a list now; Back closes it first. Hold a chat for 2 seconds to delete it.",
  "Edit your own posts and messages.",
  "Reply to a status from its viewer.",
  "Status: one box per person, Friends' status, reply and view counts.",
  "Singles: Discover cards, Nearby, Liked, Matches, Online or Last seen, and the ⋮ menu on profiles.",
  "Verified badge: a subscription with a blue tick, paid with Paystack.",
  "Message keys backup with a PIN, and end-to-end encryption for one-to-one chats.",
  "Text size settings (Small, Medium, Large).",
];
const AI_SYSTEM = process.env.AI_SYSTEM !== undefined ? process.env.AI_SYSTEM : `You are Orivoclass AI: a funny, warm, smart friend. Use emojis naturally. Reply in the person's language (Swahili, English or Sheng). Keep replies short unless detail is asked. Do not ask a question in every reply; ask only when you truly need to. Remember the conversation. Explain app steps clearly with the button names. Never reveal other people's data, passwords, PINs, recovery codes, keys, or server secrets; refuse kindly.
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
// For services that take one text prompt: the instructions, then the whole conversation so far, then the new message.
function promptText(S, msgs) {
  const past = msgs.slice(0, -1).map((m) => (m.role === "user" ? "Person: " : "Assistant: ") + m.content).join("\n");
  const now = "Person: " + msgs[msgs.length - 1].content;
  return (S ? S + "\n\n" : "") + (past ? "Conversation so far:\n" + past + "\n\n" : "") + now + "\nAssistant:";
}
const aiBody = (fmt, msgs, sys) => {
  const S = sys !== undefined ? sys : AI_SYSTEM;
  // The instructions also go inside the last user message, so every service reads them, whatever it does with a "system" field.
  const withS = msgs.map((m, i) => (i === msgs.length - 1 && S) ? { ...m, content: S + "\n\n---\nThe person says:\n" + m.content } : m);
  const last = withS[withS.length - 1].content;
  // Some services ignore a separate "system" field, so the instructions go inside the message itself.
  return fmt === "message" ? { message: last, history: withS.slice(0, -1), system: S }
    : fmt === "prompt" ? { prompt: promptText(S, msgs) }
    : { messages: (S ? [{ role: "system", content: S }] : []).concat(withS) };
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
// Gemini answers text, with the conversation so far.
async function geminiChat(msgs) {
  const model = process.env.GEMINI_MODEL || "gemini-2.0-flash";
  const r = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + encodeURIComponent(process.env.GEMINI_API_KEY), {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ systemInstruction: { parts: [{ text: AI_SYSTEM }] }, contents: msgs.map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] })) }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Gemini error " + r.status);
  return ((j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || []).map((p) => p.text || "").join("").trim();
}
// Gemini reads a picture together with the question.
async function geminiLook(question, dataUrl) {
  const m = /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/.exec(dataUrl);
  const model = process.env.GEMINI_MODEL || "gemini-2.0-flash";
  const r = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + encodeURIComponent(process.env.GEMINI_API_KEY), {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ systemInstruction: { parts: [{ text: AI_SYSTEM }] }, contents: [{ role: "user", parts: [{ text: question }, { inline_data: { mime_type: m[1], data: m[2] } }] }] }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Picture service error " + r.status);
  return ((j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || []).map((p) => p.text || "").join("").trim();
}
app.post("/api/ai", need, aiLimit, wrap(async (req, res) => {
  if (typeof fetch !== "function") return bad(res, "The server needs Node 18 or newer for the AI.", 500);
  const msgs = (Array.isArray(req.body.messages) ? req.body.messages : [])
    .filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string" && m.content.trim())
    .slice(-6).map((m) => ({ role: m.role, content: m.content.slice(0, m.role === "user" ? 800 : 400) })); // keeps the whole request under the service's 8000-character limit
  if (!msgs.length || msgs[msgs.length - 1].role !== "user") return bad(res, "Type a message first.");
  if (process.env.GEMINI_API_KEY && !req.body.image) { // text: answered by Gemini when its key is set
    try {
      const reply = await geminiChat(msgs);
      if (reply) return res.json({ reply: reply.slice(0, 4000) });
    } catch (e) { /* fall back to the older service below */ }
  }
  if (req.body.image) { // a picture: understood by Gemini (needs GEMINI_API_KEY on the server); the picture is not stored
    if (!process.env.GEMINI_API_KEY) return bad(res, "Picture understanding is not set up yet.", 503);
    const img = String(req.body.image);
    if (!/^data:image\/(jpeg|png|webp);base64,/.test(img) || img.length > 2700000) return bad(res, "Please choose a smaller picture (JPG, PNG or WEBP).");
    try {
      const reply = await geminiLook(msgs[msgs.length - 1].content || "What do you see in this picture? Explain it simply.", img);
      return res.json({ reply: reply || "I could not see anything clearly in that picture." });
    } catch (e) { return bad(res, "The picture service is busy. Try again in a moment.", 502); }
  }
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

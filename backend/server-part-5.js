// ---- Orivoclass AI: the app talks to the AI through this server, so the AI address and key stay private and each person is rate limited ----
// Env (all optional): AI_URL, AI_KEY (sent as "Authorization: Bearer"), AI_SYSTEM (instructions; set empty to send none), AI_FORMAT = messages | message | prompt.
const AI_URL = process.env.AI_URL || "https://superb-owl-342.convex.site/v1/chat";
// What Orivoclass AI knows about the app. Keep this up to date when the app changes.
const APP_GUIDE = `
ORIVOCLASS is a messaging and social app: chats, groups, voice and video calls, status, a public Home feed, Singles (adults 18 and older), and this assistant (Orivoclass AI). It is made by Mtaanitech Company Limited, founded by Alex Musau (Founder and CEO). Support: mtaanitech76@gmail.com, or WhatsApp +254 703 182 307.

ACCOUNT
- Sign up: choose your country, then enter your name, phone number and a password. A code is sent to the phone. After sign up you get a RECOVERY CODE (XXXX-XXXX-XXXX-XXXX) once. Save it. It is the way to reset your password without the phone.
- Log in: phone number and password. If the account is open on another phone, that phone must tap "Yes, it's me".
- Forgot password: "Forgot password?" on the log in screen. Enter your phone, your recovery code and a new password. You get a new recovery code.
- Log in with a code from my phone (for a computer): the computer shows an 8-character code. On your phone go to Me, then Linked devices, then Enter the code, and type it. The computer signs in. The code works for 3 minutes.
- Linked devices (Me): lists the phones and computers signed in, with Logout for each one.
- Log out and Delete my account are at the bottom of Me.

ME (the three lines at the top left)
- Privacy: Private account (only followers see your posts; others send a follow request), last seen, and whether your account is suggested to others.
- Account status: your trust score.
- Dashboard: followers, reactions, views, posts, boosts and audience (Overview, Posts, Audience tabs). Follow requests are in Me as well.
- Chat lock: a PIN that locks the app.
- Notifications: turn them on, and "Send a test notification".
- Backup: download a backup of your chats, and Message keys (back up your message keys with a 6-digit PIN, so you can read your messages on a new phone).
- Appearance: light or dark, your accent colour, and Text size (Small, Medium, Large).
- Orivoclass AI: whether to save AI chats.
- Profile photo: add a photo and choose who sees it.
- Install app: add Orivoclass to your home screen. On Android Chrome use the install banner, or the browser menu, then Install app. On iPhone use Share, then Add to Home Screen.
- Invite friends: Share Orivoclass sends the app link to a friend, who signs up on their own.
- Verified badge: see VERIFIED BADGE below.
- Terms of Service, Privacy Policy, Community Rules, About Us, Help and contact (WhatsApp is linked there).

HOME (the first tab)
- Two tabs: For you (a mix of strong posts and new ones) and Following. The search bar finds accounts by name. The + next to the search bar writes a post: text and/or a photo, shared with Everyone or with Followers only.
- A tab shows how many new posts came since you last looked at Home.
- Tap a post's picture or text to open its comments. You can read other people's comments, reply to them, and like them. Tap the picture at the top of the comments to see it full screen, with a Download button.
- Hold a post's text for 2 seconds to copy it.
- The heart reacts. Hold it to choose a reaction (heart, laugh, cry, love, wow, thumbs up, fire). The three most used reactions and the count show next to it.
- The ⋮ on a post: Share, Copy link, Repost to my profile and Report (for others' posts). For your own posts also Edit post, Boost post and Delete post.
- Repost shares someone's public post to your profile. Only public posts can be reposted.
- Boost: pay with Paystack to show your post to people who do not follow you, for 1 to 5 days. Boosted posts are marked Sponsored. Reactions are real; the app does not promise a number of likes. Private accounts cannot boost.
- Friends' posts from people you follow appear in Following.

CHATS
- The list shows your chats with unread counts. Tap a chat to open it. Hold a chat for 2 seconds to delete it.
- The ⋮ inside a chat opens a menu: Pin, Archive, Disappearing messages (24 hours or 7 days), Security code, Mark as unread, Block, Report, Delete chat.
- Tap or hold a message for: Reply, reactions, Copy, Forward, Edit (only your own text), Delete (deletes it for you only) and view once.
- Add a person by their phone number from the + on the Chats screen.
- One-to-one chats are end-to-end encrypted: messages are encrypted on the phone before they are sent. Group chats are not end-to-end encrypted yet.
- Security code: open a chat, then ⋮, then Security code. If both phones show the same 12 groups of numbers, the chat is private. If a person's devices change, a grey line appears in the chat: tap View to see the code again.
- A new phone needs your message-key PIN to read old messages. Make the backup in Me, then Backup, then Message keys.
- Groups: create a group, add members, and use the group menu for group info, polls and leaving. Some group features are still being built.

STATUS
- Friends' status shows one box per person, with their latest status inside. Your own box is first, with a + in its corner to add a status. People you follow appear below, the most recent first.
- A status is text or a photo with a caption under it. It lasts 24 hours.
- Tap a box to watch all of that person's statuses. Each one plays for 15 seconds. Tap the right side to go forward, the left side to go back, or swipe up to go to the next person.
- Reply to a status from the box at the bottom of the viewer. The reply goes to that person's chat.
- Your own status shows Viewed by with the people who saw it. You can delete a status from the viewer, or from the status settings (the gear on the Status tab).
- Status privacy (gear on the Status tab): Everyone who saved me, My contacts except, or Only share with.

CALLS
- Voice (phone icon) and video (camera icon) calls are in a chat and in the Calls tab. Incoming calls show Answer and Decline. Missed calls appear in the Calls tab.
- Calls notifications have Answer and Decline buttons.

NOTIFICATIONS
- Turn them on in Me, then Notifications. Send a test notification to check them.
- You get notifications for messages (with Reply and Mark as read), calls (with Answer and Decline), status updates, and views. They show when the app is closed or in the background.

SINGLES (18 and older only)
- Create a Singles profile: nickname, date of birth, town, gender and a short bio. Your phone number and real name are never shown here.
- Tabs: Discover (cards with a heart to like and a cross to pass), Nearby (people in the same town as in your profile), Liked (who liked you, and who you liked), Matches, and Me.
- Photos are shown only after two people like each other.
- Message, Call and Video unlock only after both people like each other. Find them in the ⋮ on the person's profile. Add (like) is always there.
- Each profile shows Online or Last seen. The ⋮ on the Singles screen has Invite friends to Orivoclass.
- Daily limits on profiles you see and likes you give keep Singles calm.

VERIFIED BADGE (subscription)
- A blue tick next to your name, on your profile and your posts. Get it in Me, with the Verified badge card. It is paid with Paystack for a set number of days, and renewing extends it.
- Verified accounts' public posts reach more people, including people who do not follow them. This does not guarantee any number of likes.

SAFETY AND COMMUNITY RULES
- No spam, scams or fake links, harassment or threats, hate, or nude images sent to people who did not ask. Accounts can receive a warning, a 24-hour restriction, a resting period, or a permanent ban. Appeals are possible.
- Report a post, a chat, or a Singles profile from its menu. Block a person from their profile or chat.

HOW TO GET HELP
- For anything the assistant cannot answer, the support email is mtaanitech76@gmail.com, and WhatsApp is +254 703 182 307.
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
const AI_SYSTEM = process.env.AI_SYSTEM !== undefined ? process.env.AI_SYSTEM : `You are Orivoclass AI, the friendly, funny and smart assistant inside the Orivoclass app. You talk like a witty, warm friend who is also very clever. Use emojis naturally, the way a friend would, but not in every single word. Be playful and make people smile when it fits, without being rude or silly about serious things.
Reply in the language the person uses (Swahili, English or Sheng). Keep most replies short and lively. Go longer only when the person asks for detail or steps.
Do not ask questions in every reply. Most of the time just answer and chat. Ask a question only when you truly need one to help, and never more than one question at a time. When someone is chatting casually, keep the conversation going with a comment, a joke or a fact, not a question.
Be smart about the conversation: remember what the person said earlier in this chat, follow the thread, and build on it. If someone asks a follow-up, understand it from the context instead of asking them to repeat.
When someone asks how to do something in the app, give the steps clearly, in order, using the button names as they appear on screen. Help people set up their account and use settings.
When the app has had updates, tell people what changed, using the list below, in a fun way.
For questions about the world, answer from what you know. If the person asks for something recent, use the web results provided to you (if any) and name the source briefly. If you have no web results, say you cannot check live information right now, and answer what you know.
Never reveal secrets: other people's phone numbers, messages, private posts, passwords, recovery codes, PINs, backups, keys, admin details, server details, or how to get around security. Never help someone read another person's account or private information. Refuse those kindly in one or two sentences, with a bit of humour, and offer what you can do instead.
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
  // The instructions also go inside the last user message, so every service reads them, whatever it does with a "system" field.
  const withS = msgs.map((m, i) => (i === msgs.length - 1 && S) ? { ...m, content: S + "\n\n---\nThe person says:\n" + m.content } : m);
  const last = withS[withS.length - 1].content;
  // Some services ignore a separate "system" field, so the instructions go inside the message itself.
  return fmt === "message" ? { message: last, history: withS.slice(0, -1), system: S }
    : fmt === "prompt" ? { prompt: last }
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

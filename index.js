/**
 * Node — Staff Application Backend v3
 * npm install express node-fetch dotenv mongodb
 * node index.js
 */

import express         from "express";
import fetch           from "node-fetch";
import path            from "path";
import { fileURLToPath } from "url";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({ limit: "2mb" }));

// ═══════════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════════
const C = {
  CLIENT_ID:     process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  BOT_TOKEN:     process.env.BOT_TOKEN,
  REDIRECT_URI:  process.env.REDIRECT_URI,
  GUILD_ID:      process.env.GUILD_ID,
  REQUIRED_ROLE: process.env.REQUIRED_ROLE,
  ADMIN_ROLE:    process.env.ADMIN_ROLE,
  WEBHOOK_URL:   process.env.WEBHOOK_URL,
  MONGODB_URI:   process.env.MONGODB_URI,
  PORT:          process.env.PORT || 3000,
};

const DISCORD_API = "https://discord.com/api/v10";
const SCOPES      = "identify guilds.members.read";

// ═══════════════════════════════════════════
//  MONGODB
// ═══════════════════════════════════════════
let db;
async function connectDB() {
  const client = new MongoClient(C.MONGODB_URI);
  await client.connect();
  db = client.db("node_staff");
  console.log("✅  MongoDB connected");
}
const col = name => db.collection(name);

// ═══════════════════════════════════════════
//  SESSIONS
// ═══════════════════════════════════════════
const sessions = new Map();
function createSession(userId, data) {
  const tok = Math.random().toString(36).slice(2) + Date.now().toString(36);
  sessions.set(tok, { userId, ...data });
  return tok;
}
function getSession(req) {
  const m = (req.headers.cookie || "").match(/nsession=([^;]+)/);
  return m ? (sessions.get(m[1]) || null) : null;
}
function setSessionCookie(res, tok) {
  res.setHeader("Set-Cookie", `nsession=${tok}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`);
}

// ═══════════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════════
const adminMW = (req, res, next) => {
  const s = getSession(req);
  if (!s || !s.isAdmin) return res.status(403).json({ error: "Admin role required" });
  req.session = s; next();
};

// ═══════════════════════════════════════════
//  ROUTES — PAGES
// ═══════════════════════════════════════════
app.get("/",            (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/admin-login", (_req, res) => res.sendFile(path.join(__dirname, "admin-login.html")));
app.get("/admin", (req, res) => {
  const s = getSession(req);
  if (!s || !s.isAdmin) return res.redirect("/admin-login");
  res.sendFile(path.join(__dirname, "admin.html"));
});

// ═══════════════════════════════════════════
//  OAUTH — PUBLIC FORM
// ═══════════════════════════════════════════
app.get("/auth/discord", (_req, res) => {
  const p = new URLSearchParams({ client_id: C.CLIENT_ID, redirect_uri: C.REDIRECT_URI, response_type: "code", scope: SCOPES });
  res.redirect(`https://discord.com/oauth2/authorize?${p}`);
});

app.get("/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect("/?auth=denied");
  try {
    const tok    = await exchangeCode(code, C.REDIRECT_URI);
    if (!tok)      return res.redirect("/?auth=error");
    const user   = await discordGet(tok, "/users/@me");
    const member = await discordGet(tok, `/users/@me/guilds/${C.GUILD_ID}/member`, true);
    if (!member)   return res.redirect("/?auth=not_in_server");

    const username = member.nick || user.username || "Unknown";
    const avatar   = avatarUrl(user);
    const hasRole  = member.roles?.includes(C.REQUIRED_ROLE);
    const isAdmin  = member.roles?.includes(C.ADMIN_ROLE);

    const session = createSession(user.id, { username, avatar, hasRole, isAdmin, discordId: user.id });
    setSessionCookie(res, session);

    if (!hasRole) return res.redirect(`/?auth=no_role&user=${enc(username)}&avatar=${enc(avatar)}`);
    res.redirect(`/?auth=success&user=${enc(username)}&id=${enc(user.id)}&avatar=${enc(avatar)}`);
  } catch (e) { console.error("Callback error:", e); res.redirect("/?auth=error"); }
});

// ═══════════════════════════════════════════
//  OAUTH — ADMIN PORTAL
// ═══════════════════════════════════════════
const adminRedirect = () => C.REDIRECT_URI.replace("/callback", "/admin/callback");

app.get("/auth/discord/admin", (_req, res) => {
  const p = new URLSearchParams({ client_id: C.CLIENT_ID, redirect_uri: adminRedirect(), response_type: "code", scope: SCOPES });
  res.redirect(`https://discord.com/oauth2/authorize?${p}`);
});

app.get("/admin/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect("/admin-login?auth=denied");
  try {
    const tok    = await exchangeCode(code, adminRedirect());
    if (!tok)      return res.redirect("/admin-login?auth=error");
    const user   = await discordGet(tok, "/users/@me");
    const member = await discordGet(tok, `/users/@me/guilds/${C.GUILD_ID}/member`, true);
    if (!member)   return res.redirect("/admin-login?auth=not_in_server");

    const isAdmin = member.roles?.includes(C.ADMIN_ROLE);
    if (!isAdmin)  return res.redirect("/admin-login?auth=no_role");

    const username = member.nick || user.username || "Unknown";
    const avatar   = avatarUrl(user);
    const session  = createSession(user.id, { username, avatar, isAdmin: true, discordId: user.id });
    setSessionCookie(res, session);
    res.redirect("/admin");
  } catch (e) { console.error("Admin callback error:", e); res.redirect("/admin-login?auth=error"); }
});

// ═══════════════════════════════════════════
//  API — SESSION
// ═══════════════════════════════════════════
app.get("/api/me", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });
  res.json({ username: s.username, avatar: s.avatar, isAdmin: s.isAdmin });
});

app.get("/logout", (req, res) => {
  const m = (req.headers.cookie || "").match(/nsession=([^;]+)/);
  if (m) sessions.delete(m[1]);
  res.setHeader("Set-Cookie", "nsession=; HttpOnly; Path=/; Max-Age=0");
  res.redirect("/");
});

// ═══════════════════════════════════════════
//  API — QUESTIONS
// ═══════════════════════════════════════════
const DEFAULT_QUESTIONS = [
  { id:"why",           label:"Why do you want to be on staff?",              type:"textarea", required:true,  maxLen:600, placeholder:"Tell us your genuine motivation — give us specifics." },
  { id:"serverInvites", label:"Current Server Invite Links",                  type:"textarea", required:true,  maxLen:800, placeholder:"discord.gg/example — Server (role: Moderator)\n\nNo experience? Type: N/A" },
  { id:"prevServers",   label:"Previous Server(s) & Role(s)",                 type:"textarea", required:false, maxLen:700, placeholder:"Server name, approx member count, role, duration." },
  { id:"conflict",      label:"How do you handle conflict between members?",  type:"textarea", required:true,  maxLen:600, placeholder:"Step-by-step from detection to resolution." },
  { id:"situation",     label:"Describe a specific moderation situation",      type:"textarea", required:false, maxLen:700, placeholder:"Real or hypothetical. N/A if none." },
  { id:"scenA", label:"Scenario A — Rule Violation by a Friend",              type:"scenario", required:true,  maxLen:500, body:"A close friend who's been in the server for years keeps making borderline offensive jokes. Others are complaining. How do you handle it?" },
  { id:"scenB", label:"Scenario B — Disagreement with Another Mod",           type:"scenario", required:true,  maxLen:500, body:"You think another moderator was too harsh. What do you do?" },
  { id:"scenC", label:"Scenario C — Raid in Progress",                        type:"scenario", required:true,  maxLen:500, body:"The server is being raided. Dozens of accounts spamming NSFW across every channel. You're the only mod online. Immediate steps?" },
  { id:"scenD", label:"Scenario D — Member Threatening Self-Harm",            type:"scenario", required:true,  maxLen:500, body:"A member implies they may hurt themselves in public chat. Others are panicking. What is your response?" },
  { id:"scenE", label:"Scenario E — False Report",                            type:"scenario", required:true,  maxLen:500, body:"A user reports harassment but logs show no evidence. You suspect it's fabricated. How do you proceed?" },
  { id:"scenF", label:"Scenario F — Doxxing Attempt",                         type:"scenario", required:true,  maxLen:500, body:"A user posts another member's real name and location publicly. What do you do immediately and what follows?" },
  { id:"scenG", label:"Scenario G — Disagreement with a Rule",                type:"scenario", required:true,  maxLen:500, body:"You personally disagree with a server rule. A member is currently breaking it. What do you do?" },
  { id:"scenH", label:"Scenario H — Coordinated Spam Bot Infiltration",       type:"scenario", required:true,  maxLen:500, body:"Accounts that joined weeks ago start mass-pinging and posting phishing links simultaneously. Action plan?" },
  { id:"skills",label:"Additional Skills or Qualifications",                  type:"textarea", required:false, maxLen:400, placeholder:"Design, bots, event planning, languages, etc." },
];

app.get("/api/questions", async (_req, res) => {
  try {
    const doc = await col("config").findOne({ _id: "questions" });
    res.json(doc ? doc.questions : DEFAULT_QUESTIONS);
  } catch { res.json(DEFAULT_QUESTIONS); }
});

app.put("/api/questions", adminMW, async (req, res) => {
  try {
    if (!Array.isArray(req.body)) return res.status(400).json({ error: "Expected array" });
    await col("config").replaceOne({ _id: "questions" }, { _id: "questions", questions: req.body }, { upsert: true });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.post("/api/questions/reset", adminMW, async (_req, res) => {
  try {
    await col("config").deleteOne({ _id: "questions" });
    res.json({ ok: true, questions: DEFAULT_QUESTIONS });
  } catch { res.status(500).json({ error: "DB error" }); }
});

// ═══════════════════════════════════════════
//  API — APPLICATIONS
// ═══════════════════════════════════════════
app.get("/api/applications", adminMW, async (_req, res) => {
  try { res.json(await col("applications").find({}).sort({ _submittedAt: -1 }).toArray()); }
  catch { res.status(500).json({ error: "DB error" }); }
});

app.post("/api/applications", adminMW, async (req, res) => {
  try {
    const doc = { ...req.body, _submittedAt: new Date(), _appId: "NODE-" + Math.random().toString(36).slice(2,11).toUpperCase(), _status: req.body._status || "pending", _manual: true, _addedBy: req.session.username };
    const r = await col("applications").insertOne(doc);
    res.json({ ok: true, id: r.insertedId, appId: doc._appId });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.patch("/api/applications/:id/status", adminMW, async (req, res) => {
  try {
    const { status, note } = req.body;
    if (!["pending","approved","denied"].includes(status)) return res.status(400).json({ error: "Invalid status" });
    await col("applications").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { _status: status, _reviewNote: note || "", _reviewedBy: req.session.username, _reviewedAt: new Date() } }
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "DB error" }); }
});

app.delete("/api/applications/:id", adminMW, async (req, res) => {
  try { await col("applications").deleteOne({ _id: new ObjectId(req.params.id) }); res.json({ ok: true }); }
  catch { res.status(500).json({ error: "DB error" }); }
});

// ═══════════════════════════════════════════
//  SUBMIT — from public form → MongoDB + webhook
// ═══════════════════════════════════════════
app.post("/submit", async (req, res) => {
  try {
    const s   = getSession(req);
    const doc = {
      ...req.body,
      _submittedAt: new Date(),
      _submittedBy: s?.userId   || "unknown",
      _displayName: s?.username || "Unknown",
      _avatar:      s?.avatar   || "",
      _discordId:   s?.discordId || "",
      _appId:       req.body.content?.match(/NODE-[A-Z0-9]+/)?.[0] || "NODE-" + Math.random().toString(36).slice(2,11).toUpperCase(),
      _status:      "pending",
      _manual:      false,
    };
    await col("applications").insertOne(doc);
    await fetch(C.WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req.body) });
    res.json({ ok: true });
  } catch (e) { console.error("Submit error:", e); res.status(500).json({ ok: false }); }
});

// ═══════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════
async function exchangeCode(code, redirectUri) {
  const r = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: C.CLIENT_ID, client_secret: C.CLIENT_SECRET, grant_type: "authorization_code", code, redirect_uri: redirectUri }),
  });
  const d = await r.json();
  if (!d.access_token) { console.error("Token exchange failed:", d); return null; }
  return d.access_token;
}
async function discordGet(token, endpoint, nullOn404 = false) {
  const r = await fetch(`${DISCORD_API}${endpoint}`, { headers: { Authorization: `Bearer ${token}` } });
  if (nullOn404 && !r.ok) return null;
  return r.json();
}
function avatarUrl(user) {
  return user.avatar
    ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
    : `https://cdn.discordapp.com/embed/avatars/${(BigInt(user.id) >> 22n) % 6n}.png`;
}
const enc = encodeURIComponent;

// ═══════════════════════════════════════════
//  START
// ═══════════════════════════════════════════
connectDB().then(() => {
  app.listen(C.PORT, "0.0.0.0", () => {
    console.log(`\n✅  Server → http://localhost:${C.PORT}`);
    console.log(`🔗  Redirect URI:       ${C.REDIRECT_URI}`);
    console.log(`🔗  Admin Redirect URI: ${adminRedirect()}\n`);
  });
}).catch(e => { console.error("❌  MongoDB failed:", e.message); process.exit(1); });

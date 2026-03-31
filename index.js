/**
 * Moderator Application — Discord OAuth Backend
 * -----------------------------------------------
 * Fill in your credentials in the CONFIG block below.
 * Run: npm install express node-fetch dotenv
 * Start: node index.js
 */

import express from "express";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";
import "dotenv/config";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
app.use(express.static(__dirname)); // serves index.html from same folder

// ═══════════════════════════════════════════════════════════════
//  CONFIG — Replace these with your real values
// ═══════════════════════════════════════════════════════════════
const CONFIG = {
  CLIENT_ID:     process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  BOT_TOKEN:     process.env.BOT_TOKEN,
  REDIRECT_URI:  process.env.REDIRECT_URI,
  GUILD_ID:      process.env.GUILD_ID,
  REQUIRED_ROLE: process.env.REQUIRED_ROLE,
  WEBHOOK_URL:   process.env.WEBHOOK_URL,
  PORT:          process.env.PORT || 3000,
};
// ═══════════════════════════════════════════════════════════════

const DISCORD_API = "https://discord.com/api/v10";
const SCOPES      = "identify guilds.members.read";

// ─── OAuth Step 1: Redirect to Discord ─────────────────────────
app.get("/auth/discord", (_req, res) => {
  const params = new URLSearchParams({
    client_id:     CONFIG.CLIENT_ID,
    redirect_uri:  CONFIG.REDIRECT_URI,
    response_type: "code",
    scope:         SCOPES,
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

// ─── OAuth Step 2: Discord redirects back here ─────────────────
app.get("/callback", async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    return res.redirect("/?auth=denied");
  }

  try {
    // Exchange code for access token
    const tokenRes = await fetch(`${DISCORD_API}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id:     CONFIG.CLIENT_ID,
        client_secret: CONFIG.CLIENT_SECRET,
        grant_type:    "authorization_code",
        code,
        redirect_uri:  CONFIG.REDIRECT_URI,
      }),
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error("Token exchange failed:", tokenData);
      return res.redirect("/?auth=error");
    }

    const accessToken = tokenData.access_token;

    // Fetch basic user info
    const userRes  = await fetch(`${DISCORD_API}/users/@me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const user = await userRes.json();

    // Fetch guild member info (requires guilds.members.read scope + bot in server)
    const memberRes = await fetch(
      `${DISCORD_API}/users/@me/guilds/${CONFIG.GUILD_ID}/member`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    let hasRole = false;
    let username = user.username || "Unknown";
    let avatar   = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
      : `https://cdn.discordapp.com/embed/avatars/${(BigInt(user.id) >> 22n) % 6n}.png`;

    if (memberRes.ok) {
      const member = await memberRes.json();
      hasRole = member.roles?.includes(CONFIG.REQUIRED_ROLE);
      if (member.nick) username = member.nick;
    } else {
      // User is not in the guild at all
      return res.redirect("/?auth=not_in_server");
    }

    if (!hasRole) {
      return res.redirect(`/?auth=no_role&user=${encodeURIComponent(username)}&avatar=${encodeURIComponent(avatar)}`);
    }

    // Success — pass user info to the form page
    res.redirect(
      `/?auth=success&user=${encodeURIComponent(username)}&id=${encodeURIComponent(user.id)}&avatar=${encodeURIComponent(avatar)}`
    );

  } catch (err) {
    console.error("OAuth callback error:", err);
    res.redirect("/?auth=error");
  }
});

// ─── Webhook Proxy: submit application to Discord ──────────────
app.post("/submit", async (req, res) => {
  try {
    const response = await fetch(CONFIG.WEBHOOK_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(req.body),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error("Webhook error:", text);
      return res.status(500).json({ ok: false, error: "Webhook delivery failed" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error("Submit error:", err);
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.listen(process.env.PORT || 3000, "0.0.0.0", () => {
  console.log(`\n✅  Server running → http://localhost:${process.env.PORT || 3000}`);
  console.log(`🔗  Add this to Discord Dev Portal as Redirect URI:`);
  console.log(`    ${process.env.REDIRECT_URI}\n`);
});

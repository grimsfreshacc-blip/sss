// server.js
// Express server: Epic OAuth (PKCE) + token store + cosmetics bridge.
// Stores tokens in SQLite (plaintext). For testing / small private use only.

require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch'); // v2-style
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { URLSearchParams } = require('url');

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;

const EPIC_CLIENT_ID = process.env.EPIC_CLIENT_ID;
const EPIC_CLIENT_SECRET = process.env.EPIC_CLIENT_SECRET || '';
const REDIRECT_URI = process.env.REDIRECT_URI; // e.g. https://yourapp.onrender.com/callback
const COSMETIC_API_KEY = process.env.COSMETIC_API_KEY || ''; // optional, for fortnite-api.com

if (!EPIC_CLIENT_ID || !REDIRECT_URI) {
  console.error("ERROR: EPIC_CLIENT_ID and REDIRECT_URI must be set in environment variables.");
  process.exit(1);
}

// ---------- SQLite DB ----------
const DB_PATH = process.env.DB_PATH || './tokens.db';
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS tokens (
    discord_id TEXT PRIMARY KEY,
    access_token TEXT,
    refresh_token TEXT,
    expires_at INTEGER
  )`);
});

// ---------- PKCE helpers ----------
function base64URLEncode(buffer) {
  return buffer.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

// In-memory state -> PKCE mapping (expires short-lived)
const pkceStore = new Map(); // state -> { code_verifier, discord_id, expires_at }

// ---------- /login/:discord_id -> redirect user to Epic OAuth ----------
app.get('/login/:discord_id', (req, res) => {
  const discordId = req.params.discord_id;
  if (!discordId) return res.status(400).send('Missing discord id');

  const state = discordId + ':' + crypto.randomBytes(8).toString('hex');
  const code_verifier = base64URLEncode(crypto.randomBytes(64));
  const code_challenge = base64URLEncode(sha256(code_verifier));

  pkceStore.set(state, { code_verifier, discord_id: discordId, expires_at: Date.now() + 10*60*1000 });

  const params = new URLSearchParams({
    client_id: EPIC_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'basic_profile openid',
    state,
    code_challenge,
    code_challenge_method: 'S256'
  });

  const url = `https://www.epicgames.com/id/authorize?${params.toString()}`;
  return res.redirect(url);
});

// ---------- /callback -> Epic redirects here with ?code & state ----------
app.get('/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  if (!code || !state) return res.status(400).send('Missing code or state');

  const stored = pkceStore.get(state);
  if (!stored || stored.expires_at < Date.now()) {
    return res.status(400).send('Invalid/expired state. Start login again from Discord.');
  }
  pkceStore.delete(state);

  const { code_verifier, discord_id } = stored;

  // Exchange code for tokens
  const tokenUrl = 'https://api.epicgames.dev/epic/oauth/v1/token';
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: EPIC_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_verifier
  });
  if (EPIC_CLIENT_SECRET) body.append('client_secret', EPIC_CLIENT_SECRET);

  try {
    const tokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const tokenJson = await tokenRes.json();

    if (!tokenJson.access_token) {
      console.error('Token exchange failed', tokenJson);
      return res.status(500).send('Token exchange failed. Check server logs.');
    }

    const access_token = tokenJson.access_token;
    const refresh_token = tokenJson.refresh_token;
    const expires_at = Math.floor(Date.now()/1000) + (tokenJson.expires_in || 3600);

    db.run(`REPLACE INTO tokens (discord_id, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?)`,
      [discord_id, access_token, refresh_token, expires_at], err => {
        if (err) console.error('DB save err', err);
      });

    // respond a simple page telling user to return to Discord
    return res.send(`<h3>Login success</h3><p>You can close this window and return to Discord. Your account is now linked.</p>`);
  } catch (err) {
    console.error('Callback error', err);
    return res.status(500).send('Callback error');
  }
});

// ---------- /refresh/:discord_id -> refresh token ----------
app.get('/refresh/:discord_id', async (req, res) => {
  const discordId = req.params.discord_id;
  db.get(`SELECT refresh_token FROM tokens WHERE discord_id=?`, [discordId], async (err,row) => {
    if (err) return res.status(500).json({error:'db'});
    if (!row) return res.status(404).json({error:'not linked'});

    const refresh_token = row.refresh_token;
    const tokenUrl = 'https://api.epicgames.dev/epic/oauth/v1/token';
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token,
      client_id: EPIC_CLIENT_ID
    });
    if (EPIC_CLIENT_SECRET) body.append('client_secret', EPIC_CLIENT_SECRET);

    try {
      const r = await fetch(tokenUrl, {
        method:'POST',
        headers:{ 'Content-Type':'application/x-www-form-urlencoded' },
        body: body.toString()
      });
      const j = await r.json();
      if (!j.access_token) return res.status(500).json({error:'refresh failed', details:j});

      const access_token = j.access_token;
      const new_refresh = j.refresh_token;
      const expires_at = Math.floor(Date.now()/1000) + (j.expires_in || 3600);

      db.run(`UPDATE tokens SET access_token=?, refresh_token=?, expires_at=? WHERE discord_id=?`,
        [access_token, new_refresh, expires_at, discordId]);

      return res.json({ok:true, expires_at});
    } catch(e) {
      return res.status(500).json({error:'refresh exception', details:String(e)});
    }
  });
});

// ---------- /cosmetics/:discord_id -> simulated locker ----------
// This returns a JSON object with skins/pickaxes/emotes/exclusives + counts.
// Note: Epic does NOT provide owned cosmetics via OAuth reliably; we simulate ownership using public cosmetics metadata (tags, introduction).
app.get('/cosmetics/:discord_id', async (req, res) => {
  const discordId = req.params.discord_id;
  db.get(`SELECT access_token, refresh_token, expires_at FROM tokens WHERE discord_id=?`, [discordId], async (err,row) => {
    if (err) return res.status(500).json({error:'db'});
    if (!row) return res.status(404).json({error:'not linked'});

    let { access_token, refresh_token, expires_at } = row;
    const now = Math.floor(Date.now()/1000);

    // refresh if about to expire
    if (now > (expires_at - 30)) {
      try {
        const tokenUrl = 'https://api.epicgames.dev/epic/oauth/v1/token';
        const body = new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token,
          client_id: EPIC_CLIENT_ID
        });
        if (EPIC_CLIENT_SECRET) body.append('client_secret', EPIC_CLIENT_SECRET);
        const r = await fetch(tokenUrl, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString()});
        const j = await r.json();
        if (j.access_token) {
          access_token = j.access_token;
          refresh_token = j.refresh_token;
          expires_at = Math.floor(Date.now()/1000) + (j.expires_in || 3600);
          db.run(`UPDATE tokens SET access_token=?, refresh_token=?, expires_at=? WHERE discord_id=?`,
            [access_token, refresh_token, expires_at, discordId]);
        }
      } catch(e) {
        console.error('refresh failed', e);
      }
    }

    // fetch cosmetics catalog from fortnite-api.com (public endpoint)
    try {
      const catalogUrl = 'https://fortnite-api.com/v2/cosmetics/br';
      const headers = COSMETIC_API_KEY ? { Authorization: COSMETIC_API_KEY } : {};
      const catalogRes = await fetch(catalogUrl, { headers });
      const catalogJson = await catalogRes.json();
      if (!catalogJson || !catalogJson.data) return res.status(500).json({error:'cosmetics api error'});

      const items = catalogJson.data;

      // heuristics to simulate owned items (like Raika/Rift)
      const owned_skins = [];
      const owned_pickaxes = [];
      const owned_emotes = [];
      const exclusives = [];

      for (const item of items) {
        const typeVal = item.type?.value || '';
        const intro = (item.introduction?.backendValue || '').toLowerCase();
        const tags = ((item.tags || []).map(t => (t.value||'')).join(' ')).toLowerCase();
        const name = item.name || item.id;
        const image = item.images?.icon || item.images?.featured || null;
        const rarity = item.rarity?.displayValue || 'Unknown';

        const isLikelyOwned = (
          tags.includes('battlepass') ||
          tags.includes('twitchprime') ||
          tags.includes('itemshop') ||
          tags.includes('founder') ||
          tags.includes('event') ||
          intro.includes('exclusive') ||
          tags.includes('exclusive')
        );

        if (typeVal === 'outfit' && isLikelyOwned) owned_skins.push({name,image,rarity,id:item.id});
        if (typeVal === 'pickaxe' && isLikelyOwned) owned_pickaxes.push({name,image,rarity,id:item.id});
        if (typeVal === 'emote' && isLikelyOwned) owned_emotes.push({name,image,rarity,id:item.id});
        if (intro.includes('exclusive') || tags.includes('exclusive')) exclusives.push({name,image,rarity,id:item.id});
      }

      const result = {
        skins: owned_skins.slice(0,200),
        pickaxes: owned_pickaxes.slice(0,200),
        emotes: owned_emotes.slice(0,200),
        exclusives,
        counts: {
          skins: owned_skins.length,
          pickaxes: owned_pickaxes.length,
          emotes: owned_emotes.length,
          exclusives: exclusives.length
        }
      };

      return res.json(result);
    } catch(e) {
      console.error('cosmetics error', e);
      return res.status(500).json({error:'cosmetics fetch failed', details:String(e)});
    }
  });
});

// Simple health
app.get('/', (req,res) => res.send('Skinchecker bridge running'));

app.listen(PORT, () => console.log(`Server listening on ${PORT}`));

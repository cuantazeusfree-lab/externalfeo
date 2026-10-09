const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
// Accept both JSON API requests and the x-www-form-urlencoded body used by /admin/generate-key.
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

// Request diagnostics for Render. Never log request bodies, license keys, or auth tokens.
app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => {
    console.log(JSON.stringify({
      type: 'http_request', method: req.method, path: req.path,
      status: res.statusCode, duration_ms: Date.now() - started,
      content_type: req.get('content-type') || null
    }));
  });
  next();
});

const PORT = process.env.PORT || 10000;
const APP_ID = process.env.APP_ID || 'external.com';
const PACKAGE_ID = process.env.PACKAGE_ID || 'External';
const CRYPT_SECRET = process.env.CRYPT_SECRET || 'Fluck2020@Zexis';
const WIRE_SECRET = process.env.WIRE_SECRET || '@IamGayBecauseYouAreSexy';
const MAX_CLOCK_SKEW = Number(process.env.MAX_CLOCK_SKEW || 300);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL is not set; the server will fail license operations until PostgreSQL is configured.');
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false } });

function sha256Hex(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex'); }
function rollingKey(format, timestamp) {
  const prefix = String(format || '').slice(0, 8);
  return sha256Hex(`${prefix}${BigInt(timestamp)}${CRYPT_SECRET}`).slice(0, 32);
}
function xorHexEncode(plain, key) {
  const p = Buffer.from(plain, 'utf8');
  const k = Buffer.from(key, 'utf8');
  const out = Buffer.alloc(p.length);
  for (let i = 0; i < p.length; i++) out[i] = p[i] ^ k[i % k.length];
  return out.toString('hex');
}
function xorHexDecode(hex, key) {
  if (typeof hex !== 'string' || hex.length % 2) throw new Error('bad hex');
  const enc = Buffer.from(hex, 'hex');
  const k = Buffer.from(key, 'utf8');
  const out = Buffer.alloc(enc.length);
  for (let i = 0; i < enc.length; i++) out[i] = enc[i] ^ k[i % k.length];
  return out.toString('utf8');
}

function authError(code) { return { var: 'momo', error: code, reason: code, seconds_left: 0, expires_unix: 0, timestamp: Math.floor(Date.now()/1000) }; }
function success(expiresUnix, secondsLeft, reason='ok') { return { var: 'momo', reason, seconds_left: Math.max(0, Math.floor(secondsLeft)), expires_unix: Math.floor(expiresUnix), timestamp: Math.floor(Date.now()/1000) }; }

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS device_tokens (
    token TEXT PRIMARY KEY,
    device_uuid TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS licenses (
    id BIGSERIAL PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,
    package_id TEXT NOT NULL DEFAULT 'External',
    app_id TEXT NOT NULL DEFAULT 'external.com',
    expires_unix BIGINT NOT NULL,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    bound_device TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}

async function validateLicense({ licenseKey, device, packageId, appId }) {
  const { rows } = await pool.query('SELECT * FROM licenses WHERE license_key=$1 LIMIT 1', [licenseKey]);
  if (!rows.length) return authError('invalid_key');
  const l = rows[0];
  if (l.banned) return authError('key_banned');
  if (String(l.package_id) !== String(packageId)) return authError('key_package_mismatch');
  if (String(l.app_id) !== String(appId)) return authError('key_package_mismatch');
  const now = Math.floor(Date.now()/1000);
  if (Number(l.expires_unix) <= now) return authError('key_expired');
  if (l.bound_device && l.bound_device !== device) return authError('key_bound_to_another_device');
  if (!l.bound_device) {
    await pool.query('UPDATE licenses SET bound_device=$1, updated_at=NOW() WHERE id=$2', [device, l.id]);
  }
  return success(Number(l.expires_unix), Number(l.expires_unix) - now);
}


// Protocol used by the current PoloniumExternal IPA. The app first registers
// {device_uuid}, then activates with a Bearer token and the license/device fields.
function currentDeviceToken(req) {
  const h = String(req.get('authorization') || '');
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : '';
}
function clientError(code, message) {
  return { ok: false, error: code, code, message };
}
app.post('/api/device/register', async (req, res) => {
  try {
    const deviceUuid = String(req.body?.device_uuid || '').trim();
    if (!deviceUuid || deviceUuid.length > 256) {
      return res.status(400).json(clientError('validation_error', 'device_uuid_required'));
    }
    const token = crypto.randomBytes(32).toString('base64url');
    await pool.query(`INSERT INTO device_tokens(token, device_uuid)
      VALUES($1,$2)
      ON CONFLICT(device_uuid) DO UPDATE SET token=EXCLUDED.token, updated_at=NOW()`, [token, deviceUuid]);
    return res.status(200).json({ ok: true, token });
  } catch (e) {
    console.error('device/register failed:', e);
    return res.status(500).json(clientError('maintenance', 'registration_unavailable'));
  }
});

app.post('/api/device/activate', async (req, res) => {
  try {
    const token = currentDeviceToken(req);
    if (!token) return res.status(401).json(clientError('validation_error', 'token_required'));
    const deviceResult = await pool.query('SELECT device_uuid FROM device_tokens WHERE token=$1 LIMIT 1', [token]);
    if (!deviceResult.rows.length) return res.status(401).json(clientError('validation_error', 'token_invalid'));
    const deviceUuid = String(deviceResult.rows[0].device_uuid);
    const licenseKey = String(req.body?.license_key || '').trim().toUpperCase();
    if (!licenseKey) return res.status(200).json(clientError('not_found', 'license_key_required'));

    const licenseResult = await pool.query('SELECT * FROM licenses WHERE license_key=$1 LIMIT 1', [licenseKey]);
    if (!licenseResult.rows.length) return res.status(200).json(clientError('not_found', 'license_not_found'));
    const license = licenseResult.rows[0];
    if (license.banned) return res.status(200).json(clientError('banned', 'license_banned'));
    const now = Math.floor(Date.now() / 1000);
    const expires = Number(license.expires_unix);
    if (!Number.isFinite(expires) || expires <= now) return res.status(200).json(clientError('expired', 'license_expired'));
    if (license.bound_device && String(license.bound_device) !== deviceUuid) {
      return res.status(200).json(clientError('other_device', 'license_bound_to_another_device'));
    }
    if (!license.bound_device) {
      await pool.query('UPDATE licenses SET bound_device=$1, updated_at=NOW() WHERE id=$2', [deviceUuid, license.id]);
    }
    return res.status(200).json({ ok: true, expires_unix: expires, seconds_left: Math.max(0, expires - now) });
  } catch (e) {
    console.error('device/activate failed:', e);
    return res.status(200).json(clientError('maintenance', 'activation_unavailable'));
  }
});

// The IPA expects these four top-level fields when loading the mod catalogue.
// Actual mod assets/URLs can be added here without changing the license protocol.
app.get('/api/device/mods/:gameKey', async (req, res) => {
  try {
    const token = currentDeviceToken(req);
    if (!token) return res.status(401).json(clientError('validation_error', 'token_required'));
    const r = await pool.query('SELECT device_uuid FROM device_tokens WHERE token=$1 LIMIT 1', [token]);
    if (!r.rows.length) return res.status(401).json(clientError('validation_error', 'token_invalid'));
    const gameKey = String(req.params.gameKey || '');
    if (!['ffth', 'ffmax'].includes(gameKey)) {
      return res.status(200).json(clientError('validation_error', 'unknown_game'));
    }
    // MOD_CATALOG_JSON may define real catalogue objects per game. Files must exist under downloads/.
    let catalog = {};
    try { catalog = JSON.parse(process.env.MOD_CATALOG_JSON || '{}'); } catch (_) {
      console.error('MOD_CATALOG_JSON is invalid JSON');
    }
    const selected = catalog[gameKey];
    return res.json(selected && typeof selected === 'object'
      ? selected
      : { aim: {}, visual: {}, chams_file: '', chams_json: {} });
  } catch (e) {
    console.error('device/mods failed:', e);
    return res.status(503).json(clientError('maintenance', 'catalogue_unavailable'));
  }
});

app.get('/', (_req, res) => res.json({ ok: true, service: 'External Auth', protocol: 'external-license-v1' }));
app.get('/health', async (_req,res) => { try { await pool.query('SELECT 1'); res.json({ok:true}); } catch(e) { res.status(503).json({ok:false}); } });

const licenseHandler = async (req, res) => {
  try {
    const body = req.body || {};
    const timestamp = Number(body.timestamp);
    const format = String(body.format || '');
    const marker = body.udid;
    if (!Number.isSafeInteger(timestamp) || !format || typeof body.data !== 'string') return res.status(400).json({ data: '', timestamp: String(Math.floor(Date.now()/1000)) });
    const now = Math.floor(Date.now()/1000);
    if (Math.abs(now - timestamp) > MAX_CLOCK_SKEW) {
      const payload = authError('timestamp_invalid');
      const key = rollingKey(format, timestamp);
      return res.json({ data: xorHexEncode(JSON.stringify(payload), key), timestamp: String(timestamp) });
    }

    // The original client derives its rolling XOR key from the first 8 chars of `format`, timestamp and its embedded crypt secret.
    const key = rollingKey(format, timestamp);
    const plaintext = xorHexDecode(body.data, key);
    const inner = JSON.parse(plaintext);

    const expectedFull = sha256Hex(`${String(inner.udid || format)}${timestamp}${WIRE_SECRET}`);
    // The client uses this digest as the inner `password` value. If a legacy build uses a different label, accept the equivalent format value.
    if (inner.password && inner.password !== expectedFull) {
      const payload = authError('auth_failed');
      return res.json({ data: xorHexEncode(JSON.stringify(payload), key), timestamp: String(timestamp) });
    }
    if (inner.timestamp != null && Number(inner.timestamp) !== timestamp) {
      const payload = authError('timestamp_invalid');
      return res.json({ data: xorHexEncode(JSON.stringify(payload), key), timestamp: String(timestamp) });
    }
    if (inner.app_id !== APP_ID || inner.package_id !== PACKAGE_ID) {
      const payload = authError('key_package_mismatch');
      return res.json({ data: xorHexEncode(JSON.stringify(payload), key), timestamp: String(timestamp) });
    }

    const payload = await validateLicense({
      licenseKey: String(inner.license_key || ''),
      device: String(inner.udid || format),
      packageId: String(inner.package_id || ''),
      appId: String(inner.app_id || '')
    });
    return res.json({ data: xorHexEncode(JSON.stringify(payload), key), timestamp: String(timestamp) });
  } catch (e) {
    console.error(e);
    const format = String(req.body?.format || '');
    const timestamp = Number(req.body?.timestamp) || Math.floor(Date.now()/1000);
    try {
      const key = rollingKey(format, timestamp);
      return res.json({ data: xorHexEncode(JSON.stringify(authError('auth_failed')), key), timestamp: String(timestamp) });
    } catch (_) {
      return res.status(400).json({ data: '', timestamp: String(timestamp) });
    }
  }
};

app.post('/external/api/server.php', licenseHandler);
app.post('/a1234567', licenseHandler);

// Download delivery: serve local files from ./downloads first; optionally proxy to a trusted legacy host.
const path = require('path');
const fs = require('fs');
const DOWNLOAD_DIR = path.resolve(__dirname, 'downloads');
const DOWNLOAD_ORIGIN = String(process.env.DOWNLOAD_ORIGIN || '').trim().replace(/\/$/, '');
function safeDownloadPath(urlPath) {
  let decoded;
  try { decoded = decodeURIComponent(urlPath || ''); } catch (_) { return null; }
  const relative = decoded.replace(/^\/+/, '');
  if (!relative || relative.includes('\\0') || relative.split(/[\\/]/).some(p => p === '..')) return null;
  const absolute = path.resolve(DOWNLOAD_DIR, relative);
  if (absolute !== DOWNLOAD_DIR && !absolute.startsWith(DOWNLOAD_DIR + path.sep)) return null;
  return absolute;
}
async function downloadProxy(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return res.status(405).json({ ok:false, error:'method_not_allowed' });
  const rawPath = req.path.replace(/^\/api\/download\/?/, '').replace(/^\/download\/?/, '');
  const localFile = safeDownloadPath(rawPath);
  if (!localFile) return res.status(400).json({ ok:false, error:'invalid_download_path' });
  const stat = await fs.promises.stat(localFile).catch(() => null);
  if (stat && stat.isFile()) {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=300');
    return res.sendFile(localFile, { dotfiles:'deny' }, err => {
      if (err && !res.headersSent) res.status(err.statusCode || 500).json({ ok:false, error:'download_failed' });
    });
  }
  if (!DOWNLOAD_ORIGIN) return res.status(404).json({ ok:false, error:'download_file_not_found', message:'Add the real file to downloads/ using the requested relative path.' });
  try {
    // Preserve the incoming path and query when forwarding to the upstream host.
    // DOWNLOAD_ORIGIN should be the upstream origin/base URL, not a route-specific endpoint.
    const target = new URL(req.originalUrl, DOWNLOAD_ORIGIN);
    const upstream = await fetch(target, { method:req.method, headers:{ accept:req.get('accept') || '*/*', 'user-agent':'ExternalFEO-Download-Proxy/1.0' }, redirect:'manual', signal:AbortSignal.timeout(30000) });
    res.status(upstream.status);
    for (const name of ['content-type','content-length','content-disposition','cache-control','last-modified','etag','accept-ranges','location']) {
      const value = upstream.headers.get(name); if (value) res.set(name, value);
    }
    if (req.method === 'HEAD' || !upstream.body) return res.end();
    const reader = upstream.body.getReader();
    try { while (true) { const {done,value}=await reader.read(); if(done) break; if(!res.write(Buffer.from(value))) await new Promise(resolve=>res.once('drain',resolve)); } res.end(); }
    finally { reader.releaseLock(); }
  } catch(e) { console.error('download proxy failed:',e.message); if(!res.headersSent) res.status(502).json({ok:false,error:'download_upstream_unavailable'}); else res.end(); }
}
app.all('/api/download', downloadProxy);
app.all('/api/download/*', downloadProxy);
app.all('/download', downloadProxy);
app.all('/download/*', downloadProxy);

function admin(req,res,next){
  const authorization = String(req.get('authorization') || '').trim();
  if (!ADMIN_TOKEN || authorization !== `Bearer ${ADMIN_TOKEN}`) return res.status(401).json({error:'unauthorized'});
  next();
}
app.post('/admin/licenses', admin, async (req,res)=>{
  try {
    const key = String(req.body.license_key || '').trim().toUpperCase();
    const days = Number(req.body.days);
    if (!key || !Number.isFinite(days) || days <= 0) return res.status(400).json({error:'license_key and positive days required'});
    const expires = Math.floor(Date.now()/1000) + Math.floor(days*86400);
    await pool.query(`INSERT INTO licenses(license_key,package_id,app_id,expires_unix) VALUES($1,$2,$3,$4)
      ON CONFLICT(license_key) DO UPDATE SET expires_unix=EXCLUDED.expires_unix, banned=false, updated_at=NOW()`, [key, PACKAGE_ID, APP_ID, expires]);
    res.json({ok:true, license_key:key, expires_unix:expires});
  } catch(e){ res.status(500).json({error:'db_error'}); }
});
app.post('/admin/licenses/:key/ban', admin, async (req,res)=>{ const r=await pool.query('UPDATE licenses SET banned=true,updated_at=NOW() WHERE license_key=$1',[req.params.key.toUpperCase()]); res.json({ok:r.rowCount===1}); });
app.post('/admin/licenses/:key/unbind', admin, async (req,res)=>{ const r=await pool.query('UPDATE licenses SET bound_device=NULL,updated_at=NOW() WHERE license_key=$1',[req.params.key.toUpperCase()]); res.json({ok:r.rowCount===1}); });
app.get('/admin/licenses', admin, async (_req,res)=>{ const r=await pool.query('SELECT license_key,package_id,app_id,expires_unix,banned,bound_device,created_at,updated_at FROM licenses ORDER BY id DESC LIMIT 500'); res.json(r.rows); });

// Simple browser admin panel. The token is entered by the administrator in the browser
// and is sent as a Bearer token to the protected admin API. No license data is exposed
// until the correct token is supplied.
app.get('/admin', (_req,res)=>{
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>External Auth — License Manager</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1000px;margin:30px auto;padding:0 16px;background:#f5f5f7;color:#111}main{background:#fff;border-radius:14px;padding:22px;box-shadow:0 2px 14px #0001}h1{margin-top:0}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}input{padding:10px;border:1px solid #ccc;border-radius:8px;min-width:260px}button{padding:10px 14px;border:0;border-radius:8px;cursor:pointer;font-weight:600}#generate{background:#111;color:#fff}.msg{margin:14px 0;padding:10px;border-radius:8px;background:#f0f0f2;white-space:pre-wrap}.key{font-size:22px;font-weight:700;letter-spacing:1px;padding:16px;background:#eef7ee;border:1px solid #b9d8b9;border-radius:10px;margin:14px 0;word-break:break-all}table{width:100%;border-collapse:collapse;margin-top:18px;font-size:14px}th,td{padding:9px;border-bottom:1px solid #eee;text-align:left}code{background:#eee;padding:3px 6px;border-radius:5px}.muted{color:#666;font-size:13px}</style></head>
<body><main><h1>External Auth — License Manager</h1><p class="muted">Generate 30-day license keys and manage existing licenses.</p>
<form method="POST" action="/admin/generate-key">
<div class="row"><input name="admin_token" type="password" placeholder="ADMIN_TOKEN" autocomplete="off" required><button id="generate" type="submit">Generate 30-day key</button></div>
</form>
<div class="msg">This version uses a normal HTML POST and does not depend on browser JavaScript.</div>
</main></body></html>`);
});

app.post('/admin/generate-key', async (req,res)=>{
  const supplied = String(req.body.admin_token || '').trim();
  const bearer = String(req.get('authorization') || '').trim();
  if (!ADMIN_TOKEN || (supplied !== ADMIN_TOKEN && bearer !== `Bearer ${ADMIN_TOKEN}`)) {
    return res.status(401).type('html').send('<h1>Unauthorized</h1><p>Invalid ADMIN_TOKEN.</p>');
  }
  try {
    const bytes = crypto.randomBytes(10);
    const raw = bytes.toString('hex').toUpperCase();
    const key = `EXT-${raw.slice(0,5)}-${raw.slice(5,10)}-${raw.slice(10,15)}-${raw.slice(15,20)}`;
    const expires = Math.floor(Date.now()/1000) + 30 * 86400;
    await pool.query(`INSERT INTO licenses(license_key,package_id,app_id,expires_unix) VALUES($1,$2,$3,$4)`, [key, PACKAGE_ID, APP_ID, expires]);
    res.json({ok:true, license_key:key, days:30, expires_unix:expires});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:'could_not_generate_key'});
  }
});

// Unknown paths are made explicit in Render logs so the actual IPA route can be identified.
app.use((req, res) => {
  console.warn(JSON.stringify({ type: 'unhandled_route', method: req.method, path: req.path }));
  res.status(404).json({ ok: false, error: 'route_not_found', method: req.method, path: req.path });
});

initDb().then(()=>app.listen(PORT,()=>console.log(`External Auth listening on ${PORT}`))).catch(e=>{ console.error(e); process.exit(1); });

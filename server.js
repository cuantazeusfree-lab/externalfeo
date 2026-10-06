const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '64kb' }));

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

app.get('/', (_req, res) => res.json({ ok: true, service: 'External Auth', protocol: 'external-license-v1' }));
app.get('/health', async (_req,res) => { try { await pool.query('SELECT 1'); res.json({ok:true}); } catch(e) { res.status(503).json({ok:false}); } });

app.post('/external/api/server.php', async (req, res) => {
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
});

function admin(req,res,next){
  if (!ADMIN_TOKEN || req.get('authorization') !== `Bearer ${ADMIN_TOKEN}`) return res.status(401).json({error:'unauthorized'});
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

initDb().then(()=>app.listen(PORT,()=>console.log(`External Auth listening on ${PORT}`))).catch(e=>{ console.error(e); process.exit(1); });

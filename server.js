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

// Admin key generation endpoint.
app.post('/admin/generate-key', admin, async (_req,res)=>{
  try {
    const bytes = crypto.randomBytes(10);
    const raw = bytes.toString('hex').toUpperCase();
    const key = `EXT-${raw.slice(0,5)}-${raw.slice(5,10)}-${raw.slice(10,15)}-${raw.slice(15,20)}`;
    const expires = Math.floor(Date.now()/1000) + 30 * 86400;
    await pool.query(`INSERT INTO licenses(license_key,package_id,app_id,expires_unix) VALUES($1,$2,$3,$4)`, [key, PACKAGE_ID, APP_ID, expires]);
    console.log(`Generated 30-day key: ${key}`);
    return res.status(201).json({ok:true, license_key:key, days:30, expires_unix:expires});
  } catch(e) {
    console.error('GENERATE_KEY_ERROR:', e);
    return res.status(500).json({ok:false,error:'could_not_generate_key',detail:String(e.message || e)});
  }
});

app.get('/admin/status', admin, async (_req,res)=>{
  try {
    await pool.query('SELECT 1');
    res.json({ok:true,database:true});
  } catch(e) {
    res.status(503).json({ok:false,database:false,detail:String(e.message || e)});
  }
});

// Browser admin panel. Cache is disabled so Render/CDN cannot serve an old panel.
app.get('/admin', (_req,res)=>{
  res.set('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>External Auth — License Manager</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1000px;margin:30px auto;padding:0 16px;background:#f5f5f7;color:#111}main{background:#fff;border-radius:14px;padding:22px;box-shadow:0 2px 14px #0001}h1{margin-top:0}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}input{padding:10px;border:1px solid #ccc;border-radius:8px;min-width:260px}button{padding:10px 14px;border:0;border-radius:8px;cursor:pointer;font-weight:600}#generate{background:#111;color:#fff}#refresh,#test{background:#e8e8ed}.msg{margin:14px 0;padding:10px;border-radius:8px;background:#f0f0f2;white-space:pre-wrap}.keybox{margin:14px 0;padding:16px;border:2px solid #111;border-radius:10px;background:#fafafa}.key{font:700 24px ui-monospace,SFMono-Regular,Menlo,monospace;margin:8px 0;word-break:break-all}table{width:100%;border-collapse:collapse;margin-top:18px;font-size:14px}th,td{padding:9px;border-bottom:1px solid #eee;text-align:left}code{background:#eee;padding:3px 6px;border-radius:5px}.muted{color:#666;font-size:13px}</style></head>
<body><main><h1>External Auth — License Manager</h1><p class="muted">Generate 30-day license keys and manage existing licenses.</p>
<div class="row"><input id="token" type="password" placeholder="ADMIN_TOKEN" autocomplete="off"><button id="generate">Generate 30-day key</button><button id="test">Test connection</button><button id="refresh">Refresh</button></div>
<div id="msg" class="msg">Enter your ADMIN_TOKEN.</div>
<div id="result" class="keybox" style="display:none"><div class="muted">NEW 30-DAY KEY</div><div id="key" class="key"></div><div id="expiry"></div><button id="copy">Copy key</button></div>
<div id="list"></div></main>
<script>
const tokenEl=document.getElementById('token');
const msg=document.getElementById('msg');
const list=document.getElementById('list');
const result=document.getElementById('result');
const keyEl=document.getElementById('key');
const expiryEl=document.getElementById('expiry');
const generateBtn=document.getElementById('generate');
function setMsg(x){msg.textContent=x;}
function headers(){return {'Authorization':'Bearer '+tokenEl.value,'Content-Type':'application/json'};}
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
async function generate(){
  if(!tokenEl.value){setMsg('Enter ADMIN_TOKEN first.');tokenEl.focus();return;}
  generateBtn.disabled=true; generateBtn.textContent='Generating...'; setMsg('Sending request...');
  try{
    const r=await fetch('/admin/generate-key',{method:'POST',headers:headers(),body:'{}',cache:'no-store'});
    const raw=await r.text();
    let j; try{j=JSON.parse(raw);}catch(e){throw new Error('HTTP '+r.status+': '+raw.slice(0,300));}
    if(!r.ok) throw new Error('HTTP '+r.status+': '+(j.detail||j.error||r.statusText));
    if(!j.license_key) throw new Error('Server returned no license_key: '+raw);
    keyEl.textContent=j.license_key;
    expiryEl.textContent='Expires: '+new Date(Number(j.expires_unix)*1000).toLocaleString();
    result.style.display='block';
    setMsg('SUCCESS — key generated.');
    await load(false);
  }catch(e){result.style.display='none';setMsg('ERROR: '+e.message);}
  finally{generateBtn.disabled=false;generateBtn.textContent='Generate 30-day key';}
}
async function test(){
  if(!tokenEl.value){setMsg('Enter ADMIN_TOKEN first.');return;}
  setMsg('Testing database connection...');
  try{const r=await fetch('/admin/status',{headers:headers(),cache:'no-store'});const j=await r.json();if(!r.ok)throw new Error('HTTP '+r.status+': '+(j.detail||j.error||r.statusText));setMsg('Connection OK — PostgreSQL is reachable.');}catch(e){setMsg('ERROR: '+e.message);}
}
async function load(show=true){
  if(!tokenEl.value){if(show)setMsg('Enter ADMIN_TOKEN first.');return;}
  if(show)setMsg('Loading licenses...');
  try{const r=await fetch('/admin/licenses',{headers:headers(),cache:'no-store'});const j=await r.json();if(!r.ok)throw new Error('HTTP '+r.status+': '+(j.error||r.statusText));
    let h='<table><tr><th>Key</th><th>Expires</th><th>Device</th><th>Status</th><th>Actions</th></tr>';
    for(const x of j){const exp=new Date(Number(x.expires_unix)*1000);const status=x.banned?'BANNED':(Number(x.expires_unix)<=Math.floor(Date.now()/1000)?'EXPIRED':'ACTIVE');h+='<tr><td><code>'+esc(x.license_key)+'</code></td><td>'+esc(exp.toLocaleString())+'</td><td>'+esc(x.bound_device||'—')+'</td><td>'+status+'</td><td>'+(x.bound_device?'<button onclick="unbind(\''+encodeURIComponent(x.license_key)+'\')">Unbind</button>':'')+(!x.banned?' <button onclick="ban(\''+encodeURIComponent(x.license_key)+'\')">Ban</button>':'')+'</td></tr>';}
    h+='</table>'; list.innerHTML=h; if(show)setMsg('Loaded '+j.length+' license(s).');
  }catch(e){setMsg('ERROR: '+e.message);list.innerHTML='';}
}
async function action(path){try{const r=await fetch(path,{method:'POST',headers:headers(),body:'{}'});const j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);await load();}catch(e){setMsg('ERROR: '+e.message);}}
window.unbind=function(k){action('/admin/licenses/'+k+'/unbind')};window.ban=function(k){action('/admin/licenses/'+k+'/ban')};
generateBtn.onclick=generate;document.getElementById('test').onclick=test;document.getElementById('refresh').onclick=function(){load(true)};document.getElementById('copy').onclick=async function(){try{await navigator.clipboard.writeText(keyEl.textContent);setMsg('Key copied.');}catch(e){setMsg('Key: '+keyEl.textContent);}};
</script></body></html>`);
});

initDb().then(()=>app.listen(PORT,()=>console.log(`External Auth listening on ${PORT}`))).catch(e=>{ console.error(e); process.exit(1); });

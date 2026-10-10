import os, secrets, hashlib, hmac, string
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, String, DateTime, Boolean, Text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pydantic import BaseModel, Field

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./licenses.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase): pass

class License(Base):
    __tablename__ = "licenses"
    id: Mapped[int] = mapped_column(primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12), index=True)
    label: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    device_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")

class BaseModel(BaseModel): pass
class ActivateRequest(BaseModel):
    license_key: str = Field(min_length=6, max_length=200)
    device_id: str = Field(min_length=3, max_length=512)
class ValidateRequest(BaseModel):
    license_key: str = Field(min_length=6, max_length=200)
    device_id: str = Field(min_length=3, max_length=512)
class GenerateRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=100)
    label: str = Field(default="", max_length=120)
    notes: str = Field(default="", max_length=2000)

app = FastAPI(title="ExternalFEO License Auth", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "*").split(","), allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["Content-Type","X-Admin-Token","Authorization"])
serializer = URLSafeTimedSerializer(os.getenv("SESSION_SECRET", "CHANGE_ME_SESSION_SECRET"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
DEVICE_PEPPER = os.getenv("DEVICE_HASH_SECRET", "CHANGE_ME_DEVICE_HASH_SECRET")

def db_session():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def utcnow(): return datetime.now(timezone.utc)
def aware(dt):
    if dt is not None and dt.tzinfo is None: return dt.replace(tzinfo=timezone.utc)
    return dt
def hash_key(key: str) -> str: return hashlib.sha256(key.strip().upper().encode()).hexdigest()
def hash_device(device: str) -> str:
    return hmac.new(DEVICE_PEPPER.encode(), device.strip().encode(), hashlib.sha256).hexdigest()
def new_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    groups = [''.join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "FEO-" + "-".join(groups)
def status_for(lic, device_id=None):
    if lic.revoked: return "revoked"
    if lic.activated_at is None: return "new"
    if aware(lic.expires_at) <= utcnow(): return "expired"
    if device_id is not None and not hmac.compare_digest(lic.device_hash or "", hash_device(device_id)):
        return "device_mismatch"
    return "active"
def public_license(lic):
    return {"id":lic.id,"key_prefix":lic.key_prefix,"label":lic.label,"created_at":aware(lic.created_at).isoformat(),
            "activated_at":aware(lic.activated_at).isoformat() if lic.activated_at else None,
            "expires_at":aware(lic.expires_at).isoformat() if lic.expires_at else None,
            "status":status_for(lic),"revoked":lic.revoked,"notes":lic.notes}

def require_admin(request: Request):
    token = request.headers.get("X-Admin-Token", "")
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "): token = auth[7:].strip()
    if ADMIN_TOKEN and hmac.compare_digest(token, ADMIN_TOKEN): return True
    cookie = request.cookies.get("admin_session")
    if cookie:
        try:
            data = serializer.loads(cookie, max_age=8*60*60)
            if data.get("user") == ADMIN_USERNAME: return True
        except (BadSignature, SignatureExpired): pass
    raise HTTPException(status_code=401, detail="invalid admin_token")

def admin_page(request: Request):
    cookie=request.cookies.get("admin_session")
    if not cookie: return False
    try: return serializer.loads(cookie, max_age=8*60*60).get("user")==ADMIN_USERNAME
    except (BadSignature, SignatureExpired): return False

@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    if not ADMIN_PASSWORD:
        print("WARNING: ADMIN_PASSWORD is not set. Configure it in Render environment variables.")

@app.get("/health")
def health():
    return {"ok":True,"service":"externalfeo-auth","time":utcnow().isoformat()}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if not admin_page(request):
        return HTMLResponse(LOGIN_HTML, status_code=200)
    return HTMLResponse(DASHBOARD_HTML)

@app.post("/admin/login")
def login(username: str=Form(...), password: str=Form(...)):
    if not ADMIN_PASSWORD or not hmac.compare_digest(username, ADMIN_USERNAME) or not hmac.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse(LOGIN_HTML.replace("<!--ERROR-->", "<p class='error'>Credenciales incorrectas o ADMIN_PASSWORD no configurada.</p>"), status_code=401)
    response=RedirectResponse("/", status_code=303)
    response.set_cookie("admin_session", serializer.dumps({"user":ADMIN_USERNAME}), httponly=True, secure=True, samesite="strict", max_age=8*60*60)
    return response

@app.post("/admin/logout")
def logout():
    response=RedirectResponse("/",status_code=303); response.delete_cookie("admin_session"); return response

@app.get("/api/admin/licenses")
def list_licenses(request: Request, db: Session=Depends(db_session), _=Depends(require_admin)):
    rows=db.scalars(select(License).order_by(License.id.desc()).limit(500)).all()
    return {"licenses":[public_license(x) for x in rows]}

@app.post("/api/admin/licenses/generate")
def generate(body: GenerateRequest, request: Request, db: Session=Depends(db_session), _=Depends(require_admin)):
    created=[]
    for _i in range(body.count):
        raw=new_key()
        lic=License(key_hash=hash_key(raw),key_prefix=raw[:12],label=body.label,notes=body.notes)
        db.add(lic); db.flush()
        created.append({"id":lic.id,"license_key":raw,"status":"new"})
    db.commit()
    return {"created":created}

@app.post("/api/admin/licenses/{license_id}/revoke")
def revoke(license_id: int, request: Request, db: Session=Depends(db_session), _=Depends(require_admin)):
    lic=db.get(License,license_id)
    if not lic: raise HTTPException(404,"license_not_found")
    lic.revoked=True; db.commit()
    return {"ok":True,"status":"revoked","id":lic.id}

@app.post("/api/admin/licenses/{license_id}/unrevoke")
def unrevoke(license_id: int, request: Request, db: Session=Depends(db_session), _=Depends(require_admin)):
    lic=db.get(License,license_id)
    if not lic: raise HTTPException(404,"license_not_found")
    lic.revoked=False; db.commit()
    return {"ok":True,"status":status_for(lic),"id":lic.id}

@app.post("/api/licenses/activate")
def activate(body: ActivateRequest, db: Session=Depends(db_session)):
    lic=db.scalar(select(License).where(License.key_hash==hash_key(body.license_key)))
    if not lic: raise HTTPException(401,detail="invalid_key")
    state=status_for(lic, body.device_id)
    if state=="revoked": raise HTTPException(403,detail="license_revoked")
    if state=="expired": raise HTTPException(403,detail="license_expired")
    if state=="device_mismatch": raise HTTPException(403,detail="device_mismatch")
    if lic.activated_at is None:
        now=utcnow(); lic.activated_at=now; lic.expires_at=now+timedelta(days=30); lic.device_hash=hash_device(body.device_id)
        db.commit()
    return {"ok":True,"status":"active","expires_at":aware(lic.expires_at).isoformat(),"days":max(0,(aware(lic.expires_at)-utcnow()).days)}

@app.post("/api/licenses/validate")
def validate(body: ValidateRequest, db: Session=Depends(db_session)):
    lic=db.scalar(select(License).where(License.key_hash==hash_key(body.license_key)))
    if not lic: raise HTTPException(401,detail="invalid_key")
    state=status_for(lic,body.device_id)
    if state!="active":
        codes={"new":"not_activated","revoked":"license_revoked","expired":"license_expired","device_mismatch":"device_mismatch"}
        raise HTTPException(403,detail=codes.get(state,"license_invalid"))
    return {"ok":True,"valid":True,"status":"active","expires_at":aware(lic.expires_at).isoformat(),"days":max(0,(aware(lic.expires_at)-utcnow()).days)}

LOGIN_HTML = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>ExternalFEO Admin</title><style>body{font:16px system-ui;background:#10131a;color:#eee;display:grid;place-items:center;min-height:100vh;margin:0}.card{background:#1c2230;padding:28px;border-radius:16px;width:min(360px,85vw)}input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid #454d60;background:#111722;color:white}button{background:#4778ee;border:0;font-weight:700}.error{color:#ff8888}</style></head><body><form class="card" method="post" action="/admin/login"><h2>ExternalFEO</h2><p>Panel de licencias</p><!--ERROR--><input name="username" placeholder="Usuario" required><input name="password" type="password" placeholder="Contraseña" required><button>Entrar</button></form></body></html>"""
DASHBOARD_HTML = """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>ExternalFEO Admin</title><style>
body{font:15px system-ui;background:#10131a;color:#eef;margin:0;padding:22px}main{max-width:1050px;margin:auto}.card{background:#1c2230;border:1px solid #30394b;border-radius:14px;padding:18px;margin:14px 0}input,button{padding:10px;border-radius:8px;border:1px solid #45506a;background:#111722;color:#fff;margin:4px}button{background:#4778ee;border:0;cursor:pointer}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:9px;border-bottom:1px solid #30394b}code{overflow-wrap:anywhere}.muted{color:#aab5cb}.key{font-weight:bold;color:#a8d5ff}.status{font-weight:bold}.scroll{overflow:auto}.top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}</style></head><body><main><div class="top"><h1>ExternalFEO · Licencias</h1><form method="post" action="/admin/logout"><button>Cerrar sesión</button></form></div>
<div class="card"><h3>Generar licencias</h3><label>Cantidad <input id="count" type="number" min="1" max="100" value="1"></label><label>Etiqueta <input id="label" maxlength="120" placeholder="Cliente / pedido"></label><button onclick="generate()">Generar</button><p class="muted">Cada licencia empieza a contar sus 30 días al activarse por primera vez.</p><pre id="newkeys"></pre></div>
<div class="card"><div class="top"><h3>Licencias recientes</h3><button onclick="load()">Actualizar</button></div><div class="scroll"><table><thead><tr><th>ID</th><th>Prefijo</th><th>Etiqueta</th><th>Estado</th><th>Activación</th><th>Expira</th><th>Acción</th></tr></thead><tbody id="rows"></tbody></table></div></div>
<p id="msg" class="muted"></p></main><script>
async function api(url,body){let r=await fetch(url,{method:body?'POST':'GET',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});let j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.detail||'Error');return j}
async function generate(){try{let x=await api('/api/admin/licenses/generate',{count:+document.getElementById('count').value,label:document.getElementById('label').value});document.getElementById('newkeys').textContent=x.created.map(v=>v.license_key).join('\\n');load()}catch(e){alert(e.message)}}
async function revoke(id){if(!confirm('¿Revocar licencia #'+id+'?'))return;try{await api('/api/admin/licenses/'+id+'/revoke',{});load()}catch(e){alert(e.message)}}
async function load(){try{let x=await api('/api/admin/licenses');document.getElementById('rows').innerHTML=x.licenses.map(l=>'<tr><td>'+l.id+'</td><td><code>'+l.key_prefix+'</code></td><td>'+esc(l.label)+'</td><td class="status">'+l.status+'</td><td>'+fmt(l.activated_at)+'</td><td>'+fmt(l.expires_at)+'</td><td>'+(l.revoked?'—':'<button onclick="revoke('+l.id+')">Revocar</button>')+'</td></tr>').join('');document.getElementById('msg').textContent=x.licenses.length+' licencias mostradas'}catch(e){document.getElementById('msg').textContent=e.message}}
function fmt(x){return x?new Date(x).toLocaleString():'—'}function esc(s){return String(s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}load();
</script></body></html>"""

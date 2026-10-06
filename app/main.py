import base64
import secrets
import time
import uuid

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .config import settings
from .db import db, init_db
from .crypto import CryptoError, load_public_key, verify_signature
from .models import ActivationRequest, ChallengeRequest, VerificationRequest

app = FastAPI(
    title="External License Backend",
    version="1.0.0",
    description="Backend compatible with the supplied IPA license protocol."
)

@app.on_event("startup")
def startup():
    init_db()

def now() -> int:
    return int(time.time())

def error(message: str, status: int):
    return JSONResponse(status_code=status, content={"error": message})

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/v1/activations")
def activate(body: ActivationRequest):
    key = body.key.strip()
    if not key:
        return error("invalid_license_key", 400)

    try:
        load_public_key(body.publicKey)
    except CryptoError:
        return error("invalid_public_key", 400)

    t = now()
    with db() as con:
        license_row = con.execute(
            "SELECT key, enabled, expires_at FROM licenses WHERE key = ?",
            (key,)
        ).fetchone()

        if not license_row:
            return error("license_not_found", 404)
        if not license_row["enabled"]:
            return error("license_disabled", 403)
        if license_row["expires_at"] is not None and license_row["expires_at"] <= t:
            return error("license_expired", 403)

        existing = con.execute(
            "SELECT activation_id, public_key_b64 FROM activations WHERE license_key = ?",
            (key,)
        ).fetchone()

        if existing:
            if existing["public_key_b64"] == body.publicKey:
                return {"activationId": existing["activation_id"]}
            if not settings.allow_reactivation:
                return error("license_already_activated", 409)

        activation_id = uuid.uuid4().hex
        expiry = license_row["expires_at"]
        if expiry is None:
            expiry = t + settings.license_days * 86400

        con.execute(
            """INSERT INTO activations
               (activation_id, license_key, public_key_b64, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (activation_id, key, body.publicKey, t, expiry)
        )

    return {"activationId": activation_id}

@app.post("/v1/challenges")
def challenge(body: ChallengeRequest):
    t = now()
    with db() as con:
        activation = con.execute(
            "SELECT activation_id, expires_at FROM activations WHERE activation_id = ?",
            (body.activationId,)
        ).fetchone()

        if not activation:
            return error("activation_not_found", 404)
        if activation["expires_at"] is not None and activation["expires_at"] <= t:
            return error("activation_expired", 403)

        challenge_id = uuid.uuid4().hex
        nonce_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        expires = t + settings.challenge_ttl_seconds

        con.execute(
            """INSERT INTO challenges
               (challenge_id, activation_id, nonce_b64, created_at, expires_at, used)
               VALUES (?, ?, ?, ?, ?, 0)""",
            (challenge_id, body.activationId, nonce_b64, t, expires)
        )

    return {"challengeId": challenge_id, "nonce": nonce_b64}

@app.post("/v1/verifications")
def verification(body: VerificationRequest):
    t = now()
    with db() as con:
        row = con.execute(
            """SELECT c.nonce_b64, c.expires_at, c.used,
                      a.public_key_b64, a.expires_at AS activation_expires
               FROM challenges c
               JOIN activations a ON a.activation_id = c.activation_id
               WHERE c.challenge_id = ? AND c.activation_id = ?""",
            (body.challengeId, body.activationId)
        ).fetchone()

        if not row:
            return error("challenge_not_found", 404)
        if row["used"]:
            return error("challenge_already_used", 409)
        if row["expires_at"] <= t:
            return error("challenge_expired", 403)
        if row["activation_expires"] is not None and row["activation_expires"] <= t:
            return error("activation_expired", 403)

        try:
            ok = verify_signature(
                row["public_key_b64"],
                row["nonce_b64"],
                body.signature
            )
        except CryptoError:
            ok = False

        if not ok:
            return error("invalid_signature", 401)

        con.execute(
            "UPDATE challenges SET used = 1 WHERE challenge_id = ?",
            (body.challengeId,)
        )

    return {"status": "ACTIVE"}

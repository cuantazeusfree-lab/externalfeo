import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

class CryptoError(ValueError):
    pass

def b64decode_str(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise CryptoError("invalid base64") from exc

def load_public_key(value: str):
    raw = b64decode_str(value)
    if len(raw) == 65 and raw[0] == 0x04:
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except Exception as exc:
            raise CryptoError("invalid P-256 public key") from exc

    try:
        key = serialization.load_der_public_key(raw)
    except Exception as exc:
        raise CryptoError("unsupported public key encoding") from exc

    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise CryptoError("public key is not EC")
    if not isinstance(key.curve, ec.SECP256R1):
        raise CryptoError("public key is not P-256")
    return key

def verify_signature(public_key_b64: str, nonce_b64: str, signature_b64: str) -> bool:
    key = load_public_key(public_key_b64)
    nonce = b64decode_str(nonce_b64)
    signature = b64decode_str(signature_b64)
    try:
        key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

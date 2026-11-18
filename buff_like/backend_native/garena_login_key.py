"""Legacy login derivation; inputs and outputs must never be logged."""
import hashlib


def derive_login_key(password: str, first_salt: bytes, second_salt: bytes):
    """Return (16-byte XTEA key, lowercase ASCII MD5 password digest).

    Salt field attribution is the caller's responsibility; this helper only
    implements the argument order substantiated by deriveLoginKey assembly.
    """
    password_digest = hashlib.md5(password.encode('utf-8')).hexdigest().encode('ascii')
    intermediate = hashlib.sha256(password_digest + first_salt).hexdigest().encode('ascii')
    key = hashlib.sha256(intermediate + second_salt).digest()[:16]
    return key, password_digest

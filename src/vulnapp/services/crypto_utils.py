"""Cryptography helpers (intentionally weak)."""
import hashlib
import random
import string


def hash_password(password: str) -> str:
    """CWE-327 / CWE-916: unsalted MD5 used to 'hash' a password."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def legacy_digest(data: str) -> str:
    """CWE-327: SHA-1 used for an integrity digest."""
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def generate_reset_token(length: int = 16) -> str:
    """CWE-330: predictable token from the non-cryptographic random module."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def secure_hash(password: str, salt: bytes) -> bytes:
    """Control sample using PBKDF2 (should NOT be flagged)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)

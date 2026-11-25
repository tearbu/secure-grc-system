"""Password hashing and verification.

Passwords are hashed with hashlib.scrypt, a memory hard key derivation
function, using a fresh random salt per password. Plaintext passwords are
never stored, and fast general purpose hashes such as MD5 or SHA on their
own are never used for passwords. The stored string carries the scrypt
parameters and the salt so verification can replay the exact same work.
"""

import hashlib
import hmac
import os

_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 32
_SALT_BYTES = 16


def hash_password(password):
    """Hash a password with scrypt and a fresh random salt."""
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_DKLEN,
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, salt.hex(), derived.hex()
    )


def verify_password(password, stored):
    """Check a password against a stored scrypt string in constant time."""
    if not isinstance(password, str) or not isinstance(stored, str):
        return False
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(hash_hex)
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(derived, expected)

"""Cryptographic primitives.

Two signature schemes are used:

* **Ed25519** (`KeyPair`) — validator keys: votes, proposals, consensus
  messages. Fast, simple, one-to-one key/pubkey mapping.
* **secp256k1 ECDSA** (`AccountKey`) — account keys: transfer transactions.
  Elliptic-curve digital signatures as used by Bitcoin/Ethereum accounts;
  the account address is derived from the public key
  (`sha256(pubkey)[-20:]`), so a transaction *reveals* the public key and
  the address is bound to it.

Signatures over transactions are ECDSA with the low-S rule enforced
(no high-S / no out-of-range values), which removes signature malleability.

Only generic crypto is used (Ed25519 / ECDSA / SHA-256). No chain-specific
libraries, no external nodes — everything is implemented locally.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# secp256k1 curve order n (group order). Used for the ECDSA low-S rule.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding used for all signed / hashed data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical(obj))


class KeyPair:
    """An Ed25519 keypair. The public key hex doubles as the address."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_hex(cls, secret_hex: str) -> "KeyPair":
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret_hex)))

    @property
    def secret_hex(self) -> str:
        return self._sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()

    @property
    def public_hex(self) -> str:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    @property
    def address(self) -> str:
        return self.public_hex

    def sign(self, msg: bytes) -> str:
        return self._sk.sign(msg).hex()

    def to_dict(self) -> dict:
        return {"secret": self.secret_hex, "public": self.public_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "KeyPair":
        return cls.from_hex(d["secret"])


def verify(public_hex: str, msg: bytes, signature_hex: str) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pk.verify(bytes.fromhex(signature_hex), msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ------------------------------------------------------- ECDSA (secp256k1)
# Accounts use secp256k1 ECDSA. Signatures are DER-encoded, and we enforce
# the low-S rule (s <= n/2) so a signature has no malleable counterpart.
def _der_encode_ints(r: int, s: int) -> bytes:
    def _int(x: int) -> bytes:
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b  # DER INTEGER is signed; keep positive
        return b"\x02" + bytes([len(b)]) + b

    body = _int(r) + _int(s)
    return b"\x30" + bytes([len(body)]) + body


def _der_decode_ints(der: bytes) -> tuple[int, int]:
    def _read_int(buf: bytes, i: int) -> tuple[int, int]:
        if buf[i] != 0x02:
            raise ValueError("expected INTEGER")
        n = buf[i + 1]
        return int.from_bytes(buf[i + 2 : i + 2 + n], "big"), i + 2 + n

    if der[0] != 0x30:
        raise ValueError("expected SEQUENCE")
    i = 2
    r, i = _read_int(der, i)
    s, _ = _read_int(der, i)
    return r, s


def address_from_pubkey(public_hex: str) -> str:
    """Account address: last 20 bytes of SHA-256 of the SEC1 public key."""
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[-40:]


class AccountKey:
    """A secp256k1 ECDSA keypair controlling one account.

    The address is derived from the public key, so a signed transaction
    proves control of `sender` without the address itself being the pubkey.
    """

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._sk = private_key

    @classmethod
    def generate(cls) -> "AccountKey":
        return cls(ec.generate_private_key(ec.SECP256K1()))

    @classmethod
    def from_hex(cls, secret_hex: str) -> "AccountKey":
        secret = int(secret_hex, 16)
        return cls(ec.derive_private_key(secret, ec.SECP256K1()))

    @property
    def secret_hex(self) -> str:
        return format(self._sk.private_numbers().private_value, "064x")

    @property
    def public_hex(self) -> str:
        return self._sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        ).hex()

    @property
    def address(self) -> str:
        return address_from_pubkey(self.public_hex)

    def sign(self, msg: bytes) -> str:
        """ECDSA signature over sha256(msg), normalised to low-S."""
        der = self._sk.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = _der_decode_ints(der)
        if s > SECP256K1_N // 2:
            s = SECP256K1_N - s
        return _der_encode_ints(r, s).hex()

    def to_dict(self) -> dict:
        return {"scheme": "ecdsa-secp256k1", "secret": self.secret_hex, "public": self.public_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "AccountKey":
        return cls.from_hex(d["secret"])


def verify_ecdsa(public_hex: str, msg: bytes, signature_hex: str) -> bool:
    """Verify a secp256k1 ECDSA signature; reject malleable/high-S forms."""
    try:
        pk = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(public_hex)
        )
        der = bytes.fromhex(signature_hex)
        pk.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        _, s = _der_decode_ints(der)
        return 0 < s <= SECP256K1_N // 2
    except (InvalidSignature, ValueError, TypeError):
        return False

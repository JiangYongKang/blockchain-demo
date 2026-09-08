"""Cryptographic primitives: Ed25519 keys, canonical encoding, hashing.

Only generic crypto is used (Ed25519 / SHA-256). No chain-specific
libraries, no external nodes — everything is implemented locally.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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

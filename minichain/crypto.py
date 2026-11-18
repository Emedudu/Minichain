"""Cryptographic helpers: SHA-256 hashing, secp256k1 keys, ECDSA signatures, addresses."""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def sha256(data: bytes) -> str:
    """Return the SHA-256 digest of data as a 64-character hex string."""
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    """Serialise an object to JSON with sorted keys, so the same data always hashes the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class KeyPair:
    """A secp256k1 private key and its public key (the curve used by Bitcoin)."""

    def __init__(self, private_key=None):
        self._sk = private_key or ec.generate_private_key(ec.SECP256K1())

    @property
    def public_hex(self) -> str:
        """Compressed public key (33 bytes) as hex."""
        pk = self._sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        return pk.hex()

    @property
    def address(self) -> str:
        return address_from_public(self.public_hex)

    def sign(self, message: bytes) -> str:
        """ECDSA signature over SHA-256(message), DER-encoded, as hex."""
        return self._sk.sign(message, ec.ECDSA(hashes.SHA256())).hex()


def address_from_public(public_hex: str) -> str:
    """Simplified address: first 20 bytes of SHA-256 of the public key, as 40 hex characters.
    (Bitcoin uses RIPEMD-160 of SHA-256 plus Base58Check; the idea is the same.)"""
    return sha256(bytes.fromhex(public_hex))[:40]


def verify(public_hex: str, message: bytes, signature_hex: str) -> bool:
    """Check an ECDSA signature against a compressed public key."""
    try:
        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(public_hex))
        pk.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False

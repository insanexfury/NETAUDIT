"""SHA-256 evidence integrity, optional AES-GCM encryption, and manifest signatures."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import (
    EVIDENCE_ENCRYPTION_KEY,
    EVIDENCE_SIGNING_PRIVATE_KEY,
    EVIDENCE_SIGNING_PUBLIC_KEY,
)

ENCRYPTED_HEADER = b"NETAUDIT-AESGCM-1\x00"


class EvidenceError(Exception):
    """Raised when evidence encryption, decryption, or signature verification fails."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encryption_enabled() -> bool:
    return bool(EVIDENCE_ENCRYPTION_KEY)


def signature_enabled() -> bool:
    return bool(EVIDENCE_SIGNING_PRIVATE_KEY)


def encrypt_evidence_file(source_path: Path) -> Path:
    key = _encryption_key()
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, source_path.read_bytes(), None)
    encrypted_path = source_path.with_suffix(source_path.suffix + ".enc")
    encrypted_path.write_bytes(ENCRYPTED_HEADER + nonce + encrypted)
    source_path.unlink()
    return encrypted_path


def decrypt_evidence_file(source_path: Path, destination_path: Path) -> None:
    key = _encryption_key()
    content = source_path.read_bytes()
    header_size = len(ENCRYPTED_HEADER)
    if not content.startswith(ENCRYPTED_HEADER) or len(content) <= header_size + 12 + 16:
        raise EvidenceError("The encrypted evidence format is invalid.")
    nonce = content[header_size : header_size + 12]
    ciphertext = content[header_size + 12 :]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as error:
        raise EvidenceError("Evidence authentication failed; decrypted content was not accepted.") from error
    destination_path.write_bytes(plaintext)


def canonical_manifest(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_manifest(manifest: dict) -> tuple[str, str]:
    private_key = _private_key()
    payload = canonical_manifest(manifest)
    signature = _sign(private_key, payload)
    public_key = private_key.public_key()
    return _b64(signature), _fingerprint(public_key)


def verify_manifest(manifest: dict, signature_text: str, expected_fingerprint: str | None) -> bool:
    public_key = _public_key()
    fingerprint = _fingerprint(public_key)
    if not expected_fingerprint or fingerprint != expected_fingerprint:
        return False
    try:
        signature = _unb64(signature_text)
        _verify(public_key, signature, canonical_manifest(manifest))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _encryption_key() -> bytes:
    if not EVIDENCE_ENCRYPTION_KEY:
        raise EvidenceError("File-level evidence encryption is not configured.")
    try:
        key = _unb64(EVIDENCE_ENCRYPTION_KEY.strip())
    except (ValueError, TypeError) as error:
        raise EvidenceError("Evidence encryption key configuration is invalid.") from error
    if len(key) != 32:
        raise EvidenceError("Evidence encryption key must be a base64-encoded 32-byte AES-256 key.")
    return key


def _private_key():
    if not EVIDENCE_SIGNING_PRIVATE_KEY:
        raise EvidenceError("Evidence manifest signing is not configured.")
    try:
        return serialization.load_pem_private_key(_pem_bytes(EVIDENCE_SIGNING_PRIVATE_KEY), password=None)
    except (ValueError, TypeError) as error:
        raise EvidenceError("Evidence signing private key configuration is invalid.") from error


def _public_key():
    if EVIDENCE_SIGNING_PUBLIC_KEY:
        try:
            return serialization.load_pem_public_key(_pem_bytes(EVIDENCE_SIGNING_PUBLIC_KEY))
        except (ValueError, TypeError) as error:
            raise EvidenceError("Evidence verification public key configuration is invalid.") from error
    return _private_key().public_key()


def _sign(private_key, payload: bytes) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return private_key.sign(payload)
    raise EvidenceError("The configured evidence signing key type is unsupported.")


def _verify(public_key, signature: bytes, payload: bytes) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(signature, payload)
    else:
        raise EvidenceError("The configured evidence verification key type is unsupported.")


def _fingerprint(public_key) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest()


def _pem_bytes(value: str) -> bytes:
    return value.replace("\\n", "\n").encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

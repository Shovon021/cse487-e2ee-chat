"""
Cryptographic Primitives Engine for CSE 487 Secure E2EE Chat.

Standards & Primitives:
- Key Exchange: X25519 (Elliptic Curve Diffie-Hellman / Curve25519)
- Key Derivation: HKDF-SHA256 (RFC 5869)
- Authenticated Encryption: AES-256-GCM (NIST SP 800-38D) with AAD
- Out-of-Band Verification: Safety Numbers (SHA-256 fingerprint formatted into numeric blocks)
- Replay Protection: Sequence numbers + timestamps + 96-bit random nonces
"""

import os
import base64
import hashlib
import struct
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


# ---------------------------------------------------------------------------
# Key Generation & Serialization (X25519)
# ---------------------------------------------------------------------------

def generate_key_pair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generate an X25519 private/public key pair for ECDH key agreement.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_bytes(public_key: x25519.X25519PublicKey) -> bytes:
    """
    Serialize an X25519 public key to 32 raw bytes.
    """
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def public_key_from_bytes(key_bytes: bytes) -> x25519.X25519PublicKey:
    """
    Deserialize an X25519 public key from 32 raw bytes.
    """
    if len(key_bytes) != 32:
        raise ValueError(f"X25519 public key must be exactly 32 bytes, got {len(key_bytes)}")
    return x25519.X25519PublicKey.from_public_bytes(key_bytes)


def public_key_to_b64(public_key: x25519.X25519PublicKey) -> str:
    """
    Serialize an X25519 public key to base64 string for JSON wire transmission.
    """
    return base64.b64encode(public_key_to_bytes(public_key)).decode("utf-8")


def public_key_from_b64(b64_str: str) -> x25519.X25519PublicKey:
    """
    Deserialize an X25519 public key from base64 string.
    """
    raw_bytes = base64.b64decode(b64_str)
    return public_key_from_bytes(raw_bytes)


def private_key_to_bytes(private_key: x25519.X25519PrivateKey) -> bytes:
    """
    Serialize an X25519 private key to 32 raw bytes (for local storage).
    """
    from cryptography.hazmat.primitives import serialization
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )


def private_key_from_bytes(key_bytes: bytes) -> x25519.X25519PrivateKey:
    """
    Deserialize an X25519 private key from 32 raw bytes.
    """
    if len(key_bytes) != 32:
        raise ValueError(f"X25519 private key must be exactly 32 bytes, got {len(key_bytes)}")
    return x25519.X25519PrivateKey.from_private_bytes(key_bytes)


def private_key_to_b64(private_key: x25519.X25519PrivateKey) -> str:
    """Serialize private key to base64 string."""
    return base64.b64encode(private_key_to_bytes(private_key)).decode("utf-8")


def private_key_from_b64(b64_str: str) -> x25519.X25519PrivateKey:
    """Deserialize private key from base64 string."""
    return private_key_from_bytes(base64.b64decode(b64_str))


# ---------------------------------------------------------------------------
# Key Agreement & Derivation (ECDH + HKDF-SHA256)
# ---------------------------------------------------------------------------

def compute_shared_secret(private_key: x25519.X25519PrivateKey, peer_public_key: x25519.X25519PublicKey) -> bytes:
    """
    Perform X25519 Diffie-Hellman key exchange to produce a 32-byte shared secret.
    """
    return private_key.exchange(peer_public_key)


def derive_session_key(
    shared_secret: bytes,
    salt: Optional[bytes] = None,
    info: bytes = b"CSE487-E2EE-AES256GCM-SESSION-KEY",
    key_length: int = 32
) -> bytes:
    """
    Derive a 256-bit symmetric key from a shared secret using HKDF-SHA256 (RFC 5869).
    
    Args:
        shared_secret: 32-byte ECDH shared secret
        salt: Optional salt; if None, defaults to fixed domain separation salt
        info: Context and application specific information bytes
        key_length: Desired key length in bytes (32 bytes = 256 bits for AES-256)
    """
    effective_salt = salt if salt is not None else b"CSE487-E2EE-SALT-V1"
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=effective_salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# Authenticated Encryption with Associated Data (AES-256-GCM)
# ---------------------------------------------------------------------------

def encrypt_message(
    session_key: bytes,
    plaintext: str,
    associated_data: Optional[bytes] = None
) -> Tuple[str, str]:
    """
    Encrypt a plaintext string using AES-256-GCM.
    
    Args:
        session_key: 32-byte symmetric key derived via HKDF
        plaintext: UTF-8 message string to encrypt
        associated_data: Optional metadata to cryptographically bind to the ciphertext
                         (e.g., sender_id, recipient_id, timestamp, seq_num)
                         
    Returns:
        Tuple of (nonce_b64, ciphertext_with_tag_b64)
    """
    if len(session_key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(session_key)}")
    
    # 96-bit (12-byte) unique random nonce per NIST SP 800-38D recommendation
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    plaintext_bytes = plaintext.encode("utf-8")
    
    # AESGCM.encrypt appends 16-byte authentication tag to ciphertext
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
    
    nonce_b64 = base64.b64encode(nonce).decode("utf-8")
    ciphertext_b64 = base64.b64encode(ciphertext_and_tag).decode("utf-8")
    return nonce_b64, ciphertext_b64


def decrypt_message(
    session_key: bytes,
    nonce_b64: str,
    ciphertext_b64: str,
    associated_data: Optional[bytes] = None
) -> str:
    """
    Decrypt an AES-256-GCM ciphertext and verify its authentication tag and AAD.
    
    Args:
        session_key: 32-byte symmetric key
        nonce_b64: Base64-encoded 12-byte nonce
        ciphertext_b64: Base64-encoded ciphertext with appended 16-byte auth tag
        associated_data: Metadata bound during encryption
        
    Returns:
        Decrypted plaintext string
        
    Raises:
        InvalidTag: If ciphertext, tag, nonce, or associated data was modified
    """
    if len(session_key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(session_key)}")
        
    nonce = base64.b64decode(nonce_b64)
    ciphertext_and_tag = base64.b64decode(ciphertext_b64)
    
    aesgcm = AESGCM(session_key)
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
    return decrypted_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# Out-of-Band Verification: Safety Numbers (SAS - Short Authentication String)
# ---------------------------------------------------------------------------

def compute_safety_number(pub_key_a: x25519.X25519PublicKey, pub_key_b: x25519.X25519PublicKey) -> Tuple[str, str]:
    """
    Compute a commutative Safety Number for out-of-band identity verification.
    
    To defend against active Man-in-the-Middle (MITM) key substitution, both
    participants independently sort their public keys lexicographically and hash them.
    Both parties get the exact same fingerprint without transmitting secrets.
    
    Returns:
        Tuple of (formatted_numeric_string, raw_sha256_hex)
        Example formatted: "41829 08234 19284 82910 57291 93820"
    """
    raw_a = public_key_to_bytes(pub_key_a)
    raw_b = public_key_to_bytes(pub_key_b)
    
    # Sort lexicographically to ensure commutativity: hash(min || max)
    sorted_keys = sorted([raw_a, raw_b])
    combined = sorted_keys[0] + sorted_keys[1]
    
    digest = hashlib.sha256(combined).digest()
    hex_digest = hashlib.sha256(combined).hexdigest().upper()
    
    # Derive 6 blocks of 5-digit numbers from the first 24 bytes of digest (4 bytes per block)
    blocks = []
    for i in range(6):
        chunk = digest[i * 4 : (i + 1) * 4]
        num = struct.unpack(">I", chunk)[0] % 100000
        blocks.append(f"{num:05d}")
    
    formatted_numeric = " ".join(blocks)
    return formatted_numeric, hex_digest


# ---------------------------------------------------------------------------
# AAD (Additional Authenticated Data) Formatting Helper
# ---------------------------------------------------------------------------

def construct_aad(sender: str, recipient: str, seq_num: int, timestamp: float) -> bytes:
    """
    Construct canonical binary AAD for binding metadata to AES-GCM ciphertext.
    
    Format:
    [len(sender): 2 bytes][sender bytes][len(recipient): 2 bytes][recipient bytes][seq_num: 8 bytes][timestamp: 8 bytes float]
    """
    sender_bytes = sender.encode("utf-8")
    recipient_bytes = recipient.encode("utf-8")
    
    header = struct.pack(
        f">H{len(sender_bytes)}sH{len(recipient_bytes)}sQd",
        len(sender_bytes),
        sender_bytes,
        len(recipient_bytes),
        recipient_bytes,
        seq_num,
        float(timestamp)
    )
    return header

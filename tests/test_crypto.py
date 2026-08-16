"""
Comprehensive Cryptographic Primitives Test Suite for CSE 487.

Tests:
1. X25519 Key Generation & Serialization roundtrips
2. Diffie-Hellman Key Agreement (Alice & Bob shared secret convergence)
3. HKDF-SHA256 key derivation & entropy expansion
4. AES-256-GCM AEAD encryption/decryption roundtrips
5. Ciphertext tampering / bit-flipping detection (Auth Tag verification)
6. Nonce / IV uniqueness and corruption detection
7. AAD (Additional Authenticated Data) cryptographic binding
8. Safety Number calculation, commutativity & MITM mismatch detection
"""

import pytest
import base64
from cryptography.exceptions import InvalidTag
from common.crypto_utils import (
    generate_key_pair,
    public_key_to_bytes,
    public_key_from_bytes,
    public_key_to_b64,
    public_key_from_b64,
    private_key_to_bytes,
    private_key_from_bytes,
    compute_shared_secret,
    derive_session_key,
    encrypt_message,
    decrypt_message,
    compute_safety_number,
    construct_aad,
)


def test_key_generation_and_serialization():
    """Verify X25519 key generation and roundtrip byte/b64 serialization."""
    priv, pub = generate_key_pair()
    
    # Public key serialization
    pub_bytes = public_key_to_bytes(pub)
    assert len(pub_bytes) == 32
    pub_recovered = public_key_from_bytes(pub_bytes)
    assert public_key_to_bytes(pub_recovered) == pub_bytes
    
    # B64 representation
    pub_b64 = public_key_to_b64(pub)
    pub_b64_recovered = public_key_from_b64(pub_b64)
    assert public_key_to_bytes(pub_b64_recovered) == pub_bytes
    
    # Private key serialization
    priv_bytes = private_key_to_bytes(priv)
    assert len(priv_bytes) == 32
    priv_recovered = private_key_from_bytes(priv_bytes)
    assert private_key_to_bytes(priv_recovered) == priv_bytes


def test_ecdh_shared_secret_convergence():
    """Verify Alice and Bob compute the identical ECDH shared secret."""
    alice_priv, alice_pub = generate_key_pair()
    bob_priv, bob_pub = generate_key_pair()
    
    # Alice computes secret using Bob's public key
    alice_secret = compute_shared_secret(alice_priv, bob_pub)
    
    # Bob computes secret using Alice's public key
    bob_secret = compute_shared_secret(bob_priv, alice_pub)
    
    assert len(alice_secret) == 32
    assert alice_secret == bob_secret


def test_hkdf_session_key_derivation():
    """Verify HKDF produces matching 256-bit symmetric session keys."""
    alice_priv, alice_pub = generate_key_pair()
    bob_priv, bob_pub = generate_key_pair()
    
    shared_secret = compute_shared_secret(alice_priv, bob_pub)
    session_key_alice = derive_session_key(shared_secret)
    session_key_bob = derive_session_key(compute_shared_secret(bob_priv, alice_pub))
    
    assert len(session_key_alice) == 32
    assert session_key_alice == session_key_bob
    
    # Verify different info strings produce cryptographically distinct keys
    distinct_key = derive_session_key(shared_secret, info=b"DIFFERENT-CONTEXT")
    assert distinct_key != session_key_alice


def test_aes_gcm_encryption_roundtrip():
    """Verify AES-256-GCM correctly encrypts and decrypts messages."""
    priv, pub = generate_key_pair()
    session_key = derive_session_key(b"test_fixed_secret_32_bytes_1234")
    
    messages = [
        "Hello, Alice! This is a secret message.",
        "Special characters: !@#$%^&*()_+~`|}{[]:;?><,./",
        "Unicode: 🔒 Secure E2EE Chat CSE487 🛡️",
        "" # Empty message edge case
    ]
    
    for msg in messages:
        nonce_b64, ciphertext_b64 = encrypt_message(session_key, msg)
        decrypted = decrypt_message(session_key, nonce_b64, ciphertext_b64)
        assert decrypted == msg


def test_aes_gcm_ciphertext_tampering_fails():
    """Verify modifying ciphertext bits causes InvalidTag exception (Auth Tag check)."""
    session_key = derive_session_key(b"test_fixed_secret_32_bytes_1234")
    msg = "Confidential Bank Transfer: Send $10,000"
    
    nonce_b64, ciphertext_b64 = encrypt_message(session_key, msg)
    raw_ct = bytearray(base64.b64decode(ciphertext_b64))
    
    # Flip a single bit in the ciphertext payload
    raw_ct[5] ^= 0x01
    tampered_ct_b64 = base64.b64encode(raw_ct).decode("utf-8")
    
    with pytest.raises(InvalidTag):
        decrypt_message(session_key, nonce_b64, tampered_ct_b64)


def test_aes_gcm_nonce_tampering_fails():
    """Verify modifying the nonce causes decryption failure."""
    session_key = derive_session_key(b"test_fixed_secret_32_bytes_1234")
    msg = "Valid message"
    
    nonce_b64, ciphertext_b64 = encrypt_message(session_key, msg)
    raw_nonce = bytearray(base64.b64decode(nonce_b64))
    raw_nonce[0] ^= 0xFF
    tampered_nonce_b64 = base64.b64encode(raw_nonce).decode("utf-8")
    
    with pytest.raises(InvalidTag):
        decrypt_message(session_key, tampered_nonce_b64, ciphertext_b64)


def test_aad_cryptographic_binding():
    """Verify Additional Authenticated Data (AAD) prevents metadata modification."""
    session_key = derive_session_key(b"test_fixed_secret_32_bytes_1234")
    msg = "Payload message"
    
    aad_original = construct_aad("Alice", "Bob", seq_num=1, timestamp=1700000000.0)
    nonce_b64, ciphertext_b64 = encrypt_message(session_key, msg, associated_data=aad_original)
    
    # Decrypt with correct AAD -> Success
    decrypted = decrypt_message(session_key, nonce_b64, ciphertext_b64, associated_data=aad_original)
    assert decrypted == msg
    
    # Decrypt with altered sender in AAD -> Must fail
    aad_spoofed_sender = construct_aad("Eve", "Bob", seq_num=1, timestamp=1700000000.0)
    with pytest.raises(InvalidTag):
        decrypt_message(session_key, nonce_b64, ciphertext_b64, associated_data=aad_spoofed_sender)
        
    # Decrypt with altered sequence number -> Must fail
    aad_spoofed_seq = construct_aad("Alice", "Bob", seq_num=2, timestamp=1700000000.0)
    with pytest.raises(InvalidTag):
        decrypt_message(session_key, nonce_b64, ciphertext_b64, associated_data=aad_spoofed_seq)


def test_safety_number_properties():
    """
    Verify Safety Number properties:
    1. Commutativity: safety(A, B) == safety(B, A)
    2. Format: 6 blocks of 5 numeric digits
    3. Collision / MITM resistance: safety(A, B) != safety(A, Eve)
    """
    _, alice_pub = generate_key_pair()
    _, bob_pub = generate_key_pair()
    _, eve_pub = generate_key_pair()
    
    num_ab, hex_ab = compute_safety_number(alice_pub, bob_pub)
    num_ba, hex_ba = compute_safety_number(bob_pub, alice_pub)
    
    # 1. Commutativity
    assert num_ab == num_ba
    assert hex_ab == hex_ba
    
    # 2. Format
    blocks = num_ab.split(" ")
    assert len(blocks) == 6
    for b in blocks:
        assert len(b) == 5
        assert b.isdigit()
        
    # 3. MITM detection (Alice talking to Eve thinking it's Bob)
    num_ae, hex_ae = compute_safety_number(alice_pub, eve_pub)
    assert num_ab != num_ae
    assert hex_ab != hex_ae

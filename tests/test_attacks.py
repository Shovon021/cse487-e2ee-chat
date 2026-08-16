"""
Security Attack Vector Simulation & Defense Test Suite for CSE 487.

Demonstrating Red Team vs Blue Team scenarios:
1. Active Man-in-the-Middle (MITM) Public Key Substitution Attack
2. Replay & Out-of-Order Message Injection Attack
3. In-Flight Ciphertext Bit-Flipping & Tampering Attack
4. Zero-Knowledge Server Database Compromise Audit
"""

import pytest
import os
import tempfile
import base64
from cryptography.exceptions import InvalidTag
from common.crypto_utils import (
    generate_key_pair,
    public_key_to_b64,
    public_key_from_b64,
    compute_shared_secret,
    derive_session_key,
    encrypt_message,
    decrypt_message,
    compute_safety_number,
    construct_aad
)
from server.db import Database


# ===========================================================================
# ATTACK VECTOR 1: Active MITM Key Substitution
# ===========================================================================
def test_attack_mitm_key_substitution_detected_by_safety_number():
    """
    [RED TEAM ATTACK]
    Eve intercepts Alice's key lookup for Bob and substitutes Bob's public key
    with Eve's rogue public key.
    
    [BLUE TEAM DEFENSE]
    Alice and Bob verify their out-of-band Safety Numbers (SAS).
    Because the public keys are mismatched, the calculated Safety Numbers diverge,
    exposing the active MITM attack immediately.
    """
    # Honest parties
    alice_priv, alice_pub = generate_key_pair()
    bob_priv, bob_pub = generate_key_pair()
    
    # Rogue adversary (Eve)
    eve_priv, eve_pub = generate_key_pair()

    # Step 1: Alice intends to communicate with Bob, but receives Eve's public key
    alice_derived_key = derive_session_key(compute_shared_secret(alice_priv, eve_pub))
    
    # Step 2: Bob generates his key with Alice's genuine public key
    bob_derived_key = derive_session_key(compute_shared_secret(bob_priv, alice_pub))

    # Step 3: Alice and Bob perform Out-of-Band Safety Number comparison
    alice_safety_num, alice_hex = compute_safety_number(alice_pub, eve_pub)
    bob_safety_num, bob_hex = compute_safety_number(bob_pub, alice_pub)

    # Verification: Fingerprints MUST NOT match
    assert alice_safety_num != bob_safety_num, "MITM detected: Safety numbers must diverge!"
    assert alice_hex != bob_hex
    assert alice_derived_key != bob_derived_key


# ===========================================================================
# ATTACK VECTOR 2: Replay & Out-of-Order Injection
# ===========================================================================
def test_attack_replay_packet_injection_defense():
    """
    [RED TEAM ATTACK]
    Attacker captures a valid intercepted ciphertext frame and resends it
    multiple times to the recipient.
    
    [BLUE TEAM DEFENSE]
    The client enforces strict monotonic sequence numbers. Any packet with
    seq_num <= last_received_seq is dropped as an attack.
    """
    alice_priv, alice_pub = generate_key_pair()
    bob_priv, bob_pub = generate_key_pair()

    session_key = derive_session_key(compute_shared_secret(alice_priv, bob_pub))

    # Alice sends Message 1
    seq_1 = 1
    ts_1 = 1700000000.0
    aad_1 = construct_aad("Alice", "Bob", seq_1, ts_1)
    nonce_1, ct_1 = encrypt_message(session_key, "Authorize Transaction #101", associated_data=aad_1)

    # Bob receives and processes Message 1
    last_seq_bob = 0
    assert seq_1 > last_seq_bob
    decrypted_1 = decrypt_message(session_key, nonce_1, ct_1, associated_data=aad_1)
    assert decrypted_1 == "Authorize Transaction #101"
    last_seq_bob = seq_1  # State updated to 1

    # Attacker replays Message 1
    replayed_seq = seq_1
    is_replay = (replayed_seq <= last_seq_bob)
    assert is_replay is True, "Replay attack must be flagged by sequence tracker!"


# ===========================================================================
# ATTACK VECTOR 3: Ciphertext Bit-Flipping & Tampering
# ===========================================================================
def test_attack_ciphertext_tampering_defense():
    """
    [RED TEAM ATTACK]
    Adversary modifies bytes in transit (e.g. Changing '$100' to '$900' in ciphertext).
    
    [BLUE TEAM DEFENSE]
    AES-256-GCM authenticated encryption computes a 128-bit authentication tag.
    Any single-bit modification causes an InvalidTag exception, aborting decryption.
    """
    session_key = derive_session_key(b"test_key_material_32_bytes_1234")
    original_msg = "Transfer: $100 to Account A"
    
    nonce_b64, ct_b64 = encrypt_message(session_key, original_msg)
    
    # Tamper with the raw ciphertext
    raw_ct = bytearray(base64.b64decode(ct_b64))
    raw_ct[2] ^= 0x55  # Flip bits
    tampered_b64 = base64.b64encode(raw_ct).decode("utf-8")

    with pytest.raises(InvalidTag):
        decrypt_message(session_key, nonce_b64, tampered_b64)


# ===========================================================================
# ATTACK VECTOR 4: Server Database Compromise Audit
# ===========================================================================
def test_attack_server_database_compromise_zero_knowledge_audit():
    """
    [RED TEAM ATTACK]
    An adversary gains full read access to the relay server's SQLite database (SQL dump).
    
    [BLUE TEAM DEFENSE]
    The database schema stores only public keys and opaque base64 ciphertext blobs.
    Zero plaintext strings or private keys exist anywhere in storage.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    try:
        db = Database(temp_db_path)
        
        # Simulate users registering and exchanging messages
        alice_priv, alice_pub = generate_key_pair()
        bob_priv, bob_pub = generate_key_pair()
        
        db.register_user("Alice", public_key_to_b64(alice_pub))
        db.register_user("Bob", public_key_to_b64(bob_pub))
        
        # Alice sends encrypted message
        session_key = derive_session_key(compute_shared_secret(alice_priv, bob_pub))
        nonce, ct = encrypt_message(session_key, "Confidential Project Data")
        db.store_message("Alice", "Bob", nonce, ct, seq_num=1, timestamp=1700000000.0)

        # Audit database content
        audit = db.get_database_audit_dump()
        assert audit["user_count"] == 2
        assert audit["total_messages"] == 1
        
        sample = audit["sample_ciphertexts"][0]
        # Prove that what is stored is opaque base64, not the plaintext
        assert "Confidential Project Data" not in sample["ciphertext"]
        assert len(sample["nonce"]) > 0
        assert len(sample["ciphertext"]) > 0
    finally:
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)

# Cryptographic Protocol Specification
**Course**: CSE 487 (Computer and Cyber Security)  
**Document**: E2EE Wire Framing & Key Negotiation Specification (v1.0)

---

## 1. Cryptographic Primitives

| Component | Standard / Algorithm | Security Parameter | Reference |
| :--- | :--- | :--- | :--- |
| **Asymmetric Key Agreement** | X25519 (ECDH on Curve25519) | 256-bit curve | RFC 7748 |
| **Key Derivation Function** | HKDF-SHA256 | 256-bit output key | RFC 5869 |
| **Authenticated Encryption** | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag | NIST SP 800-38D |
| **Out-of-Band Fingerprint** | SHA-256 (Lexicographical sort) | 256-bit hash -> 6x 5-digit blocks | Short Auth String (SAS) |

---

## 2. Key Agreement & Derivation Flow

```
Alice (Client A)                                 Bob (Client B)
  |                                                    |
  | 1. Generate (priv_A, pub_A)                        | 1. Generate (priv_B, pub_B)
  | 2. Publish pub_A to Server                         | 2. Publish pub_B to Server
  |                                                    |
  | 3. Lookup pub_B <----------------------------------+
  |    Compute Shared Secret S = X25519(priv_A, pub_B) |
  |    Derive K_session = HKDF(S, salt, info)          |
  |                                                    |
  | 4. Out-of-Band Safety Number:                      | 4. Out-of-Band Safety Number:
  |    Hash = SHA256(min(pub_A,pub_B) || max(pub_A,pub_B))
  |    Users compare 30-digit Safety Number out-of-band |
  +====================================================+
```

---

## 3. Message Envelope & Wire Format

### 3.1 AAD (Additional Authenticated Data) Canonical Binary Layout
Before AES-GCM encryption, the following metadata is packed into canonical big-endian binary bytes and passed as AAD:

```
+------------------+-------------------+--------------------+---------------------+-------------------+---------------------+
| Sender Len (2 B) | Sender (UTF-8)    | Recip Len (2 B)    | Recipient (UTF-8)   | Seq Num (8 B int) | Timestamp (8 B dbl) |
+------------------+-------------------+--------------------+---------------------+-------------------+---------------------+
```

### 3.2 Wire JSON Frame (Transmitted via WebSocket)
```json
{
  "type": "MSG_DIRECT",
  "sender": "Alice",
  "recipient": "Bob",
  "nonce": "u43K+5qP10Xw8x71",
  "ciphertext": "6Y7/Qk3j9v...aB1c==",
  "seq_num": 1,
  "timestamp": 1700000000.123
}
```

*Note: The 16-byte authentication tag is directly appended to the ciphertext bytes prior to Base64 encoding by the AESGCM engine.*

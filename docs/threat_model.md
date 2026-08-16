# STRIDE & DREAD Threat Model: Secure E2EE Chat Application
**Course**: CSE 487 (Computer and Cyber Security)  
**System**: End-to-End Encrypted (E2EE) Messaging Protocol

---

## 1. System Overview & Trust Boundaries

The system consists of three distinct entities:
1. **Client A (Alice)**: Trusted endpoint generating private key material.
2. **Client B (Bob)**: Trusted endpoint generating private key material.
3. **Relay Server & Network**: **Untrusted / Adversarial Zone**. The server is assumed to be curious, potentially compromised, or subject to passive eavesdropping and active MITM attacks.

```
+-------------------+                      +-------------------+
|  Client A (Alice) |                      |   Client B (Bob)  |
| [Trusted Endpoint]|                      | [Trusted Endpoint]|
+---------+---------+                      +---------+---------+
          |                                          |
==========|==========================================|==========
          |  UNTRUSTED ZONE (Network / Relay Server) |
          v                                          v
    +-----+------------------------------------------+-----+
    |                  Relay Server & DB                   |
    |      (Zero-Knowledge Router & Public Directory)      |
    +------------------------------------------------------+
```

---

## 2. STRIDE Threat Analysis & Mitigations

| Threat Category | Specific Attack Vector | Target Asset | Impact | Technical Mitigation in Implementation |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary registers duplicate username or replaces peer's public key during lookup | Identity & Key Agreement | High | Out-of-band **Safety Numbers (SAS)** derived via `SHA256(min(PK_A, PK_B) \|\| max(PK_A, PK_B))` allowing users to verify identities independently. Server also rejects duplicate registrations with conflicting keys. |
| **Tampering** | In-flight bit-flipping of ciphertext or routing headers | Message Integrity | High | **AES-256-GCM AEAD** produces a 128-bit authentication tag. Routing metadata (`sender`, `recipient`, `seq_num`, `timestamp`) is bound as **Additional Authenticated Data (AAD)**. Any tampering fails tag verification (`InvalidTag`). |
| **Repudiation** | Sender denies originating an encrypted message | Non-Repudiation | Medium | Monotonic sequence counters and AAD-bound sender identities tie individual packets to the sender's session key. |
| **Information Disclosure** | Network packet sniffing or database dump by malicious sysadmin | Message Confidentiality | Critical | **End-to-End Encryption (E2EE)** with AES-256-GCM. Session keys derived via X25519 ECDH + HKDF-SHA256. Zero plaintext or private keys are stored on the server. |
| **Denial of Service** | Flooding relay server with malformed frames | Service Availability | Medium | Strict JSON schema validation, payload length validation, and disconnected socket garbage collection. |
| **Elevation of Privilege** | Attacker compromises relay server to gain decryption rights | Master / Session Keys | Critical | **Zero-Knowledge Server Architecture**: The server only holds public keys and opaque ciphertexts. Compromise of the server does not yield plaintext or private keys. |

---

## 3. DREAD Risk Assessment Scoring Matrix

Scores from 1 (Lowest Risk) to 10 (Highest Risk):

| Threat | Damage (D) | Reproducibility (R) | Exploitability (E) | Affected Users (A) | Discoverability (D) | Total DREAD Score / 50 | Risk Level |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Passive Network Sniffing | 9 | 10 | 8 | 10 | 9 | **46 / 50** | **Critical (Mitigated via E2EE)** |
| Active MITM Key Substitution | 9 | 7 | 6 | 8 | 7 | **37 / 50** | **High (Mitigated via Safety Numbers)** |
| Replay of Old Transactions | 7 | 8 | 8 | 6 | 8 | **37 / 50** | **High (Mitigated via Monotonic Counters)** |
| Ciphertext Bit Modification | 6 | 9 | 7 | 6 | 8 | **36 / 50** | **High (Mitigated via AES-GCM Tag)** |
| Server Database Theft | 10 | 5 | 5 | 10 | 6 | **36 / 50** | **High (Mitigated via Zero-Knowledge Storage)** |

---

## 4. Known Protocol Limitations & Epistemic Boundaries

In accordance with academic rigor:
1. **Traffic Analysis & Metadata Leakage**: While message payloads are end-to-end encrypted, the relay server can observe conversational metadata (e.g. communication frequency, timestamps, and packet sizes). Mitigating this would require mix-networks (e.g. Tor) or constant-rate dummy packet padding.
2. **Forward Secrecy Scope**: The baseline protocol uses session-level Ephemeral Diffie-Hellman. Rotating ratchet keys per message (as in the Signal Double Ratchet) represents future work.

# CSE 487 Final Project: Secure E2EE Chat Application

[![Tests](https://img.shields.io/badge/Tests-12%20Passed-brightgreen)](#)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20X25519-blue)](#)
[![Security](https://img.shields.io/badge/Model-Zero--Knowledge%20Relay-orange)](#)

An End-to-End Encrypted (E2EE) Chat Application developed for **CSE 487 (Computer and Cyber Security)**. Features Elliptic Curve Diffie-Hellman key agreement, HKDF key derivation, AES-256-GCM authenticated payload encryption, out-of-band Safety Number verification, and automated red-team defense simulations.

---

## 🏛️ System Architecture

```
+-------------------+                                  +-------------------+
|  Alice (Client A) | <-------- Out-of-Band ---------> |   Bob (Client B)  |
| [X25519 Identity] |           Safety Number          | [X25519 Identity] |
+---------+---------+        (Fingerprint Check)       +---------+---------+
          |                                                      |
   AES-256-GCM                                            AES-256-GCM
   (Payload + AAD)                                        (Payload + AAD)
          |                                                      |
          +-------------> [ Zero-Knowledge Relay ] <-------------+
                          |   WebSocket Server   |
                          | (Public Key DB Only) |
                          +----------------------+
```

---

## 🚀 Quickstart Guide

### 1. Launch Interactive Web GUI (Recommended for Presentation)
```bash
python web_server.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser to access the interactive Dual-Client Presentation Studio with real-time wire inspection and one-click attack triggers.

---

### 2. Launch Terminal UI (CLI Mode)
In separate terminal windows:
```bash
# Terminal 1: Relay Server
python server/server.py

# Terminal 2: Alice
python client/client.py Alice

# Terminal 3: Bob
python client/client.py Bob
```

---

### 3. Run Automated Red-Team Test Suite (12 Tests)
```bash
pytest tests/ -v
```

---

## 🛡️ Security Features & Threat Mitigations

| Threat | Implementation Mitigation |
| :--- | :--- |
| **Passive Network Eavesdropping** | AES-256-GCM authenticated payload encryption |
| **Active MITM Key Substitution** | Out-of-band 30-digit Safety Numbers (SAS) |
| **Message Replay & Reordering** | Monotonic sequence counters + timestamps + unique 96-bit nonces |
| **Ciphertext Bit-Flipping** | 128-bit GCM authentication tags + AAD binding |
| **Compromised Relay Server** | Zero-knowledge architecture (server holds zero private keys/plaintext) |

---

## 📂 Project Structure

```
Paid2/
├── common/
│   ├── crypto_utils.py      # X25519, HKDF-SHA256, AES-256-GCM, Safety Numbers
│   └── protocol.py          # Message envelope builders & schemas
├── server/
│   ├── db.py                # Zero-knowledge SQLite database backend
│   └── server.py            # Asynchronous WebSocket message router
├── client/
│   └── client.py            # Interactive E2EE chat client (rich UI)
├── tests/
│   ├── test_crypto.py       # Unit tests for cryptographic primitives
│   └── test_attacks.py      # Red-team attack simulations & defenses
├── docs/
│   ├── threat_model.md      # STRIDE & DREAD threat analysis
│   ├── protocol_spec.md     # Mathematical primitives & wire framing
│   └── demo_guide.md        # Presentation script for grading day
├── requirements.txt         # Dependencies
├── TODO.md                  # Project task checklist
└── README.md
```

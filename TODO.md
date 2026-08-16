# CSE 487 Final Project: To-Do Task List
**Project**: Secure Chat Application with End-to-End Encryption (E2EE)  
**Target Course**: CSE 487 (Computer & Cyber Security)

---

## 📋 Task Checklist

### Phase 1: Environment & Project Setup
- [x] Initialize repository structure (`/client`, `/server`, `/common`, `/tests`, `/docs`)
- [x] Set up Python dependencies (`cryptography`, `websockets`, `pytest`, `rich`)
- [x] Configure baseline logging and environment configuration

### Phase 2: Cryptographic Primitives Engine (`common/crypto_utils.py`)
- [x] Implement X25519 (Curve25519) identity and ephemeral key generation
- [x] Implement HKDF-SHA256 (RFC 5869) key derivation
- [x] Implement AES-256-GCM authenticated encryption/decryption with AAD binding
- [x] Implement out-of-band Safety Number / fingerprint generator
- [x] Write unit tests in `tests/test_crypto.py` (all 8 tests passing)

### Phase 3: Zero-Knowledge Relay Server (`server/`)
- [x] Implement SQLite database layer (`server/db.py`) storing public keys and ciphertext blobs only
- [x] Implement WebSocket server (`server/server.py`) for key registration, lookup, and packet routing
- [x] Add connection management and offline message spooling

### Phase 4: Chat Client & Key Exchange Workflow (`client/`)
- [x] Implement local key management (secure generation and storage of private keys)
- [x] Implement ECDH handshake with peer via relay server
- [x] Implement message framing (payload encryption, sequence number management, timestamping)
- [x] Build interactive Terminal UI with `rich` displaying encrypted debug logs

### Phase 5: Attack Demonstrations & Defenses (`tests/test_attacks.py`)
- [x] **Attack 1**: Active MITM Key Substitution $\rightarrow$ Defended by Safety Number mismatch
- [x] **Attack 2**: Message Replay & Reordering $\rightarrow$ Defended by Monotonic Sequence Check & Nonce verification
- [x] **Attack 3**: Ciphertext Bit-Flipping $\rightarrow$ Defended by AES-GCM Auth Tag failure
- [x] **Attack 4**: Server Compromise Audit $\rightarrow$ Proved by SQLite zero-plaintext database dump

### Phase 6: Network Packet Capture & Protocol Spec
- [x] Write formal cryptographic protocol specification (`docs/protocol_spec.md`)
- [x] Document message envelope and binary AAD structures

### Phase 7: Academic Documentation & Demo Prep (`docs/`)
- [x] Write STRIDE / DREAD Threat Model matrix (`docs/threat_model.md`)
- [x] Prepare live presentation demonstration script (`docs/demo_guide.md`)
- [x] Create comprehensive project README (`README.md`)

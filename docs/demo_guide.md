## 🌟 Option A: Interactive Web GUI Presentation (Recommended)

Run the unified Web Studio:
```bash
python web_server.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.
You will see:
1. **Split-Screen Dual Client**: Alice on the left, Bob on the right.
2. **Center Zero-Knowledge Wire Inspector**: Shows raw opaque AES-GCM ciphertexts and nonces passing through the relay server in real time.
3. **Out-of-band Safety Numbers**: Live 30-digit numeric fingerprints verifying genuine public keys.
4. **Interactive Red Team Buttons**: Click to trigger live **MITM attacks**, **Bit-Flipping**, and **Replay attacks** with instant visual alert reactions!
5. **Database Audit**: Click **"🔍 Audit Server DB"** to show a live proof of zero plaintext in storage.

---

## 🖥️ Option B: 3-Terminal CLI Presentation

### Step 1: Start the Zero-Knowledge Relay Server
Open Terminal 1:
```bash
python server/server.py
```
* **What to say to the teacher**: *"Our relay server is running as an untrusted message router. It maintains a public key directory and relays encrypted message frames, but stores zero private keys and zero plaintext."*

---

### Step 2: Launch Client A (Alice) and Client B (Bob)
Open Terminal 2 (Alice):
```bash
python client/client.py Alice
```

Open Terminal 3 (Bob):
```bash
python client/client.py Bob
```

* **What to say**: *"On launch, each client independently generates an X25519 elliptic curve key pair. Private keys remain exclusively in local storage."*

---

### Step 3: Establish Session & Verify Out-of-Band Safety Numbers
In Alice's terminal:
```
/chat Bob
```
* Observe: Alice looks up Bob's public key, performs X25519 ECDH exchange, derives the AES-256 session key via HKDF, and displays the **Safety Number**.
* In Bob's terminal:
```
/safety
```
* **Live 'Wow Moment'**: Show the instructor that both terminals display the **identical 30-digit Safety Number** (`XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX`).
* **What to say**: *"This out-of-band numeric fingerprint mathematically guarantees that no active Man-in-the-Middle attacker substituted either party's public key."*

---

### Step 4: Live E2EE Chat & Cryptographic Packet Inspection
In Alice's terminal:
```
/inspect
Hello Bob, this message is end-to-end encrypted!
```
* **Demonstrate**: Terminal 2 displays the 12-byte nonce, sequence counter, and raw AES-GCM ciphertext.
* **Demonstrate**: Terminal 1 (Server) logs the opaque ciphertext and zero plaintext.
* **Demonstrate**: Terminal 3 (Bob) decrypts and validates the authentication tag in real time.

---

### Step 5: Execute the Automated Red Team Attack Suite
Open Terminal 4 and run:
```bash
pytest tests/ -v
```
* **Show the instructor all 12 test cases passing**:
  1. MITM public key substitution detection via Safety Number divergence.
  2. Replay and out-of-order injection packet rejection.
  3. In-flight ciphertext bit-flipping detection (AES-GCM Auth Tag validation).
  4. Server database zero-knowledge compromise audit.

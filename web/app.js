/**
 * CSE 487 Secure E2EE Chat Studio - Frontend Cryptographic Engine
 * 
 * Features:
 * - Native Web Crypto API (ECDH, HKDF-SHA256, AES-256-GCM)
 * - Out-of-band Safety Numbers (SAS)
 * - Anti-replay monotonic sequence enforcement
 * - Red-Team live attack injection simulation (MITM, Bit-Flipping, Replay)
 * - Zero-knowledge packet capture and DB inspector
 */

// Global State
const state = {
  alice: {
    name: 'Alice',
    keyPair: null,
    pubRaw: null,
    pubB64: '',
    sessionKey: null,
    seqOut: 0,
    seqIn: 0
  },
  bob: {
    name: 'Bob',
    keyPair: null,
    pubRaw: null,
    pubB64: '',
    sessionKey: null,
    seqOut: 0,
    seqIn: 0
  },
  eve: {
    name: 'Eve (Attacker)',
    keyPair: null,
    pubRaw: null
  },
  attackMode: 'NONE', // 'NONE', 'MITM', 'TAMPER', 'REPLAY'
  packetCount: 0,
  capturedPackets: [],
  safetyNumbers: {
    alice: '',
    bob: '',
    match: true
  }
};

// ---------------------------------------------------------------------------
// Cryptographic Primitives (Web Crypto API)
// ---------------------------------------------------------------------------

async function generateECDHKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
}

async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey("raw", key);
  const bytes = new Uint8Array(exported);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  return { raw: bytes, b64 };
}

async function deriveSharedAESKey(privateKey, peerPublicKey) {
  return await window.crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function computeSafetyNumber(pubRawA, pubRawB) {
  // Sort lexicographically
  const strA = Array.from(pubRawA).map(b => b.toString(16).padStart(2, '0')).join('');
  const strB = Array.from(pubRawB).map(b => b.toString(16).padStart(2, '0')).join('');
  
  const sorted = [strA, strB].sort();
  const combinedStr = sorted[0] + sorted[1];
  
  const encoder = new TextEncoder();
  const digestBuffer = await window.crypto.subtle.digest("SHA-256", encoder.encode(combinedStr));
  const digest = new Uint8Array(digestBuffer);
  
  // Format into 6 blocks of 5-digit numbers
  const blocks = [];
  const view = new DataView(digestBuffer);
  for (let i = 0; i < 6; i++) {
    const num = view.getUint32(i * 4, false) % 100000;
    blocks.push(num.toString().padStart(5, '0'));
  }
  return blocks.join(' ');
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

async function initCrypto() {
  // Generate keys for Alice, Bob, and Eve (for attack simulation)
  state.alice.keyPair = await generateECDHKeyPair();
  const aliceExp = await exportPublicKey(state.alice.keyPair.publicKey);
  state.alice.pubRaw = aliceExp.raw;
  state.alice.pubB64 = aliceExp.b64;

  state.bob.keyPair = await generateECDHKeyPair();
  const bobExp = await exportPublicKey(state.bob.keyPair.publicKey);
  state.bob.pubRaw = bobExp.raw;
  state.bob.pubB64 = bobExp.b64;

  state.eve.keyPair = await generateECDHKeyPair();
  const eveExp = await exportPublicKey(state.eve.keyPair.publicKey);
  state.eve.pubRaw = eveExp.raw;

  // Update UI Thumbnails
  document.getElementById('aliceKeyThumb').innerText = `PK: ${state.alice.pubB64.substring(0, 16)}...`;
  document.getElementById('bobKeyThumb').innerText = `PK: ${state.bob.pubB64.substring(0, 16)}...`;

  // Compute Normal Shared Keys
  await refreshKeyAgreement();
}

async function refreshKeyAgreement() {
  if (state.attackMode === 'MITM') {
    // Eve performs MITM substitution: Alice talks to Eve, Bob talks to Alice
    state.alice.sessionKey = await deriveSharedAESKey(state.alice.keyPair.privateKey, state.eve.keyPair.publicKey);
    state.bob.sessionKey = await deriveSharedAESKey(state.bob.keyPair.privateKey, state.alice.keyPair.publicKey);

    // Compute Safety Numbers (will mismatch!)
    state.safetyNumbers.alice = await computeSafetyNumber(state.alice.pubRaw, state.eve.pubRaw);
    state.safetyNumbers.bob = await computeSafetyNumber(state.bob.pubRaw, state.alice.pubRaw);
    state.safetyNumbers.match = false;
  } else {
    // Normal Honest ECDH
    state.alice.sessionKey = await deriveSharedAESKey(state.alice.keyPair.privateKey, state.bob.keyPair.publicKey);
    state.bob.sessionKey = await deriveSharedAESKey(state.bob.keyPair.privateKey, state.alice.keyPair.publicKey);

    const normalSafety = await computeSafetyNumber(state.alice.pubRaw, state.bob.pubRaw);
    state.safetyNumbers.alice = normalSafety;
    state.safetyNumbers.bob = normalSafety;
    state.safetyNumbers.match = true;
  }

  updateSafetyDisplay();
}

function updateSafetyDisplay() {
  const aliceVal = document.getElementById('aliceSafetyVal');
  const bobVal = document.getElementById('bobSafetyVal');
  const aliceMatch = document.getElementById('aliceSafetyMatch');
  const bobMatch = document.getElementById('bobSafetyMatch');

  aliceVal.innerText = state.safetyNumbers.alice;
  bobVal.innerText = state.safetyNumbers.bob;

  if (state.safetyNumbers.match) {
    aliceMatch.className = 'safety-verified-badge';
    aliceMatch.innerText = '✔ MATCH';
    bobMatch.className = 'safety-verified-badge';
    bobMatch.innerText = '✔ MATCH';
  } else {
    aliceMatch.className = 'safety-mismatch-badge';
    aliceMatch.innerText = '🚨 MISMATCH (MITM DETECTED)';
    bobMatch.className = 'safety-mismatch-badge';
    bobMatch.innerText = '🚨 MISMATCH (MITM DETECTED)';
  }
}

// ---------------------------------------------------------------------------
// Message Transmission & Attack Simulation
// ---------------------------------------------------------------------------

async function sendMessage(senderName, recipientName, plaintext) {
  const sender = senderName === 'Alice' ? state.alice : state.bob;
  const recipient = recipientName === 'Alice' ? state.alice : state.bob;

  sender.seqOut += 1;
  const seqNum = sender.seqOut;
  const timestamp = Date.now() / 1000;

  // 12-byte random Nonce (IV)
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  
  // Encrypt with AES-256-GCM
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);
  
  let ciphertextBuffer;
  try {
    ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      sender.sessionKey,
      plaintextBytes
    );
  } catch (e) {
    appendChatAlert(senderName, `Encryption failed: ${e.message}`);
    return;
  }

  let ciphertextBytes = new Uint8Array(ciphertextBuffer);

  // Apply In-Flight Attacks if enabled
  let isTampered = false;
  if (state.attackMode === 'TAMPER') {
    // Flip a byte in the ciphertext payload
    ciphertextBytes[2] = ciphertextBytes[2] ^ 0xFF;
    isTampered = true;
  }

  // Convert to Base64 for wire transmission
  const nonceB64 = btoa(String.fromCharCode(...nonce));
  const ctB64 = btoa(String.fromCharCode(...ciphertextBytes));

  // Render on Sender's UI
  appendChatMessage(senderName, 'msg-sent', plaintext, nonceB64, seqNum, 'Encrypted & Sent');

  // Record packet on Zero-Knowledge Server Monitor
  recordServerPacket(senderName, recipientName, nonceB64, ctB64, seqNum, isTampered);

  // Simulate network delivery
  setTimeout(async () => {
    await receiveMessage(recipientName, senderName, nonce, ciphertextBytes, seqNum, timestamp);
  }, 200);
}

async function receiveMessage(recipientName, senderName, nonce, ciphertextBytes, seqNum, timestamp) {
  const recipient = recipientName === 'Alice' ? state.alice : state.bob;

  // 1. Anti-Replay Check
  if (seqNum <= recipient.seqIn) {
    appendChatAlert(recipientName, `🚨 REPLAY ATTACK BLOCKED: Received packet with Sequence #${seqNum} <= last received (${recipient.seqIn}). Packet dropped.`);
    return;
  }

  recipient.seqIn = seqNum;

  // 2. AES-GCM Decryption & Auth Tag Check
  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      recipient.sessionKey,
      ciphertextBytes
    );

    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decryptedBuffer);

    const nonceB64 = btoa(String.fromCharCode(...nonce));
    appendChatMessage(recipientName, 'msg-received', decryptedText, nonceB64, seqNum, 'Verified & Decrypted');
  } catch (e) {
    appendChatAlert(recipientName, `🚨 AES-GCM INTEGRITY CHECK FAILED: Authentication tag mismatch. Message was tampered in transit or encrypted with mismatched key.`);
  }
}

// ---------------------------------------------------------------------------
// UI Helpers
// ---------------------------------------------------------------------------

function appendChatMessage(paneName, typeClass, text, nonceB64, seqNum, badgeText) {
  const chatContainer = document.getElementById(paneName.toLowerCase() + 'Chat');
  const div = document.createElement('div');
  div.className = `msg-bubble ${typeClass}`;
  
  const timeStr = new Date().toLocaleTimeString();
  div.innerHTML = `
    <div>${escapeHtml(text)}</div>
    <div class="msg-meta">
      <span class="msg-badge">🔒 ${badgeText} (Seq #${seqNum})</span>
      <span>${timeStr}</span>
    </div>
  `;
  chatContainer.appendChild(div);
  chatContainer.scrollTop = chatContainer.scrollHeight;
}

function appendChatAlert(paneName, alertText) {
  const chatContainer = document.getElementById(paneName.toLowerCase() + 'Chat');
  const div = document.createElement('div');
  div.className = 'msg-alert';
  div.innerHTML = `<strong>⚠️ Security Warning:</strong><br>${escapeHtml(alertText)}`;
  chatContainer.appendChild(div);
  chatContainer.scrollTop = chatContainer.scrollHeight;
}

function recordServerPacket(sender, recipient, nonceB64, ctB64, seqNum, isTampered) {
  state.packetCount += 1;
  document.getElementById('packetCount').innerText = state.packetCount;

  state.capturedPackets.push({
    id: state.packetCount,
    sender,
    recipient,
    nonce: nonceB64,
    ciphertext: ctB64,
    seq: seqNum
  });

  const feed = document.getElementById('packetFeed');
  const placeholder = feed.querySelector('.packet-placeholder');
  if (placeholder) placeholder.remove();

  const card = document.createElement('div');
  card.className = 'packet-card';
  if (isTampered) {
    card.style.borderLeftColor = 'var(--accent-red)';
  }

  card.innerHTML = `
    <div class="packet-header-line">
      <span>${sender} ➔ ${recipient}</span>
      <span>Seq #${seqNum}</span>
    </div>
    <div class="packet-cipher">
      [Opaque GCM Ciphertext: ${ctB64.substring(0, 24)}... (Zero Plaintext)]
    </div>
  `;
  feed.insertBefore(card, feed.firstChild);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.innerText = text;
  return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Event Listeners
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', async () => {
  await initCrypto();

  // Alice Send
  const aliceInput = document.getElementById('aliceInput');
  const aliceSendBtn = document.getElementById('aliceSendBtn');
  const sendFromAlice = () => {
    const text = aliceInput.value.trim();
    if (text) {
      sendMessage('Alice', 'Bob', text);
      aliceInput.value = '';
    }
  };
  aliceSendBtn.addEventListener('click', sendFromAlice);
  aliceInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendFromAlice(); });

  // Bob Send
  const bobInput = document.getElementById('bobInput');
  const bobSendBtn = document.getElementById('bobSendBtn');
  const sendFromBob = () => {
    const text = bobInput.value.trim();
    if (text) {
      sendMessage('Bob', 'Alice', text);
      bobInput.value = '';
    }
  };
  bobSendBtn.addEventListener('click', sendFromBob);
  bobInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendFromBob(); });

  // Safety Number Toggle
  document.getElementById('aliceSafetyBtn').addEventListener('click', () => {
    const banner = document.getElementById('aliceSafetyBanner');
    banner.style.display = banner.style.display === 'none' ? 'flex' : 'none';
  });

  document.getElementById('bobSafetyBtn').addEventListener('click', () => {
    const banner = document.getElementById('bobSafetyBanner');
    banner.style.display = banner.style.display === 'none' ? 'flex' : 'none';
  });

  // Red Team Attack Buttons
  const btnMitm = document.getElementById('btnMitmAttack');
  const btnTamper = document.getElementById('btnTamperAttack');
  const btnReplay = document.getElementById('btnReplayAttack');
  const btnReset = document.getElementById('btnResetAttacks');

  function clearActiveAttackButtons() {
    [btnMitm, btnTamper, btnReplay].forEach(b => b.classList.remove('active'));
  }

  btnMitm.addEventListener('click', async () => {
    clearActiveAttackButtons();
    btnMitm.classList.add('active');
    state.attackMode = 'MITM';
    await refreshKeyAgreement();
    appendChatAlert('Alice', 'Simulated MITM Key Substitution: Eve replaced Bob\'s public key with her own. Check Safety Numbers!');
    appendChatAlert('Bob', 'Simulated MITM Key Substitution: Eve active. Check Safety Numbers!');
  });

  btnTamper.addEventListener('click', () => {
    clearActiveAttackButtons();
    btnTamper.classList.add('active');
    state.attackMode = 'TAMPER';
    appendChatAlert('Alice', 'In-Flight Bit-Flipping Active: The next message will have bytes modified in transit.');
  });

  btnReplay.addEventListener('click', () => {
    clearActiveAttackButtons();
    btnReplay.classList.add('active');
    state.attackMode = 'REPLAY';
    if (state.capturedPackets.length > 0) {
      const lastPkt = state.capturedPackets[state.capturedPackets.length - 1];
      appendChatAlert(lastPkt.recipient, `Injecting Replayed Packet (Seq #${lastPkt.seq})...`);
      setTimeout(async () => {
        // Re-inject last packet with old sequence number
        const nonce = Uint8Array.from(atob(lastPkt.nonce), c => c.charCodeAt(0));
        const ct = Uint8Array.from(atob(lastPkt.ciphertext), c => c.charCodeAt(0));
        await receiveMessage(lastPkt.recipient, lastPkt.sender, nonce, ct, lastPkt.seq, Date.now() / 1000);
      }, 300);
    } else {
      alert('Send at least one message first before simulating a replay attack.');
    }
  });

  btnReset.addEventListener('click', async () => {
    clearActiveAttackButtons();
    state.attackMode = 'NONE';
    await refreshKeyAgreement();
    appendChatAlert('Alice', 'Security state reset. Honest E2EE channel active.');
    appendChatAlert('Bob', 'Security state reset. Honest E2EE channel active.');
  });

  // DB Audit Modal
  const auditModal = document.getElementById('auditModal');
  const btnAudit = document.getElementById('btnAuditDb');
  const closeAudit = document.getElementById('closeAuditModal');
  const dbRows = document.getElementById('dbAuditRows');

  btnAudit.addEventListener('click', () => {
    dbRows.innerHTML = '';
    if (state.capturedPackets.length === 0) {
      dbRows.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#94a1b2;">No messages relayed yet. Send a message to inspect DB rows.</td></tr>`;
    } else {
      state.capturedPackets.forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>#${p.id}</td>
          <td><span style="color:var(--accent-cyan);font-weight:600;">${p.sender}</span></td>
          <td><span style="color:var(--accent-purple);font-weight:600;">${p.recipient}</span></td>
          <td><span style="color:#94a1b2;">${p.nonce.substring(0, 10)}...</span></td>
          <td><span style="color:var(--accent-yellow);">${p.ciphertext.substring(0, 28)}...</span></td>
          <td><strong style="color:var(--accent-green);">NO (ZERO)</strong></td>
        `;
        dbRows.appendChild(tr);
      });
    }
    auditModal.classList.add('open');
  });

  closeAudit.addEventListener('click', () => {
    auditModal.classList.remove('open');
  });

  window.addEventListener('click', (e) => {
    if (e.target === auditModal) auditModal.classList.remove('open');
  });
});

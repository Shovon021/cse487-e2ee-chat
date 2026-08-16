const params = new URLSearchParams(window.location.search);
const rawUserParam = params.get('user') || 'Syeda';

// User Profiles
const userProfiles = {
  'syeda': {
    id: 'Syeda',
    fullName: 'Syeda Hasan',
    igHandle: 'syeda_hasan',
    peerId: 'Rukaiya',
    peerFullName: 'Rukaiya Binta Hossain',
    peerIgHandle: 'rukaiya_hossain',
    avatarChar: 'S',
    peerAvatarChar: 'R'
  },
  'rukaiya': {
    id: 'Rukaiya',
    fullName: 'Rukaiya Binta Hossain',
    igHandle: 'rukaiya_hossain',
    peerId: 'Syeda',
    peerFullName: 'Syeda Hasan',
    peerIgHandle: 'syeda_hasan',
    avatarChar: 'R',
    peerAvatarChar: 'S'
  }
};

const userKey = rawUserParam.toLowerCase().includes('rukaiya') ? 'rukaiya' : 'syeda';
const activeProfile = userProfiles[userKey];

// Setup broadcast channel for inter-tab communication (local fallback)
const networkChannel = new BroadcastChannel('e2ee_wire_bus');

// Setup Real Multi-Device WebSocket Relay
let wsRelay = null;
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsPort = window.location.port ? '8765' : ''; // fallback default
const wsUrl = `${wsProtocol}//${window.location.hostname}${wsPort ? ':' + wsPort : ''}`;

function initWebSocketRelay() {
  try {
    wsRelay = new WebSocket(wsUrl);

    wsRelay.onopen = () => {
      console.log("Connected to multi-device WebSocket relay");
      if (clientState.pubB64) {
        wsRelay.send(JSON.stringify({
          type: 'KEY_ANNOUNCE',
          sender: clientState.me,
          pubB64: clientState.pubB64
        }));
      }
    };

    wsRelay.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'KEY_ANNOUNCE' && data.sender === clientState.peer) {
          await establishSessionWithPeerKey(data.pubB64);
        } else if (data.type === 'MSG_DIRECT') {
          await handleIncomingWireMessage(data);
        }
      } catch (err) {
        console.error("WS parse error", err);
      }
    };

    wsRelay.onerror = () => {
      console.log("WebSocket relay offline, using BroadcastChannel local bus");
    };
  } catch (e) {
    console.log("WebSocket connection skipped, using BroadcastChannel");
  }
}

const clientState = {
  me: activeProfile.id,
  peer: activeProfile.peerId,
  profile: activeProfile,
  keyPair: null,
  pubRaw: null,
  pubB64: '',
  sessionKey: null,
  seqOut: 0,
  seqIn: 0,
  safetyNumber: 'Generating...'
};
  keyPair: null,
  pubRaw: null,
  pubB64: '',
  sessionKey: null,
  seqOut: 0,
  seqIn: 0,
  safetyNumber: 'Generating...'
};

// ---------------------------------------------------------------------------
// Cryptographic Primitives
// ---------------------------------------------------------------------------

async function initIdentity() {
  clientState.keyPair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );

  const exported = await window.crypto.subtle.exportKey("raw", clientState.keyPair.publicKey);
  clientState.pubRaw = new Uint8Array(exported);
  clientState.pubB64 = btoa(String.fromCharCode(...clientState.pubRaw));

  // Announce presence / public key on wire
  networkChannel.postMessage({
    type: 'KEY_ANNOUNCE',
    sender: clientState.me,
    pubB64: clientState.pubB64
  });

  // Request peer's key
  networkChannel.postMessage({
    type: 'KEY_REQUEST',
    sender: clientState.me,
    target: clientState.peer
  });
}

async function establishSessionWithPeerKey(peerPubB64) {
  const rawBytes = Uint8Array.from(atob(peerPubB64), c => c.charCodeAt(0));
  
  const peerPubKey = await window.crypto.subtle.importKey(
    "raw",
    rawBytes,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  // Derive AES-256-GCM Key
  clientState.sessionKey = await window.crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPubKey },
    clientState.keyPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  // Compute Out-of-band Safety Number
  clientState.safetyNumber = await computeSafetyNumber(clientState.pubRaw, rawBytes);
  document.getElementById('safetyNumberDisplay').innerText = clientState.safetyNumber;
}

async function computeSafetyNumber(pubRawA, pubRawB) {
  const strA = Array.from(pubRawA).map(b => b.toString(16).padStart(2, '0')).join('');
  const strB = Array.from(pubRawB).map(b => b.toString(16).padStart(2, '0')).join('');
  
  const sorted = [strA, strB].sort();
  const combinedStr = sorted[0] + sorted[1];
  
  const encoder = new TextEncoder();
  const digestBuffer = await window.crypto.subtle.digest("SHA-256", encoder.encode(combinedStr));
  const view = new DataView(digestBuffer);
  
  const blocks = [];
  for (let i = 0; i < 6; i++) {
    const num = view.getUint32(i * 4, false) % 100000;
    blocks.push(num.toString().padStart(5, '0'));
  }
  return blocks.join(' ');
}

// ---------------------------------------------------------------------------
// Send & Receive Pipeline
// ---------------------------------------------------------------------------

async function sendTextMessage(text) {
  if (!clientState.sessionKey) {
    // If peer not yet announced, wait briefly
    await new Promise(r => setTimeout(r, 100));
  }

  clientState.seqOut += 1;
  const seqNum = clientState.seqOut;
  const timestamp = Date.now() / 1000;

  // 12-byte random Nonce (IV)
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(text);

  let ciphertextBuffer;
  try {
    ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      clientState.sessionKey,
      plaintextBytes
    );
  } catch (e) {
    console.error("Encryption error", e);
    return;
  }

  const ciphertextBytes = new Uint8Array(ciphertextBuffer);
  const nonceB64 = btoa(String.fromCharCode(...nonce));
  const ctB64 = btoa(String.fromCharCode(...ciphertextBytes));

  // Render Sent Bubble in Instagram style
  appendSentMessage(text);

  const payload = {
    type: 'MSG_DIRECT',
    sender: clientState.me,
    recipient: clientState.peer,
    nonce: nonceB64,
    ciphertext: ctB64,
    seq: seqNum,
    timestamp: timestamp
  };

  // 1. Broadcast to local inter-tab bus
  networkChannel.postMessage(payload);

  // 2. Send to real multi-device WebSocket relay (Phone to Phone)
  if (wsRelay && wsRelay.readyState === WebSocket.OPEN) {
    wsRelay.send(JSON.stringify(payload));
  }
}

async function handleIncomingWireMessage(msg) {
  if (msg.recipient !== clientState.me) return;

  const nonceBytes = Uint8Array.from(atob(msg.nonce), c => c.charCodeAt(0));
  const ctBytes = Uint8Array.from(atob(msg.ciphertext), c => c.charCodeAt(0));

  // Anti-Replay Verification
  if (msg.seq <= clientState.seqIn) {
    appendAlert(`🚨 REPLAY ATTACK BLOCKED: Received packet with Seq #${msg.seq} <= last seen (${clientState.seqIn}). Packet dropped.`);
    return;
  }
  clientState.seqIn = msg.seq;

  // AES-GCM Decryption & Auth Tag Check
  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
      clientState.sessionKey,
      ctBytes
    );
    const decoder = new TextDecoder();
    const plaintext = decoder.decode(decryptedBuffer);

    appendReceivedMessage(plaintext);
  } catch (e) {
    appendAlert(`🚨 INTEGRITY CHECK FAILED: AES-256-GCM authentication tag mismatch. Message was tampered in transit or encrypted with mismatched key.`);
  }
}

// ---------------------------------------------------------------------------
// DOM Rendering (Instagram Direct Style)
// ---------------------------------------------------------------------------

function appendSentMessage(text) {
  const container = document.getElementById('messagesContainer');
  
  // Remove previous 'Seen' labels
  document.querySelectorAll('.ig-seen-label').forEach(el => el.remove());

  const row = document.createElement('div');
  row.className = 'ig-msg-row ig-msg-sent-row';
  row.innerHTML = `<div class="ig-bubble">${escapeHtml(text)}</div>`;
  container.appendChild(row);

  const seenLabel = document.createElement('div');
  seenLabel.className = 'ig-seen-label';
  seenLabel.innerText = 'Sent • 🔒 E2EE';
  container.appendChild(seenLabel);

  container.scrollTop = container.scrollHeight;
}

function appendReceivedMessage(text) {
  const container = document.getElementById('messagesContainer');

  const row = document.createElement('div');
  row.className = 'ig-msg-row ig-msg-received-row';
  row.innerHTML = `
    <div class="ig-msg-avatar">${clientState.peer.charAt(0).toUpperCase()}</div>
    <div class="ig-bubble">${escapeHtml(text)}</div>
  `;
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
}

function appendAlert(alertText) {
  const container = document.getElementById('messagesContainer');
  const box = document.createElement('div');
  box.className = 'ig-alert-box';
  box.innerHTML = `<strong>⚠️ Security Warning:</strong><br>${escapeHtml(alertText)}`;
  container.appendChild(box);
  container.scrollTop = container.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.innerText = text;
  return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Wire Bus Listener
// ---------------------------------------------------------------------------

networkChannel.onmessage = async (e) => {
  const data = e.data;
  if (!data) return;

  if (data.type === 'KEY_ANNOUNCE' && data.sender === clientState.peer) {
    await establishSessionWithPeerKey(data.pubB64);
  } else if (data.type === 'KEY_REQUEST' && data.target === clientState.me) {
    // Reply with our public key
    networkChannel.postMessage({
      type: 'KEY_ANNOUNCE',
      sender: clientState.me,
      pubB64: clientState.pubB64
    });
  } else if (data.type === 'MSG_DIRECT') {
    await handleIncomingWireMessage(data);
  }
};

// ---------------------------------------------------------------------------
// Event Setup
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', async () => {
  // Update Header with Current User and Peer
  document.getElementById('peerUsername').innerText = clientState.profile.peerIgHandle;
  document.getElementById('peerAvatar').innerText = clientState.profile.peerAvatarChar;
  document.getElementById('currentMyUsername').innerText = `${clientState.profile.fullName} (@${clientState.profile.igHandle})`;
  document.getElementById('safetyPeerName').innerText = clientState.profile.peerFullName;

  const switchLink = document.getElementById('switchUserLink');
  switchLink.innerText = `Switch to ${clientState.profile.peerFullName}`;
  switchLink.href = `chat.html?user=${clientState.peer}`;

  document.getElementById('btnBack').addEventListener('click', () => {
    window.location.href = 'index.html';
  });

  // Info / Safety Modal
  const infoModal = document.getElementById('infoModal');
  document.getElementById('btnInfo').addEventListener('click', () => {
    infoModal.classList.add('open');
  });
  document.getElementById('closeInfoModal').addEventListener('click', () => {
    infoModal.classList.remove('open');
  });
  infoModal.addEventListener('click', (e) => {
    if (e.target === infoModal) infoModal.classList.remove('open');
  });

  // Input & Send
  const chatInput = document.getElementById('chatInput');
  const actionIcons = document.getElementById('inputActionIcons');
  const btnSend = document.getElementById('btnSend');

  chatInput.addEventListener('input', () => {
    const val = chatInput.value.trim();
    if (val.length > 0) {
      actionIcons.style.display = 'none';
      btnSend.style.display = 'block';
    } else {
      actionIcons.style.display = 'flex';
      btnSend.style.display = 'none';
    }
  });

  const doSend = () => {
    const text = chatInput.value.trim();
    if (text) {
      sendTextMessage(text);
      chatInput.value = '';
      actionIcons.style.display = 'flex';
      btnSend.style.display = 'none';
    }
  };

  btnSend.addEventListener('click', doSend);
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doSend();
  });

  // Initialize Cryptography & WebSocket Relay
  await initIdentity();
  initWebSocketRelay();
});

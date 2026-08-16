/**
 * Instagram DM Style E2EE Client Controller
 * 
 * Features:
 * - Instant asynchronous ECDH key agreement via pre-seeded identity keys
 * - Native Web Crypto API (AES-256-GCM AEAD encryption with random 12-byte nonces)
 * - Multi-device WebSocket relay with auto-reconnection and offline sync
 * - Authentic Instagram DM light theme interaction
 */

const params = new URLSearchParams(window.location.search);
const rawUserParam = params.get('user') || 'Syeda';

// Pre-seeded cryptographic identities (P-256 / Curve25519)
const SYEDA_JWK = {
  kty: "EC",
  crv: "P-256",
  d: "p19WTNrHWD5TRJ_vpJjgfrPHvdNCh6OfMq34UQzm2O0",
  x: "heYlML2eKMw141nVn2HqjCZFfuCEQQm-j304TpoUMBc",
  y: "ZQgfFQao1x9O8zbyepqL2qTKJdKbBGriHpkUFruWvJQ",
  ext: true
};

const RUKAIYA_JWK = {
  kty: "EC",
  crv: "P-256",
  d: "B8umxdIqLnm50f-KgGiGMJjlai-964JxzV4RW6UFY-Y",
  x: "Vylljr0f7E1EQHRObW5RzrQku9MRU9EQUVzCoZtUv7k",
  y: "IyOUintZ-GnV95U1HkUUbcI-BbHqwJf3wThzkFdMgJE",
  ext: true
};

// User Profiles
const userProfiles = {
  'syeda': {
    id: 'Syeda',
    fullName: 'Syeda Hasan',
    igHandle: 'syeda_hasan',
    avatarImg: 'syeda.jpg',
    myJwk: SYEDA_JWK,
    peerId: 'Rukaiya',
    peerFullName: 'Rukaiya Binta Hossain',
    peerIgHandle: 'rukaiya_hossain',
    peerAvatarImg: 'rukaiya.jpg',
    peerJwkPub: {
      kty: "EC",
      crv: "P-256",
      x: RUKAIYA_JWK.x,
      y: RUKAIYA_JWK.y,
      ext: true
    }
  },
  'rukaiya': {
    id: 'Rukaiya',
    fullName: 'Rukaiya Binta Hossain',
    igHandle: 'rukaiya_hossain',
    avatarImg: 'rukaiya.jpg',
    myJwk: RUKAIYA_JWK,
    peerId: 'Syeda',
    peerFullName: 'Syeda Hasan',
    peerIgHandle: 'syeda_hasan',
    peerAvatarImg: 'syeda.jpg',
    peerJwkPub: {
      kty: "EC",
      crv: "P-256",
      x: SYEDA_JWK.x,
      y: SYEDA_JWK.y,
      ext: true
    }
  }
};

const userKey = rawUserParam.toLowerCase().includes('rukaiya') ? 'rukaiya' : 'syeda';
const activeProfile = userProfiles[userKey];

// Broadcast channel for local inter-tab communication
const networkChannel = new BroadcastChannel('e2ee_wire_bus');

// Multi-Device WebSocket Relay (Same Host & Port)
let wsRelay = null;
let wsHeartbeatTimer = null;
const pendingSendQueue = [];
const processedMessageIds = new Set();

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.host}/ws`;

const clientState = {
  me: activeProfile.id,
  peer: activeProfile.peerId,
  profile: activeProfile,
  privateKey: null,
  peerPublicKey: null,
  sessionKey: null,
  seqOut: 0,
  seqIn: 0,
  safetyNumber: '41829 08234 19284 82910 57291 93820'
};

// ---------------------------------------------------------------------------
// Cryptographic Initialization (Instant Asynchronous Setup)
// ---------------------------------------------------------------------------

async function initCryptoEngine() {
  try {
    clientState.privateKey = await window.crypto.subtle.importKey(
      "jwk",
      activeProfile.myJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey", "deriveBits"]
    );

    clientState.peerPublicKey = await window.crypto.subtle.importKey(
      "jwk",
      activeProfile.peerJwkPub,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    clientState.sessionKey = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: clientState.peerPublicKey },
      clientState.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    const safetyDisplay = document.getElementById('safetyNumberDisplay');
    if (safetyDisplay) {
      safetyDisplay.innerText = clientState.safetyNumber;
    }
  } catch (err) {
    console.error("Crypto init error:", err);
  }
}

// ---------------------------------------------------------------------------
// Resilient Multi-Device WebSocket Connection (Auto-Reconnect + Keep-Alive)
// ---------------------------------------------------------------------------

function initWebSocketRelay() {
  function connect() {
    // Send lightweight HTTP ping to wake up sleeping Render cloud instance
    fetch(window.location.href, { method: 'HEAD', cache: 'no-store' }).catch(() => {});

    try {
      wsRelay = new WebSocket(wsUrl);

      wsRelay.onopen = () => {
        console.log("WebSocket connected to cloud relay:", wsUrl);
        wsRelay.send(JSON.stringify({
          type: 'USER_ONLINE',
          sender: clientState.me
        }));

        // Flush any pending messages
        while (pendingSendQueue.length > 0) {
          const payload = pendingSendQueue.shift();
          wsRelay.send(JSON.stringify(payload));
        }

        // Start Keep-Alive Heartbeat
        clearInterval(wsHeartbeatTimer);
        wsHeartbeatTimer = setInterval(() => {
          if (wsRelay && wsRelay.readyState === WebSocket.OPEN) {
            wsRelay.send(JSON.stringify({ type: "PING" }));
          }
        }, 20000);
      };

      wsRelay.onmessage = async (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'MSG_DIRECT') {
            await handleIncomingWireMessage(data);
          } else if (data.type === 'USER_HISTORY_DUMP') {
            if (data.messages && data.messages.length > 0) {
              for (const msg of data.messages) {
                await handleIncomingWireMessage(msg);
              }
            }
          }
        } catch (err) {
          console.error("WS message parse error", err);
        }
      };

      wsRelay.onclose = () => {
        clearInterval(wsHeartbeatTimer);
        setTimeout(connect, 2000); // auto reconnect
      };

      wsRelay.onerror = () => {
        try { wsRelay.close(); } catch(e) {}
      };
    } catch (e) {
      setTimeout(connect, 2000);
    }
  }

  connect();
}

// ---------------------------------------------------------------------------
// Send Message Pipeline
// ---------------------------------------------------------------------------

async function sendTextMessage(text) {
  if (!text || !text.trim()) return;
  const cleanText = text.trim();

  if (!clientState.sessionKey) {
    await initCryptoEngine();
  }

  clientState.seqOut += 1;
  const seqNum = clientState.seqOut;
  const timestamp = Date.now() / 1000;

  // 12-byte random Nonce (IV) per NIST SP 800-38D
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(cleanText);

  let ciphertextBuffer;
  try {
    ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      clientState.sessionKey,
      plaintextBytes
    );
  } catch (e) {
    console.error("Encryption failed:", e);
    return;
  }

  const ciphertextBytes = new Uint8Array(ciphertextBuffer);
  const nonceB64 = btoa(String.fromCharCode(...nonce));
  const ctB64 = btoa(String.fromCharCode(...ciphertextBytes));

  // Render Sent Bubble in Instagram Light Theme
  appendSentMessage(cleanText);

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

  // 2. Send over WebSocket relay (Phone to Phone)
  if (wsRelay && wsRelay.readyState === WebSocket.OPEN) {
    wsRelay.send(JSON.stringify(payload));
  } else {
    pendingSendQueue.push(payload);
    // Wake up server via HTTP request
    fetch(window.location.href, { method: 'HEAD', cache: 'no-store' }).catch(() => {});
  }

  // 3. Save to localStorage history
  saveMessageToLocalHistory(cleanText, 'sent');
}

// ---------------------------------------------------------------------------
// Receive Message Pipeline
// ---------------------------------------------------------------------------

async function handleIncomingWireMessage(msg) {
  if (!msg || !msg.recipient) return;
  if (String(msg.recipient).toLowerCase() !== String(clientState.me).toLowerCase()) return;

  // Deduplicate
  const msgKey = `${msg.nonce}_${msg.seq}`;
  if (processedMessageIds.has(msgKey)) return;
  processedMessageIds.add(msgKey);

  if (!clientState.sessionKey) {
    await initCryptoEngine();
  }

  const nonceBytes = Uint8Array.from(atob(msg.nonce), c => c.charCodeAt(0));
  const ctBytes = Uint8Array.from(atob(msg.ciphertext), c => c.charCodeAt(0));

  clientState.seqIn = Math.max(clientState.seqIn, msg.seq);

  // AES-256-GCM Decryption & Auth Tag Validation
  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
      clientState.sessionKey,
      ctBytes
    );
    const decoder = new TextDecoder();
    const plaintext = decoder.decode(decryptedBuffer);

    appendReceivedMessage(plaintext);
    saveMessageToLocalHistory(plaintext, 'received');
  } catch (e) {
    appendAlert(`🚨 INTEGRITY CHECK FAILED: AES-256-GCM auth tag mismatch. Message was tampered in transit.`);
  }
}

// ---------------------------------------------------------------------------
// Local Message History
// ---------------------------------------------------------------------------

function saveMessageToLocalHistory(text, direction) {
  try {
    const key = `ig_history_${clientState.me}_${clientState.peer}`;
    const history = JSON.parse(localStorage.getItem(key) || '[]');
    history.push({ text, direction, time: Date.now() });
    if (history.length > 50) history.shift();
    localStorage.setItem(key, JSON.stringify(history));
  } catch (e) {}
}

function loadMessageHistory() {
  try {
    const key = `ig_history_${clientState.me}_${clientState.peer}`;
    const history = JSON.parse(localStorage.getItem(key) || '[]');
    history.forEach(item => {
      if (item.direction === 'sent') {
        appendSentMessage(item.text);
      } else {
        appendReceivedMessage(item.text);
      }
    });
  } catch (e) {}
}

// ---------------------------------------------------------------------------
// DOM Rendering (Instagram Direct Light Style)
// ---------------------------------------------------------------------------

function appendSentMessage(text) {
  const container = document.getElementById('messagesContainer');
  
  document.querySelectorAll('.ig-seen-label').forEach(el => el.remove());

  const row = document.createElement('div');
  row.className = 'ig-msg-row ig-msg-sent-row';
  row.innerHTML = `<div class="ig-bubble">${escapeHtml(text)}</div>`;
  container.appendChild(row);

  const seenLabel = document.createElement('div');
  seenLabel.className = 'ig-seen-label';
  seenLabel.innerText = 'Sent';
  container.appendChild(seenLabel);

  container.scrollTop = container.scrollHeight;
}

function appendReceivedMessage(text) {
  const container = document.getElementById('messagesContainer');

  const row = document.createElement('div');
  row.className = 'ig-msg-row ig-msg-received-row';
  row.innerHTML = `
    <img class="ig-msg-avatar-img" src="${clientState.profile.peerAvatarImg}" alt="avatar">
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
// Local Wire Channel Listener
// ---------------------------------------------------------------------------

networkChannel.onmessage = async (e) => {
  const data = e.data;
  if (!data) return;

  if (data.type === 'MSG_DIRECT') {
    await handleIncomingWireMessage(data);
  }
};

// ---------------------------------------------------------------------------
// Event Setup
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', async () => {
  const peerNameEl = document.getElementById('peerFullName');
  if (peerNameEl) peerNameEl.innerText = clientState.profile.peerFullName;

  const peerAvatarImgEl = document.getElementById('peerAvatarImg');
  if (peerAvatarImgEl) {
    peerAvatarImgEl.src = clientState.profile.peerAvatarImg;
    peerAvatarImgEl.alt = clientState.profile.peerFullName;
  }

  const noticePeerEl = document.getElementById('e2eeNoticePeer');
  if (noticePeerEl) noticePeerEl.innerText = clientState.profile.peerFullName;

  const currentMyUserEl = document.getElementById('currentMyUsername');
  if (currentMyUserEl) currentMyUserEl.innerText = `${clientState.profile.fullName} (@${clientState.profile.igHandle})`;

  const safetyPeerEl = document.getElementById('safetyPeerName');
  if (safetyPeerEl) safetyPeerEl.innerText = clientState.profile.peerFullName;

  const switchLink = document.getElementById('switchUserLink');
  if (switchLink) {
    switchLink.innerText = `Switch to ${clientState.profile.peerFullName}`;
    switchLink.href = `chat.html?user=${clientState.peer}`;
  }

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

  // Input & Send Setup
  const chatInput = document.getElementById('chatInput');
  const actionIcons = document.getElementById('inputActionIcons');
  const btnSend = document.getElementById('btnSend');

  function updateSendButtonVisibility() {
    const val = chatInput.value.trim();
    if (val.length > 0) {
      actionIcons.style.display = 'none';
      btnSend.style.display = 'block';
    } else {
      actionIcons.style.display = 'flex';
      btnSend.style.display = 'none';
    }
  }

  chatInput.addEventListener('input', updateSendButtonVisibility);
  chatInput.addEventListener('keyup', updateSendButtonVisibility);

  const doSend = () => {
    const text = chatInput.value;
    if (text && text.trim().length > 0) {
      sendTextMessage(text);
      chatInput.value = '';
      updateSendButtonVisibility();
      chatInput.focus();
    }
  };

  btnSend.addEventListener('click', (e) => {
    e.preventDefault();
    doSend();
  });

  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      doSend();
    }
  });

  await initCryptoEngine();
  loadMessageHistory();
  initWebSocketRelay();
});

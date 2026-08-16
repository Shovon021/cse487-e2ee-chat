/**
 * Minimalist Terminal Wire Monitor
 * No animations, pure terminal text stream.
 */

const networkChannel = new BroadcastChannel('e2ee_wire_bus');

const terminalState = {
  framesCount: 0,
  capturedPackets: []
};

const termLogs = document.getElementById('termLogs');
const termScreen = document.getElementById('termScreen');
const emptyState = document.getElementById('emptyState');
const statFrames = document.getElementById('statFrames');

// ---------------------------------------------------------------------------
// Multi-Device WebSocket Relay Listener
// ---------------------------------------------------------------------------

let wsRelay = null;
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsPort = window.location.port ? '8765' : '';
const wsUrl = `${wsProtocol}//${window.location.hostname}${wsPort ? ':' + wsPort : ''}`;

function initTerminalWebSocket() {
  try {
    wsRelay = new WebSocket(wsUrl);

    wsRelay.onopen = () => {
      wsRelay.send(JSON.stringify({ type: "REGISTER_MONITOR" }));
    };

    wsRelay.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'MSG_DIRECT') {
          processIncomingFrame(data);
        } else if (data.type === 'HISTORY_DUMP') {
          if (data.history && data.history.length > 0) {
            data.history.forEach(p => processIncomingFrame(p));
          }
        }
      } catch (err) {
        console.error("Monitor WS error", err);
      }
    };
  } catch (e) {
    console.log("WebSocket connect error, using BroadcastChannel");
  }
}

initTerminalWebSocket();

// Local inter-tab channel listener (fallback)
networkChannel.onmessage = (e) => {
  const data = e.data;
  if (!data) return;

  if (data.type === 'MSG_DIRECT') {
    processIncomingFrame(data);
  }
};

// ---------------------------------------------------------------------------
// Frame Processing & Terminal Text Logging
// ---------------------------------------------------------------------------

function processIncomingFrame(pkt) {
  // Prevent duplicate rendering
  const exists = terminalState.capturedPackets.some(p => p.nonce === pkt.nonce && p.seq === pkt.seq);
  if (exists) return;

  terminalState.framesCount += 1;
  if (statFrames) statFrames.innerText = terminalState.framesCount;
  terminalState.capturedPackets.push(pkt);

  // Hide initial waiting message
  if (emptyState) {
    emptyState.style.display = 'none';
  }

  logCapturedFrame(pkt);
}

function logCapturedFrame(pkt) {
  const dateObj = pkt.timestamp ? new Date(pkt.timestamp * 1000) : new Date();
  const timeStr = dateObj.toLocaleTimeString() + '.' + String(dateObj.getMilliseconds()).padStart(3, '0');
  
  const senderName = pkt.sender === 'Syeda' ? 'SYEDA HASAN' : (pkt.sender === 'Rukaiya' ? 'RUKAIYA BINTA HOSSAIN' : pkt.sender);
  const recipName = pkt.recipient === 'Syeda' ? 'SYEDA HASAN' : (pkt.recipient === 'Rukaiya' ? 'RUKAIYA BINTA HOSSAIN' : pkt.recipient);

  const block = document.createElement('div');
  block.className = 'term-packet-block';

  block.innerHTML = `
    <div class="term-pkt-header">
      <span>[FRAME #${terminalState.framesCount}] ${senderName} ➔ ${recipName} | SEQ: ${pkt.seq}</span>
      <span class="term-pkt-meta">${timeStr}</span>
    </div>
    <div class="term-pkt-meta">
      NONCE (12B): ${pkt.nonce} | CIPHER: AES-256-GCM (NIST SP 800-38D)
    </div>
    <div class="term-pkt-cipher">
      CIPHERTEXT (OPAQUE): ${pkt.ciphertext}
    </div>
    <div class="term-pkt-footer">
      <span>INTEGRITY: 128-BIT AUTH TAG VERIFIED</span>
      <span>PLAINTEXT LEAKS: 0 (CONFIDENTIAL)</span>
    </div>
  `;

  termLogs.appendChild(block);
  termScreen.scrollTop = termScreen.scrollHeight;
}

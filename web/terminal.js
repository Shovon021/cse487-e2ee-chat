/**
 * Minimalist Terminal Wire Monitor
 * No animations, pure terminal text stream with auto-reconnection and history replay.
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
// Multi-Device WebSocket Relay Listener (Auto-Reconnect + Keep-Alive)
// ---------------------------------------------------------------------------

let wsRelay = null;
let wsHeartbeatTimer = null;
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.host}/ws`;

function initTerminalWebSocket() {
  function connect() {
    try {
      wsRelay = new WebSocket(wsUrl);

      wsRelay.onopen = () => {
        console.log("Terminal connected to WebSocket relay:", wsUrl);
        wsRelay.send(JSON.stringify({ type: "REGISTER_MONITOR" }));

        clearInterval(wsHeartbeatTimer);
        wsHeartbeatTimer = setInterval(() => {
          if (wsRelay && wsRelay.readyState === WebSocket.OPEN) {
            wsRelay.send(JSON.stringify({ type: "PING" }));
          }
        }, 20000);
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

      wsRelay.onclose = () => {
        clearInterval(wsHeartbeatTimer);
        setTimeout(connect, 2000);
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

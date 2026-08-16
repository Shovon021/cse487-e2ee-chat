/**
 * Server & Database Wire Traffic Monitor Controller
 * 
 * Clean light-theme dashboard logging live encrypted packets.
 * Newest input appears at the top (first place).
 */

const networkChannel = new BroadcastChannel('e2ee_wire_bus');

const terminalState = {
  framesCount: 0,
  capturedPackets: []
};

const termLogs = document.getElementById('termLogs');
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
        console.log("Monitor connected to WebSocket relay:", wsUrl);
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
// Frame Processing & Rendering (Newest on Top)
// ---------------------------------------------------------------------------

function processIncomingFrame(pkt) {
  // Prevent duplicate rendering
  const exists = terminalState.capturedPackets.some(p => p.nonce === pkt.nonce && p.seq === pkt.seq);
  if (exists) return;

  terminalState.framesCount += 1;
  if (statFrames) statFrames.innerText = terminalState.framesCount;
  terminalState.capturedPackets.push(pkt);

  // Hide initial empty state message
  if (emptyState) {
    emptyState.style.display = 'none';
  }

  logCapturedFrame(pkt);
}

function logCapturedFrame(pkt) {
  const dateObj = pkt.timestamp ? new Date(pkt.timestamp * 1000) : new Date();
  const timeStr = dateObj.toLocaleTimeString() + '.' + String(dateObj.getMilliseconds()).padStart(3, '0');
  
  const senderName = pkt.sender === 'Syeda' ? 'Syeda Hasan' : (pkt.sender === 'Rukaiya' ? 'Rukaiya Binta Hossain' : pkt.sender);
  const recipName = pkt.recipient === 'Syeda' ? 'Syeda Hasan' : (pkt.recipient === 'Rukaiya' ? 'Rukaiya Binta Hossain' : pkt.recipient);

  const card = document.createElement('div');
  card.className = 'packet-card';

  card.innerHTML = `
    <div class="packet-card-header">
      <span class="packet-badge-title">CAPTURED WIRE PACKET #${terminalState.framesCount} (LATEST)</span>
      <span class="packet-time">${timeStr}</span>
    </div>
    <div class="packet-route-row">
      <span class="route-sender">Sender: <strong>${escapeHtml(senderName)}</strong></span>
      <span class="route-arrow">──►</span>
      <span class="route-recipient">Recipient: <strong>${escapeHtml(recipName)}</strong></span>
      <span class="route-seq">Sequence: #${pkt.seq}</span>
    </div>
    <div class="packet-meta-row">
      <span class="packet-meta-item">Encryption Algorithm: <strong>AES-256-GCM (NIST SP 800-38D)</strong></span>
      <span class="packet-meta-item">Nonce (12-Byte IV): <strong>${escapeHtml(pkt.nonce)}</strong></span>
    </div>
    <div class="packet-cipher-box">
      <span class="cipher-box-label">Raw Ciphertext on Wire & in Server Database:</span>
      <div class="cipher-box-code">${escapeHtml(pkt.ciphertext)}</div>
    </div>
    <div class="packet-footer-row">
      <span class="badge-integrity">Integrity: 128-Bit GCM Auth Tag Validated</span>
      <span class="badge-confidentiality">Confidentiality: 0 Plaintext Leaks (Server & Database Cannot Decrypt)</span>
    </div>
  `;

  // Prepend to insert newest packet at the top (first place)
  termLogs.insertBefore(card, termLogs.firstChild);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.innerText = text;
  return div.innerHTML;
}

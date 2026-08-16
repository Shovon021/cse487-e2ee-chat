import os
import sys

# Force UTF-8 standard output for Windows console compatibility
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

import asyncio
import threading
import http.server
import socketserver
import json
from typing import Dict, Set
import websockets
from rich.console import Console
from rich.panel import Panel

console = Console(highlight=False)

HTTP_PORT = int(os.environ.get("PORT", 5000))
WS_PORT = 8765
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# In-memory relay state
connected_clients: Dict[str, any] = {}       # username -> websocket
monitor_clients: Set[any] = set()            # set of monitor websockets
registered_keys: Dict[str, str] = {}         # username -> public_key_b64
message_history = []


# ---------------------------------------------------------------------------
# WebSocket Multi-Device Relay Handler
# ---------------------------------------------------------------------------

async def ws_relay_handler(websocket):
    client_type = "unknown"
    username = None

    try:
        async for raw_message in websocket:
            try:
                data = json.loads(raw_message)
                msg_type = data.get("type")

                # Monitor Registration
                if msg_type == "REGISTER_MONITOR":
                    client_type = "monitor"
                    monitor_clients.add(websocket)
                    # Send existing history to new monitor
                    await websocket.send(json.dumps({
                        "type": "HISTORY_DUMP",
                        "history": message_history
                    }))
                    console.print("[dim]🖥️ Terminal Monitor connected via WebSocket[/dim]")

                # User Identity & Key Announcement
                elif msg_type == "KEY_ANNOUNCE":
                    client_type = "user"
                    username = data.get("sender")
                    pub_b64 = data.get("pubB64")
                    if username and pub_b64:
                        connected_clients[username] = websocket
                        registered_keys[username] = pub_b64
                        console.print(f"[bold green]📱 Device Connected:[/bold green] [cyan]{username}[/cyan] (PK: [dim]{pub_b64[:16]}...[/dim])")
                        
                        # Broadcast announcement to all users and monitors
                        broadcast_data = json.dumps({
                            "type": "KEY_ANNOUNCE",
                            "sender": username,
                            "pubB64": pub_b64
                        })
                        for user_name, ws in connected_clients.items():
                            if ws != websocket:
                                await ws.send(broadcast_data)
                        for mon_ws in list(monitor_clients):
                            await mon_ws.send(broadcast_data)

                # Key Lookup Request
                elif msg_type == "KEY_REQUEST":
                    target = data.get("target")
                    if target in registered_keys:
                        await websocket.send(json.dumps({
                            "type": "KEY_ANNOUNCE",
                            "sender": target,
                            "pubB64": registered_keys[target]
                        }))

                # Direct Encrypted Message Relay
                elif msg_type == "MSG_DIRECT":
                    sender = data.get("sender")
                    recipient = data.get("recipient")
                    nonce = data.get("nonce")
                    ciphertext = data.get("ciphertext")
                    seq = data.get("seq")
                    timestamp = data.get("timestamp")

                    # Log to console
                    console.print(
                        f"[bold green]🔒 [RELAY][/bold green] [cyan]{sender}[/cyan] ➔ [cyan]{recipient}[/cyan] "
                        f"(Seq #{seq} | Nonce: [dim]{nonce[:10]}...[/dim] | Ciphertext: [yellow]{ciphertext[:24]}...[/yellow])"
                    )

                    # Store in history
                    packet_record = {
                        "type": "MSG_DIRECT",
                        "sender": sender,
                        "recipient": recipient,
                        "nonce": nonce,
                        "ciphertext": ciphertext,
                        "seq": seq,
                        "timestamp": timestamp
                    }
                    message_history.append(packet_record)
                    if len(message_history) > 100:
                        message_history.pop(0)

                    # Forward to recipient device if online
                    if recipient in connected_clients:
                        target_ws = connected_clients[recipient]
                        await target_ws.send(json.dumps(packet_record))

                    # Broadcast to all live Terminal Monitors (Sir's Laptop)
                    for mon_ws in list(monitor_clients):
                        try:
                            await mon_ws.send(json.dumps(packet_record))
                        except Exception:
                            monitor_clients.discard(mon_ws)

            except json.JSONDecodeError:
                pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if client_type == "monitor":
            monitor_clients.discard(websocket)
        elif username and username in connected_clients:
            connected_clients.pop(username, None)
            console.print(f"[bold yellow]🔌 Device Disconnected:[/bold yellow] [cyan]{username}[/cyan]")


async def start_ws_server():
    async with websockets.serve(ws_relay_handler, "0.0.0.0", WS_PORT):
        console.print(f"[bold green]✔ WebSocket Relay running on ws://0.0.0.0:{WS_PORT}[/bold green]")
        await asyncio.Future()  # run forever


def run_ws_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_ws_server())


# ---------------------------------------------------------------------------
# HTTP Server Handler
# ---------------------------------------------------------------------------

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        pass


def run_server():
    # Start WebSocket Relay in background thread
    ws_thread = threading.Thread(target=run_ws_loop, daemon=True)
    ws_thread.start()

    os.chdir(WEB_DIR)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", HTTP_PORT), CustomHandler) as httpd:
        console.print(Panel(
            f"[bold green]✨ CSE 487 Multi-Device Live E2EE Chat Studio[/bold green]\n\n"
            f"🌐 [bold cyan]HTTP Interface:[/bold cyan] http://0.0.0.0:{HTTP_PORT}\n"
            f"⚡ [bold magenta]WebSocket Relay:[/bold magenta] ws://0.0.0.0:{WS_PORT}\n\n"
            f"[bold yellow]Live Multi-Device Presentation URLs:[/bold yellow]\n"
            f"  📱 [cyan]Phone 1 (Alice):[/cyan] http://<YOUR-IP>:{HTTP_PORT}/chat.html?user=Alice\n"
            f"  📱 [cyan]Phone 2 (Bob):[/cyan]   http://<YOUR-IP>:{HTTP_PORT}/chat.html?user=Bob\n"
            f"  💻 [cyan]Sir's Laptop:[/cyan]    http://<YOUR-IP>:{HTTP_PORT}/terminal.html\n\n"
            f"[dim]Press Ctrl+C to terminate.[/dim]",
            title="🛡️ Multi-Device E2EE Relay Ready",
            border_style="green"
        ))
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[bold red]Server stopped.[/bold red]")


if __name__ == "__main__":
    run_server()

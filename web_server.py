"""
Unified HTTP & WebSocket Relay Server for CSE 487.

Serves static web files (Instagram DM + Terminal Monitor) and handles
real-time multi-device WebSocket routing on the EXACT SAME PORT (Port 5000 / $PORT).
"""

import os
import sys
import mimetypes
import json
import asyncio
from typing import Dict, Set
import websockets
import websockets.http11 as http11
import websockets.datastructures as ds
from rich.console import Console
from rich.panel import Panel

# Force UTF-8 standard output for Windows console compatibility
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

console = Console(highlight=False)

PORT = int(os.environ.get("PORT", 5000))
HOST = "0.0.0.0"
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# In-memory relay state
connected_clients: Dict[str, any] = {}       # username -> websocket
monitor_clients: Set[any] = set()            # set of monitor websockets
registered_keys: Dict[str, str] = {}         # username -> public_key_b64
message_history = []


# ---------------------------------------------------------------------------
# HTTP Static File Request Handler (Same Port)
# ---------------------------------------------------------------------------

async def process_http_request(connection, request):
    """
    Handle HTTP requests on the same port.
    If the request has 'Upgrade: websocket', return None so websockets handles it.
    """
    headers_dict = {k.lower(): v for k, v in request.headers.items()}
    if headers_dict.get("upgrade", "").lower() == "websocket":
        return None  # Let WebSocket handler process it

    # Standard HTTP GET file serving
    path = request.path.split("?")[0].lstrip("/")
    if not path or path == "":
        path = "index.html"

    file_path = os.path.join(WEB_DIR, path)

    # Security check: prevent directory traversal
    try:
        file_path = os.path.realpath(file_path)
        real_web_dir = os.path.realpath(WEB_DIR)
        if not file_path.startswith(real_web_dir):
            return http11.Response(
                403, "Forbidden",
                ds.Headers([("Content-Type", "text/plain")]),
                b"403 Forbidden"
            )
    except Exception:
        return http11.Response(
            400, "Bad Request",
            ds.Headers([("Content-Type", "text/plain")]),
            b"400 Bad Request"
        )

    if os.path.isfile(file_path):
        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"
        if mime_type.startswith("text/") or mime_type in ["application/javascript", "application/json"]:
            mime_type += "; charset=utf-8"

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            return http11.Response(
                200, "OK",
                ds.Headers([
                    ("Content-Type", mime_type),
                    ("Content-Length", str(len(content))),
                    ("Access-Control-Allow-Origin", "*"),
                    ("Cache-Control", "no-cache")
                ]),
                content
            )
        except Exception as e:
            return http11.Response(
                500, "Server Error",
                ds.Headers([("Content-Type", "text/plain")]),
                f"500 Server Error: {e}".encode()
            )
    else:
        return http11.Response(
            404, "Not Found",
            ds.Headers([("Content-Type", "text/plain")]),
            b"404 Not Found"
        )


# ---------------------------------------------------------------------------
# WebSocket Multi-Device Message Router (Same Port)
# ---------------------------------------------------------------------------

async def ws_relay_handler(websocket):
    client_type = "user"
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
                    if message_history:
                        await websocket.send(json.dumps({
                            "type": "HISTORY_DUMP",
                            "history": message_history
                        }))
                    console.print("[dim]🖥️ Terminal Monitor Connected via WebSocket[/dim]")

                # User Identity Announcement
                elif msg_type in ["KEY_ANNOUNCE", "USER_ONLINE"]:
                    username = data.get("sender")
                    pub_b64 = data.get("pubB64", "")
                    if username:
                        connected_clients[username] = websocket
                        if pub_b64:
                            registered_keys[username] = pub_b64
                        console.print(f"[bold green]📱 Device Connected:[/bold green] [cyan]{username}[/cyan]")
                        
                        # Forward to all monitors
                        for mon_ws in list(monitor_clients):
                            try:
                                await mon_ws.send(json.dumps({
                                    "type": "USER_ONLINE",
                                    "username": username
                                }))
                            except Exception:
                                monitor_clients.discard(mon_ws)

                # Direct Encrypted Message Relay
                elif msg_type == "MSG_DIRECT":
                    sender = data.get("sender")
                    recipient = data.get("recipient")
                    nonce = data.get("nonce")
                    ciphertext = data.get("ciphertext")
                    seq = data.get("seq")
                    timestamp = data.get("timestamp")

                    console.print(
                        f"[bold green]🔒 [RELAY][/bold green] [cyan]{sender}[/cyan] ➔ [cyan]{recipient}[/cyan] "
                        f"(Seq #{seq} | Nonce: [dim]{nonce[:8]}...[/dim] | Ciphertext: [yellow]{ciphertext[:20]}...[/yellow])"
                    )

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

                    # 1. Forward to Recipient Phone
                    if recipient in connected_clients:
                        target_ws = connected_clients[recipient]
                        try:
                            await target_ws.send(json.dumps(packet_record))
                        except Exception:
                            connected_clients.pop(recipient, None)

                    # 2. Broadcast to ALL connected Terminal Monitors (Sir's Screen)
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


# ---------------------------------------------------------------------------
# Unified Server Main Loop
# ---------------------------------------------------------------------------

async def main():
    console.print(Panel(
        f"[bold green]✨ CSE 487 Unified HTTP & Multi-Device WebSocket Relay[/bold green]\n\n"
        f"🌐 [bold cyan]Listening on:[/bold cyan] http://{HOST}:{PORT}\n"
        f"⚡ [bold magenta]Unified WebSocket:[/bold magenta] ws://{HOST}:{PORT}/ws (Exact Same Port!)\n\n"
        f"[bold yellow]Live Multi-Device Presentation URLs:[/bold yellow]\n"
        f"  📱 [cyan]Phone 1 (Syeda):[/cyan]   http://<HOST>:{PORT}/chat.html?user=Syeda\n"
        f"  📱 [cyan]Phone 2 (Rukaiya):[/cyan] http://<HOST>:{PORT}/chat.html?user=Rukaiya\n"
        f"  💻 [cyan]Sir's Laptop:[/cyan]      http://<HOST>:{PORT}/terminal.html\n\n"
        f"[dim]Press Ctrl+C to terminate.[/dim]",
        title="🛡️ Zero-Knowledge E2EE Server Ready",
        border_style="green"
    ))

    async with websockets.serve(
        ws_relay_handler,
        HOST,
        PORT,
        process_request=process_http_request
    ):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Server stopped.[/bold red]")

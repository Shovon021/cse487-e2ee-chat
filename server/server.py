"""
Zero-Knowledge Relay Server for CSE 487 Secure E2EE Chat.

The server functions strictly as an untrusted message router and public key directory.
It has NO access to private keys or plaintext, and logs only cryptographic metadata.
"""

import asyncio
import json
import argparse
import logging
from typing import Dict, Optional
import websockets
from websockets.server import WebSocketServerProtocol
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from common.protocol import (
    MessageType,
    parse_wire_message,
    create_direct_encrypted_msg
)
from server.db import Database

console = Console()


class RelayServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765, db_path: str = "server.db"):
        self.host = host
        self.port = port
        self.db = Database(db_path)
        self.active_connections: Dict[str, WebSocketServerProtocol] = {}
        self.socket_to_user: Dict[WebSocketServerProtocol, str] = {}

    async def broadcast_presence(self, username: str, is_online: bool):
        """Notify all connected clients of a user's presence change."""
        msg = json.dumps({
            "type": MessageType.USER_ONLINE.value if is_online else MessageType.USER_OFFLINE.value,
            "username": username
        })
        for user, ws in list(self.active_connections.items()):
            if user != username:
                try:
                    await ws.send(msg)
                except Exception:
                    pass

    async def handle_register(self, ws: WebSocketServerProtocol, data: dict):
        """Handle client registration and public key publication."""
        username = data.get("username", "").strip()
        public_key = data.get("public_key", "").strip()

        if not username or not public_key:
            await ws.send(json.dumps({
                "type": MessageType.REGISTER_FAILED.value,
                "error": "Missing username or public_key"
            }))
            return

        success = self.db.register_user(username, public_key)
        if not success:
            console.print(f"[bold red]❌ Registration rejected for '{username}': Public key mismatch with registered record.[/bold red]")
            await ws.send(json.dumps({
                "type": MessageType.REGISTER_FAILED.value,
                "error": "Username already registered with a different public key"
            }))
            return

        # Register connection
        self.active_connections[username] = ws
        self.socket_to_user[ws] = username

        console.print(f"[bold green]✔ User Registered & Connected:[/bold green] [cyan]{username}[/cyan] (PK: [dim]{public_key[:16]}...[/dim])")
        
        await ws.send(json.dumps({
            "type": MessageType.REGISTER_SUCCESS.value,
            "username": username,
            "message": "Registration successful. Welcome to E2EE Relay."
        }))

        await self.broadcast_presence(username, is_online=True)

        # Deliver pending offline messages
        undelivered = self.db.get_undelivered_messages(username)
        if undelivered:
            console.print(f"[yellow]📦 Spooling {len(undelivered)} stored offline ciphertext messages to [cyan]{username}[/cyan][/yellow]")
            for msg_row in undelivered:
                relay_pkt = create_direct_encrypted_msg(
                    sender=msg_row["sender"],
                    recipient=username,
                    nonce_b64=msg_row["nonce"],
                    ciphertext_b64=msg_row["ciphertext"],
                    seq_num=msg_row["seq_num"],
                    timestamp=msg_row["timestamp"]
                )
                await ws.send(relay_pkt)

    async def handle_key_lookup(self, ws: WebSocketServerProtocol, data: dict):
        """Return registered public key for a target user."""
        target = data.get("target", "").strip()
        public_key = self.db.get_public_key(target)
        if public_key:
            await ws.send(json.dumps({
                "type": MessageType.KEY_LOOKUP_SUCCESS.value,
                "target": target,
                "public_key": public_key
            }))
        else:
            await ws.send(json.dumps({
                "type": MessageType.KEY_LOOKUP_FAILED.value,
                "target": target,
                "error": f"User '{target}' not found in public key directory"
            }))

    async def handle_list_users(self, ws: WebSocketServerProtocol):
        """Return list of all registered users and online flags."""
        all_users = self.db.get_all_users()
        user_list = [
            {
                "username": u["username"],
                "public_key": u["public_key"],
                "is_online": u["username"] in self.active_connections
            }
            for u in all_users
        ]
        await ws.send(json.dumps({
            "type": MessageType.LIST_USERS_RESPONSE.value,
            "users": user_list
        }))

    async def handle_direct_message(self, ws: WebSocketServerProtocol, data: dict):
        """Relay opaque encrypted ciphertext to recipient."""
        sender = self.socket_to_user.get(ws)
        recipient = data.get("recipient", "").strip()
        nonce = data.get("nonce", "")
        ciphertext = data.get("ciphertext", "")
        seq_num = data.get("seq_num", 0)
        timestamp = data.get("timestamp", 0.0)

        if not sender or not recipient or not ciphertext:
            await ws.send(json.dumps({
                "type": MessageType.ERROR.value,
                "error": "Invalid message envelope parameters"
            }))
            return

        # Visual log proving zero-knowledge relay behavior
        console.print(Panel(
            f"[bold]From:[/bold] [cyan]{sender}[/cyan]  ➔  [bold]To:[/bold] [cyan]{recipient}[/cyan]\n"
            f"[bold]Seq #:[/bold] {seq_num} | [bold]Nonce:[/bold] [dim]{nonce}[/dim]\n"
            f"[bold]Ciphertext (Opaque):[/bold] [yellow]{ciphertext[:32]}... [dim]({len(ciphertext)} bytes)[/dim][/yellow]",
            title="🔒 [bold green]Zero-Knowledge Message Relay[/bold green]",
            border_style="blue"
        ))

        is_online = recipient in self.active_connections
        self.db.store_message(sender, recipient, nonce, ciphertext, seq_num, timestamp, delivered=is_online)

        if is_online:
            recipient_ws = self.active_connections[recipient]
            relay_pkt = create_direct_encrypted_msg(
                sender=sender,
                recipient=recipient,
                nonce_b64=nonce,
                ciphertext_b64=ciphertext,
                seq_num=seq_num,
                timestamp=timestamp
            )
            await recipient_ws.send(relay_pkt)
            await ws.send(json.dumps({
                "type": MessageType.MSG_DELIVERED.value,
                "recipient": recipient,
                "seq_num": seq_num,
                "status": "delivered_online"
            }))
        else:
            await ws.send(json.dumps({
                "type": MessageType.MSG_DELIVERED.value,
                "recipient": recipient,
                "seq_num": seq_num,
                "status": "queued_offline"
            }))

    async def client_handler(self, ws: WebSocketServerProtocol):
        """Manage individual WebSocket client connection lifetime."""
        client_ip = ws.remote_address[0] if ws.remote_address else "unknown"
        console.print(f"[dim]⚡ New incoming connection from {client_ip}[/dim]")
        
        try:
            async for raw_msg in ws:
                try:
                    data = parse_wire_message(raw_msg)
                    msg_type = data.get("type")

                    if msg_type == MessageType.REGISTER.value:
                        await self.handle_register(ws, data)
                    elif msg_type == MessageType.KEY_LOOKUP.value:
                        await self.handle_key_lookup(ws, data)
                    elif msg_type == MessageType.LIST_USERS.value:
                        await self.handle_list_users(ws)
                    elif msg_type == MessageType.MSG_DIRECT.value:
                        await self.handle_direct_message(ws, data)
                    else:
                        await ws.send(json.dumps({
                            "type": MessageType.ERROR.value,
                            "error": f"Unknown message type: {msg_type}"
                        }))
                except ValueError as e:
                    await ws.send(json.dumps({
                        "type": MessageType.ERROR.value,
                        "error": str(e)
                    }))
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            username = self.socket_to_user.pop(ws, None)
            if username:
                self.active_connections.pop(username, None)
                console.print(f"[bold yellow]🔌 User Disconnected:[/bold yellow] [cyan]{username}[/cyan]")
                await self.broadcast_presence(username, is_online=False)

    async def run(self):
        """Start the WebSocket server loop."""
        console.print(Panel(
            f"[bold green]CSE 487 Secure E2EE Chat Relay Server[/bold green]\n"
            f"Listening on: [cyan]ws://{self.host}:{self.port}[/cyan]\n"
            f"Database: [dim]{self.db.db_path}[/dim]\n"
            f"Security Mode: [bold magenta]Zero-Knowledge Encrypted Relay[/bold magenta]",
            title="🛡️ Server Initialized",
            border_style="green"
        ))
        async with websockets.serve(self.client_handler, self.host, self.port):
            await asyncio.Future()  # run forever


def main():
    parser = argparse.ArgumentParser(description="CSE 487 Secure E2EE Chat Relay Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    parser.add_argument("--db", default="server.db", help="SQLite database path")
    args = parser.parse_args()

    server = RelayServer(host=args.host, port=args.port, db_path=args.db)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        console.print("\n[bold red]Server stopped by user.[/bold red]")


if __name__ == "__main__":
    main()

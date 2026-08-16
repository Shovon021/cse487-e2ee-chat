"""
Interactive End-to-End Encrypted (E2EE) Chat Client for CSE 487.

Security Features:
- Local X25519 Private Key Generation & Storage (keys never leave the device)
- On-Demand ECDH Key Agreement & HKDF-SHA256 Session Key Derivation
- Out-of-Band Safety Number (Numeric Fingerprint) Display
- AES-256-GCM AEAD Encryption with Strict AAD Binding
- Monotonic Anti-Replay Sequence Tracking
- Real-Time Ciphertext / Nonce Debug Inspection Toggle
"""

import asyncio
import json
import os
import sys
import time
import argparse
from typing import Dict, Optional, Tuple
import websockets
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from cryptography.exceptions import InvalidTag

from common.crypto_utils import (
    generate_key_pair,
    public_key_to_b64,
    public_key_from_b64,
    private_key_to_b64,
    private_key_from_b64,
    compute_shared_secret,
    derive_session_key,
    encrypt_message,
    decrypt_message,
    compute_safety_number,
    construct_aad
)
from common.protocol import (
    MessageType,
    parse_wire_message,
    create_register_msg,
    create_key_lookup_msg,
    create_direct_encrypted_msg,
    create_list_users_msg
)

console = Console()


class E2EEClient:
    def __init__(self, username: str, server_uri: str = "ws://127.0.0.1:8765", key_dir: str = ".keys"):
        self.username = username
        self.server_uri = server_uri
        self.key_dir = key_dir
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        
        # Crypto State
        self.private_key = None
        self.public_key = None
        self._init_keys()
        
        # Session State
        self.active_peer: Optional[str] = None
        self.peer_public_keys: Dict[str, any] = {}      # peer_name -> X25519PublicKey
        self.session_keys: Dict[str, bytes] = {}        # peer_name -> 32-byte AES key
        self.outgoing_seq_nums: Dict[str, int] = {}     # peer_name -> int
        self.last_received_seq: Dict[str, int] = {}     # peer_name -> int
        
        # UI & Debug Modes
        self.inspect_mode = False
        self.running = True
        self.lookup_futures: Dict[str, asyncio.Future] = {}

    def _init_keys(self):
        """Load existing key pair or generate and save a fresh X25519 identity."""
        os.makedirs(self.key_dir, exist_ok=True)
        key_file = os.path.join(self.key_dir, f"{self.username}_keys.json")

        if os.path.exists(key_file):
            try:
                with open(key_file, "r") as f:
                    data = json.load(f)
                self.private_key = private_key_from_b64(data["private_key"])
                self.public_key = public_key_from_b64(data["public_key"])
                console.print(f"[green]✔ Loaded existing cryptographic identity for [cyan]{self.username}[/cyan][/green]")
                return
            except Exception as e:
                console.print(f"[yellow]⚠️ Failed to load key file, generating fresh identity: {e}[/yellow]")

        self.private_key, self.public_key = generate_key_pair()
        with open(key_file, "w") as f:
            json.dump({
                "username": self.username,
                "public_key": public_key_to_b64(self.public_key),
                "private_key": private_key_to_b64(self.private_key)
            }, f, indent=2)
        console.print(f"[bold green]✨ Generated new X25519 cryptographic identity for [cyan]{self.username}[/cyan][/bold green]")

    def establish_session_with_peer(self, peer_username: str, peer_pub_key) -> bytes:
        """Derive symmetric session key via ECDH and HKDF."""
        self.peer_public_keys[peer_username] = peer_pub_key
        shared_secret = compute_shared_secret(self.private_key, peer_pub_key)
        session_key = derive_session_key(shared_secret)
        self.session_keys[peer_username] = session_key
        
        if peer_username not in self.outgoing_seq_nums:
            self.outgoing_seq_nums[peer_username] = 0
            self.last_received_seq[peer_username] = 0
            
        return session_key

    def display_safety_number(self, peer_username: str):
        """Display Safety Number for out-of-band identity verification."""
        peer_pub = self.peer_public_keys.get(peer_username)
        if not peer_pub:
            console.print(f"[red]No public key available for '{peer_username}'.[/red]")
            return

        formatted_num, hex_hash = compute_safety_number(self.public_key, peer_pub)
        
        table = Table(title=f"🛡️ Safety Number with {peer_username}", show_header=False, border_style="cyan")
        table.add_row("[bold yellow]Numeric (6 Chunks):[/bold yellow]", f"[bold green]{formatted_num}[/bold green]")
        table.add_row("[bold yellow]SHA-256 Digest:[/bold yellow]", f"[dim]{hex_hash}[/dim]")
        
        console.print(table)
        console.print("[dim]Compare this number with your peer out-of-band (e.g. in person or voice) to verify no MITM attack occurred.[/dim]\n")

    async def lookup_peer_key(self, peer_username: str) -> Optional[any]:
        """Request peer's public key from the relay server."""
        if peer_username in self.peer_public_keys:
            return self.peer_public_keys[peer_username]

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.lookup_futures[peer_username] = future

        await self.ws.send(create_key_lookup_msg(peer_username))
        try:
            peer_pub_b64 = await asyncio.wait_for(future, timeout=5.0)
            peer_pub = public_key_from_b64(peer_pub_b64)
            self.establish_session_with_peer(peer_username, peer_pub)
            return peer_pub
        except asyncio.TimeoutError:
            console.print(f"[bold red]Key lookup timed out for '{peer_username}'.[/bold red]")
            return None
        except Exception as e:
            console.print(f"[bold red]Key lookup failed for '{peer_username}': {e}[/bold red]")
            return None
        finally:
            self.lookup_futures.pop(peer_username, None)

    async def send_chat_message(self, recipient: str, plaintext: str):
        """Encrypt message with AES-256-GCM and send over WebSocket."""
        if recipient not in self.session_keys:
            pub = await self.lookup_peer_key(recipient)
            if not pub:
                console.print(f"[red]Cannot send message: Failed to obtain public key for {recipient}[/red]")
                return

        session_key = self.session_keys[recipient]
        self.outgoing_seq_nums[recipient] += 1
        seq_num = self.outgoing_seq_nums[recipient]
        timestamp = time.time()

        # Build Canonical AAD
        aad = construct_aad(self.username, recipient, seq_num, timestamp)
        
        # Encrypt
        nonce_b64, ciphertext_b64 = encrypt_message(session_key, plaintext, associated_data=aad)

        # Transmit
        msg_payload = create_direct_encrypted_msg(
            sender=self.username,
            recipient=recipient,
            nonce_b64=nonce_b64,
            ciphertext_b64=ciphertext_b64,
            seq_num=seq_num,
            timestamp=timestamp
        )
        await self.ws.send(msg_payload)

        # Local UI Print
        time_str = time.strftime('%H:%M:%S', time.localtime(timestamp))
        console.print(f"[bold cyan][{time_str}] You ➔ {recipient}:[/bold cyan] {plaintext}")

        if self.inspect_mode:
            console.print(Panel(
                f"[bold]Nonce (12B):[/bold] [dim]{nonce_b64}[/dim]\n"
                f"[bold]Ciphertext + Tag (256-bit GCM):[/bold] [yellow]{ciphertext_b64}[/yellow]\n"
                f"[bold]Sequence Number:[/bold] {seq_num}",
                title="🔍 Cryptographic Inspection (Outbound)",
                border_style="magenta"
            ))

    async def handle_incoming_direct_message(self, data: dict):
        """Process incoming ciphertext frame, perform anti-replay checks, and decrypt."""
        sender = data.get("sender")
        recipient = data.get("recipient")
        nonce_b64 = data.get("nonce")
        ciphertext_b64 = data.get("ciphertext")
        seq_num = data.get("seq_num", 0)
        timestamp = data.get("timestamp", time.time())

        # Ensure session established
        if sender not in self.session_keys:
            peer_pub = await self.lookup_peer_key(sender)
            if not peer_pub:
                console.print(f"[bold red]❌ Rejected message from unknown sender '{sender}': Key lookup failed[/bold red]")
                return

        session_key = self.session_keys[sender]

        # 1. Anti-Replay & Sequence Number Verification
        last_seq = self.last_received_seq.get(sender, 0)
        if seq_num <= last_seq:
            console.print(Panel(
                f"[bold red]🚨 REPLAY / OUT-OF-ORDER ATTACK DETECTED![/bold red]\n"
                f"Sender: [cyan]{sender}[/cyan]\n"
                f"Received Sequence #: [bold red]{seq_num}[/bold red] (Expected > {last_seq})\n"
                f"Action: Packet DROPPED.",
                title="⚠️ Security Alert",
                border_style="red"
            ))
            return
            
        self.last_received_seq[sender] = seq_num

        # 2. AAD Reconstruction & Cryptographic Decryption
        aad = construct_aad(sender, recipient, seq_num, timestamp)
        try:
            plaintext = decrypt_message(session_key, nonce_b64, ciphertext_b64, associated_data=aad)
            time_str = time.strftime('%H:%M:%S', time.localtime(timestamp))
            console.print(f"[bold green][{time_str}] {sender}:[/bold green] {plaintext}")

            if self.inspect_mode:
                console.print(Panel(
                    f"[bold]Decrypted with Session Key:[/bold] [dim]{session_key.hex()[:16]}...[/dim]\n"
                    f"[bold]Received Nonce:[/bold] [dim]{nonce_b64}[/dim]\n"
                    f"[bold]Ciphertext:[/bold] [yellow]{ciphertext_b64[:32]}...[/yellow]\n"
                    f"[bold]Integrity (Auth Tag):[/bold] [bold green]VALID (MATCH)[/bold green]",
                    title="🔍 Cryptographic Inspection (Inbound)",
                    border_style="green"
                ))
        except InvalidTag:
            console.print(Panel(
                f"[bold red]🚨 MESSAGE TAMPERING / INTEGRITY CHECK FAILED![/bold red]\n"
                f"Sender: [cyan]{sender}[/cyan]\n"
                f"The ciphertext or metadata was modified in transit, or encrypted with a mismatched key.\n"
                f"Action: Decryption aborted.",
                title="❌ Cryptographic Decryption Failure",
                border_style="red"
            ))

    async def incoming_listener(self):
        """Listen for incoming WebSocket messages from the relay server."""
        try:
            async for raw_msg in self.ws:
                data = parse_wire_message(raw_msg)
                msg_type = data.get("type")

                if msg_type == MessageType.MSG_DIRECT.value:
                    await self.handle_incoming_direct_message(data)
                elif msg_type == MessageType.KEY_LOOKUP_SUCCESS.value:
                    target = data.get("target")
                    pub_key = data.get("public_key")
                    if target in self.lookup_futures and not self.lookup_futures[target].done():
                        self.lookup_futures[target].set_result(pub_key)
                elif msg_type == MessageType.KEY_LOOKUP_FAILED.value:
                    target = data.get("target")
                    err = data.get("error", "Key lookup failed")
                    if target in self.lookup_futures and not self.lookup_futures[target].done():
                        self.lookup_futures[target].set_exception(ValueError(err))
                elif msg_type == MessageType.LIST_USERS_RESPONSE.value:
                    users = data.get("users", [])
                    table = Table(title="👥 Registered Users Directory", border_style="cyan")
                    table.add_column("Username", style="cyan")
                    table.add_column("Status", style="bold")
                    table.add_column("Public Key Fingerprint", style="dim")
                    for u in users:
                        status = "[green]● Online[/green]" if u["is_online"] else "[dim]○ Offline[/dim]"
                        table.add_row(u["username"], status, u["public_key"][:20] + "...")
                    console.print(table)
                elif msg_type == MessageType.USER_ONLINE.value:
                    console.print(f"[dim]⚡ [cyan]{data.get('username')}[/cyan] is now online.[/dim]")
                elif msg_type == MessageType.USER_OFFLINE.value:
                    console.print(f"[dim]🔌 [cyan]{data.get('username')}[/cyan] went offline.[/dim]")
                elif msg_type == MessageType.ERROR.value:
                    console.print(f"[bold red]Server Error:[/bold red] {data.get('error')}")
        except websockets.exceptions.ConnectionClosed:
            if self.running:
                console.print("[bold red]Connection to relay server closed.[/bold red]")

    async def interactive_shell(self):
        """Asynchronous user command and message loop."""
        loop = asyncio.get_running_loop()
        
        console.print(Panel(
            f"[bold green]Logged in as:[/bold green] [cyan]{self.username}[/cyan]\n"
            f"[bold]Commands:[/bold]\n"
            f"  [yellow]/chat <username>[/yellow]  - Switch active chat partner\n"
            f"  [yellow]/safety[/yellow]           - View Safety Number (fingerprint) with current peer\n"
            f"  [yellow]/users[/yellow]            - List registered users & online status\n"
            f"  [yellow]/inspect[/yellow]          - Toggle cryptographic packet inspection\n"
            f"  [yellow]/help[/yellow]             - Show this help message\n"
            f"  [yellow]/exit[/yellow]             - Quit chat",
            title="💬 E2EE Chat Client Ready",
            border_style="cyan"
        ))

        while self.running:
            prompt_peer = f" ➔ {self.active_peer}" if self.active_peer else " (no peer selected)"
            try:
                line = await loop.run_in_executor(None, input, f"[{self.username}{prompt_peer}]> ")
                line = line.strip()
                if not line:
                    continue

                if line.startswith("/"):
                    parts = line.split(" ", 1)
                    cmd = parts[0].lower()

                    if cmd == "/chat":
                        if len(parts) < 2 or not parts[1].strip():
                            console.print("[red]Usage: /chat <username>[/red]")
                            continue
                        target = parts[1].strip()
                        if target == self.username:
                            console.print("[red]Cannot chat with yourself.[/red]")
                            continue
                        pub = await self.lookup_peer_key(target)
                        if pub:
                            self.active_peer = target
                            console.print(f"[bold green]✔ Chat session established with [cyan]{target}[/cyan][/bold green]")
                            self.display_safety_number(target)
                    elif cmd == "/safety":
                        if not self.active_peer:
                            console.print("[yellow]No active chat partner. Use /chat <username> first.[/yellow]")
                        else:
                            self.display_safety_number(self.active_peer)
                    elif cmd == "/users":
                        await self.ws.send(create_list_users_msg())
                    elif cmd == "/inspect":
                        self.inspect_mode = not self.inspect_mode
                        state = "[bold green]ENABLED[/bold green]" if self.inspect_mode else "[bold red]DISABLED[/bold red]"
                        console.print(f"Cryptographic inspection mode {state}.")
                    elif cmd == "/help":
                        console.print("Commands: /chat <user>, /safety, /users, /inspect, /exit")
                    elif cmd == "/exit":
                        self.running = False
                        break
                    else:
                        console.print(f"[red]Unknown command '{cmd}'. Type /help for options.[/red]")
                else:
                    if not self.active_peer:
                        console.print("[yellow]No active chat partner selected. Type /chat <username> first.[/yellow]")
                    else:
                        await self.send_chat_message(self.active_peer, line)
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break

    async def start(self):
        """Connect to relay server and start client event loop."""
        try:
            async with websockets.connect(self.server_uri) as ws:
                self.ws = ws
                # Register public key with server
                reg_payload = create_register_msg(self.username, public_key_to_b64(self.public_key))
                await ws.send(reg_payload)

                reg_resp_raw = await ws.recv()
                reg_resp = parse_wire_message(reg_resp_raw)

                if reg_resp.get("type") == MessageType.REGISTER_FAILED.value:
                    console.print(f"[bold red]❌ Registration failed: {reg_resp.get('error')}[/bold red]")
                    return

                console.print(f"[bold green]✔ Registered with relay server at {self.server_uri}[/bold green]\n")

                listener_task = asyncio.create_task(self.incoming_listener())
                shell_task = asyncio.create_task(self.interactive_shell())

                done, pending = await asyncio.wait(
                    [listener_task, shell_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
        except ConnectionRefusedError:
            console.print(f"[bold red]❌ Could not connect to relay server at {self.server_uri}. Is the server running?[/bold red]")


def main():
    parser = argparse.ArgumentParser(description="CSE 487 E2EE Secure Chat Client")
    parser.add_argument("username", help="Your chat username (e.g. Alice, Bob)")
    parser.add_argument("--server", default="ws://127.0.0.1:8765", help="WebSocket relay server URI")
    args = parser.parse_args()

    client = E2EEClient(username=args.username, server_uri=args.server)
    try:
        asyncio.run(client.start())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Client exited.[/bold yellow]")


if __name__ == "__main__":
    main()

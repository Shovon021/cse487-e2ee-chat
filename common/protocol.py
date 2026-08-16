"""
Wire Protocol Definitions & Message Framing for CSE 487 Secure E2EE Chat.

Defines standardized JSON message schemas for communication between clients
and the relay server. The server acts exclusively as a zero-knowledge router.
"""

import time
import json
import base64
from enum import Enum
from typing import Dict, Any, Optional


class MessageType(str, Enum):
    # Registration & Identity
    REGISTER = "REGISTER"
    REGISTER_SUCCESS = "REGISTER_SUCCESS"
    REGISTER_FAILED = "REGISTER_FAILED"
    
    # Key Directory Service
    KEY_LOOKUP = "KEY_LOOKUP"
    KEY_LOOKUP_SUCCESS = "KEY_LOOKUP_SUCCESS"
    KEY_LOOKUP_FAILED = "KEY_LOOKUP_FAILED"
    
    # Encrypted Message Exchange
    MSG_DIRECT = "MSG_DIRECT"
    MSG_DELIVERED = "MSG_DELIVERED"
    
    # Presence & System
    USER_ONLINE = "USER_ONLINE"
    USER_OFFLINE = "USER_OFFLINE"
    LIST_USERS = "LIST_USERS"
    LIST_USERS_RESPONSE = "LIST_USERS_RESPONSE"
    ERROR = "ERROR"


def create_register_msg(username: str, public_key_b64: str) -> str:
    """Create a registration payload with the user's X25519 public key."""
    return json.dumps({
        "type": MessageType.REGISTER.value,
        "username": username,
        "public_key": public_key_b64,
        "timestamp": time.time()
    })


def create_key_lookup_msg(target_username: str) -> str:
    """Create a key lookup request payload."""
    return json.dumps({
        "type": MessageType.KEY_LOOKUP.value,
        "target": target_username,
        "timestamp": time.time()
    })


def create_direct_encrypted_msg(
    sender: str,
    recipient: str,
    nonce_b64: str,
    ciphertext_b64: str,
    seq_num: int,
    timestamp: Optional[float] = None
) -> str:
    """
    Create a zero-knowledge direct message envelope.
    The server only inspects 'sender' and 'recipient' for routing;
    the message body (nonce + ciphertext) is opaque.
    """
    ts = timestamp if timestamp is not None else time.time()
    return json.dumps({
        "type": MessageType.MSG_DIRECT.value,
        "sender": sender,
        "recipient": recipient,
        "nonce": nonce_b64,
        "ciphertext": ciphertext_b64,
        "seq_num": seq_num,
        "timestamp": ts
    })


def create_list_users_msg() -> str:
    """Request list of all registered users."""
    return json.dumps({
        "type": MessageType.LIST_USERS.value,
        "timestamp": time.time()
    })


def parse_wire_message(raw_json: str) -> Dict[str, Any]:
    """Parse and validate JSON message."""
    try:
        data = json.loads(raw_json)
        if not isinstance(data, dict) or "type" not in data:
            raise ValueError("Message must be a JSON object with a 'type' field")
        return data
    except json.JSONDecodeError as e:
        raise ValueError(f"Malformed JSON: {str(e)}")

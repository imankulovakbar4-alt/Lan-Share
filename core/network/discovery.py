"""Validation helpers for LAN Share's UDP discovery datagrams."""

from __future__ import annotations

import json

MAX_DISCOVERY_BYTES = 4096
MAX_PEER_ID_LENGTH = 64
MAX_HOST_LENGTH = 64
MAX_ROOM_LENGTH = 32


def decode_discovery_packet(data: bytes) -> dict | None:
    """Decode a bounded UDP JSON object; reject malformed or non-object data."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not data or len(data) > MAX_DISCOVERY_BYTES:
        return None
    try:
        packet = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return packet if isinstance(packet, dict) else None


def normalize_announcement(packet: dict, source_ip: str) -> dict | None:
    """Validate a peer announcement and use the datagram source as its IP.

    The advertised 'ip' field is deliberately ignored: UDP announcements are
    unauthenticated and that field must not override the observed source address.
    """
    if not isinstance(packet, dict) or packet.get("type") == "query":
        return None

    peer_id = packet.get("id")
    if not isinstance(peer_id, str) or not peer_id or len(peer_id) > MAX_PEER_ID_LENGTH:
        return None

    port = packet.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return None

    host = packet.get("host", "")
    if not isinstance(host, str):
        host = ""
    host = host.strip()[:MAX_HOST_LENGTH] or source_ip

    room = packet.get("room", "")
    if not isinstance(room, str):
        room = ""
    room = room[:MAX_ROOM_LENGTH]

    access = packet.get("access", "")
    if not isinstance(access, str):
        access = ""
    access = access[:16]

    return {
        "id": peer_id,
        "host": host,
        "ip": source_ip,
        "port": port,
        "room": room,
        "access": access,
        "hidden": bool(packet.get("hidden", False)),
        "seen": None,  # caller supplies the monotonic wall-clock timestamp
    }

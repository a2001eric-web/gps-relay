"""
gps-relay - Zero-storage WebSocket relay for gps-bridge and Sovereign chat.

Architecture:
    GPS/device traffic  ──WebSocket──► /ws/{token}
    Sovereign chat      ──WebSocket──► /chat/{token}

The server holds active WebSocket connections in RAM only. No data is ever
written to disk or logged. Messages are forwarded verbatim to the other
connections in the same room, then discarded.

Security:
    - Tokens shorter than MIN_TOKEN_LENGTH characters are rejected (4008).
    - Each room is limited to MAX_CONNECTIONS_PER_ROOM connections (4009).
    - The server accepts at most MAX_TOTAL_TOKENS distinct tokens (4030).
    - GPS and chat traffic have separate bounded message-rate limits (4029).
    - GPS remains capped at 8 KiB; native chat is capped at 512 KiB (4013).
    - Only JSON objects matching the room's protocol shape are relayed (4003).

The legacy /ws room recognizes structurally valid native-chat envelopes so an
already-installed Companion remains usable during migration. This does not
relax the GPS lane's low-frequency or 8 KiB limits.

Protocol notes:
    - When a connection goes away, every connection still in the same room is
      sent PEER_DISCONNECTED. This is the only message the relay originates.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

MIN_TOKEN_LENGTH = 32
MAX_CONNECTIONS_PER_ROOM = 3
MAX_TOTAL_TOKENS = 500
GPS_RATE_LIMIT = 10
CHAT_RATE_LIMIT = 360
RATE_WINDOW = 30
MAX_MESSAGE_BYTES = 8192
MAX_CHAT_MESSAGE_BYTES = 512 * 1024

ENCRYPTED_ENVELOPE_FIELDS = ("ephemeral_pub", "nonce", "ciphertext", "tag")
NATIVE_CHAT_WIRE_TYPE = "sovereign_mobile_chat"
NATIVE_CHAT_ENVELOPE_FIELDS = frozenset(
    {"type", "v", "direction", "nonce", "ciphertext", "tag"}
)

# gps-bridge compares this raw literal byte for byte. Do not json.dumps it.
PEER_DISCONNECTED = '{"type":"peer_disconnected"}'

app = FastAPI(
    title="gps-relay",
    description=(
        "Zero-storage WebSocket relay. "
        "Messages are forwarded in real-time and never persisted."
    ),
)

# Maps (channel, token) -> peers. A plain dict prevents refused lookups from
# creating leaked rooms.
_connections: dict[tuple[str, str], list[WebSocket]] = {}
_rate_tracker: dict[tuple[int, str], deque[float]] = defaultdict(deque)


def _active_tokens() -> set[str]:
    return {token for _channel, token in _connections}


def _check_rate_limit(
    ws_id: int,
    lane: str,
    *,
    now: float | None = None,
) -> bool:
    current = time.monotonic() if now is None else now
    key = (ws_id, lane)
    timestamps = _rate_tracker[key]
    while timestamps and current - timestamps[0] >= RATE_WINDOW:
        timestamps.popleft()
    limit = CHAT_RATE_LIMIT if lane == "chat" else GPS_RATE_LIMIT
    if len(timestamps) >= limit:
        return False
    timestamps.append(current)
    return True


def is_gps_message(payload: dict) -> bool:
    """Return whether *payload* has the shape of a gps-bridge message."""
    if isinstance(payload.get("type"), str):
        return True
    return all(field in payload for field in ENCRYPTED_ENVELOPE_FIELDS)


def is_native_chat_message(payload: dict) -> bool:
    """Return whether *payload* has the public shape of a chat envelope."""
    return (
        payload.get("type") == NATIVE_CHAT_WIRE_TYPE
        and NATIVE_CHAT_ENVELOPE_FIELDS.issubset(payload)
        and payload.get("v") == 1
        and payload.get("direction") in {"phone_to_mac", "mac_to_phone"}
    )


def _traffic_lane(payload: dict, *, channel: str) -> str | None:
    if is_native_chat_message(payload):
        return "chat"
    if channel == "legacy" and is_gps_message(payload):
        return "gps"
    return None


@app.websocket("/ws/{token}")
async def relay(websocket: WebSocket, token: str) -> None:
    """Backward-compatible GPS/device room and native-chat migration lane."""
    await _relay_channel(websocket, token, channel="legacy")


@app.websocket("/chat/{token}")
async def chat_relay(websocket: WebSocket, token: str) -> None:
    """Dedicated room that accepts only Sovereign native-chat envelopes."""
    await _relay_channel(websocket, token, channel="chat")


async def _relay_channel(
    websocket: WebSocket,
    token: str,
    *,
    channel: str,
) -> None:
    if len(token) < MIN_TOKEN_LENGTH:
        await websocket.close(code=4008, reason="Token too short (min 32 chars).")
        return

    room = (channel, token)
    peers_for_room = _connections.get(room)
    if (
        peers_for_room is not None
        and len(peers_for_room) >= MAX_CONNECTIONS_PER_ROOM
    ):
        await websocket.close(code=4009, reason="Too many connections for this room.")
        return

    active_tokens = _active_tokens()
    if token not in active_tokens and len(active_tokens) >= MAX_TOTAL_TOKENS:
        await websocket.close(code=4030, reason="Server at capacity.")
        return

    ws_id = id(websocket)
    registered = False
    try:
        await websocket.accept()
        _connections.setdefault(room, []).append(websocket)
        registered = True

        while True:
            data = await websocket.receive_text()
            size = len(data.encode("utf-8", "surrogatepass"))
            if size > MAX_CHAT_MESSAGE_BYTES:
                await websocket.close(
                    code=4013,
                    reason="Message too large (max 512KB).",
                )
                break

            try:
                payload = json.loads(data)
            except ValueError:
                payload = None
            if not isinstance(payload, dict):
                await websocket.close(
                    code=4003,
                    reason="Only JSON objects are relayed.",
                )
                break

            lane = _traffic_lane(payload, channel=channel)
            if lane is None:
                await websocket.close(
                    code=4003,
                    reason="Unrecognised message shape.",
                )
                break
            if lane == "gps" and size > MAX_MESSAGE_BYTES:
                await websocket.close(
                    code=4013,
                    reason="Message too large (max 8KB).",
                )
                break
            if not _check_rate_limit(ws_id, lane):
                await websocket.close(
                    code=4029,
                    reason="Rate limit exceeded. Slow down.",
                )
                break

            del payload
            peers = [
                peer
                for peer in _connections.get(room, [])
                if peer is not websocket
            ]
            for peer in peers:
                try:
                    await peer.send_text(data)
                except Exception:
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        peers_to_notify: list[WebSocket] = []
        if registered:
            remaining = _connections.get(room)
            if remaining is not None:
                if websocket in remaining:
                    remaining.remove(websocket)
                if not remaining:
                    _connections.pop(room, None)
                else:
                    peers_to_notify = list(remaining)
        for key in tuple(_rate_tracker):
            if key[0] == ws_id:
                _rate_tracker.pop(key, None)

        for peer in peers_to_notify:
            try:
                await peer.send_text(PEER_DISCONNECTED)
            except Exception:
                pass


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "active_tokens": len(_active_tokens()),
            "active_rooms": len(_connections),
        }
    )

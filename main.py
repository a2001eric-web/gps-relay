"""
gps-relay - Zero-storage WebSocket relay for gps-bridge.

Architecture:
    Phone  ──WebSocket──► /ws/{token} ──► OpenClaw (gps-bridge)

The server holds active WebSocket connections in RAM only.
No data is ever written to disk or logged.
When a message arrives from one side, it is forwarded immediately
to all other connections sharing the same token, then discarded.

Security:
    - Tokens shorter than MIN_TOKEN_LENGTH characters are rejected (4008).
    - Each token is limited to MAX_CONNECTIONS_PER_TOKEN simultaneous connections (4009).
    - GPS/device traffic stays limited to GPS_RATE_LIMIT messages per
      RATE_WINDOW seconds.
    - Structurally valid Sovereign native-chat envelopes use a separate
      bounded CHAT_RATE_LIMIT so streaming cannot evict the paired bridge.
    - Oversized frames are rejected before parsing or forwarding (1009).
"""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

MIN_TOKEN_LENGTH = 32       # reject short / guessable tokens
MAX_CONNECTIONS_PER_TOKEN = 3  # reject if token already has too many connections
GPS_RATE_LIMIT = 10         # low-frequency device/GPS messages per window
CHAT_RATE_LIMIT = 360       # bounded native-chat streaming messages per window
RATE_WINDOW = 30            # seconds
MAX_MESSAGE_BYTES = 512 * 1024
NATIVE_CHAT_WIRE_TYPE = "sovereign_mobile_chat"
_NATIVE_CHAT_FIELDS = frozenset(
    {"type", "v", "direction", "nonce", "ciphertext", "tag"}
)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="gps-relay",
    description=(
        "Zero-storage WebSocket relay. "
        "Messages are forwarded in real-time and never persisted."
    ),
)

# In-memory only. Maps (channel, token) -> list[WebSocket]. Keeping channels
# separate prevents chat streaming from being broadcast to background GPS
# clients once the native app migrates to /chat. The legacy /ws endpoint still
# recognizes native-chat envelopes so already-installed clients keep working.
# Nothing is written to disk at any point.
_connections: dict[tuple[str, str], list[WebSocket]] = defaultdict(list)

# Rate tracking: maps (websocket id, traffic lane) to timestamp queues.
_rate_tracker: dict[tuple[int, str], deque[float]] = defaultdict(deque)


def _check_rate_limit(
    ws_id: int,
    lane: str,
    *,
    now: float | None = None,
) -> bool:
    """Return True if the connection is within the rate limit, False if exceeded."""
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


def _traffic_lane(data: str, *, channel: str) -> str:
    if channel == "chat":
        return "chat"
    try:
        envelope = json.loads(data)
    except json.JSONDecodeError:
        return "gps"
    if (
        isinstance(envelope, dict)
        and envelope.get("type") == NATIVE_CHAT_WIRE_TYPE
        and _NATIVE_CHAT_FIELDS.issubset(envelope)
        and envelope.get("v") == 1
        and envelope.get("direction") in {"phone_to_mac", "mac_to_phone"}
    ):
        return "chat"
    return "gps"


# ---------------------------------------------------------------------------
# WebSocket relay endpoint
# ---------------------------------------------------------------------------


@app.websocket("/ws/{token}")
async def relay(websocket: WebSocket, token: str) -> None:
    """
    Both the phone and OpenClaw connect here with the same token.
    Every message received from one side is forwarded to all other
    connections sharing that token, then immediately discarded.
    """
    await _relay_channel(websocket, token, channel="legacy")


@app.websocket("/chat/{token}")
async def chat_relay(websocket: WebSocket, token: str) -> None:
    """Dedicated high-frequency room for Sovereign native chat."""
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
    if len(_connections[room]) >= MAX_CONNECTIONS_PER_TOKEN:
        await websocket.close(code=4009, reason="Too many connections for this token.")
        return

    await websocket.accept()
    ws_id = id(websocket)
    _connections[room].append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if len(data.encode("utf-8")) > MAX_MESSAGE_BYTES:
                await websocket.close(code=1009, reason="Message too large.")
                break

            lane = _traffic_lane(data, channel=channel)
            if not _check_rate_limit(ws_id, lane):
                await websocket.close(
                    code=4029, reason="Rate limit exceeded. Slow down."
                )
                break

            peers = [ws for ws in _connections[room] if ws is not websocket]
            for peer in peers:
                try:
                    await peer.send_text(data)
                except Exception:
                    pass  # peer disconnected between check and send
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _connections.get(room, ()):
            _connections[room].remove(websocket)
        if not _connections.get(room):
            _connections.pop(room, None)
        for key in tuple(_rate_tracker):
            if key[0] == ws_id:
                _rate_tracker.pop(key, None)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> JSONResponse:
    """
    Returns the number of currently active tokens (not the tokens themselves).
    Safe to expose publicly.
    """
    return JSONResponse(
        {
            "status": "ok",
            "active_tokens": len({token for _channel, token in _connections}),
            "active_rooms": len(_connections),
        }
    )

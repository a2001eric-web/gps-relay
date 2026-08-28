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
    - The server accepts at most MAX_TOTAL_TOKENS distinct tokens at once (4030).
    - Each connection is limited to RATE_LIMIT messages per RATE_WINDOW seconds.
      Exceeding the limit closes the connection (4029).
    - Messages larger than MAX_MESSAGE_BYTES are rejected (4013).
    - Messages that are not a JSON object are rejected (4003).
    - JSON objects that do not look like a gps-bridge message are rejected (4003).

    The last three checks exist so the relay cannot be repurposed as a general
    purpose chat / file transfer channel.  They inspect *shape only* — the
    relay never reads, logs or persists message content, and rejection reasons
    never echo any part of the message back to the client.

Protocol notes:
    - When a connection goes away, every connection still in the same room is
      sent PEER_DISCONNECTED.  This is the only message the relay ever
      originates itself; it carries no information about who left.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

MIN_TOKEN_LENGTH = 32       # reject short / guessable tokens
MAX_CONNECTIONS_PER_TOKEN = 3  # reject if token already has too many connections
MAX_TOTAL_TOKENS = 500      # global cap on distinct rooms held in RAM
RATE_LIMIT = 10             # max messages per connection per window
RATE_WINDOW = 30            # seconds
MAX_MESSAGE_BYTES = 8192    # real GPS packets are 400-600 bytes; 13x headroom

# A gps-bridge message is either a control message carrying a "type" string,
# or a bare end-to-end encrypted envelope carrying exactly these four fields.
ENCRYPTED_ENVELOPE_FIELDS = ("ephemeral_pub", "nonce", "ciphertext", "tag")

# Sent to everyone left in a room when one of its connections goes away.
#
# This MUST stay a literal string.  gps-bridge compares the raw frame it
# receives against this exact text with `==` (see gps_bridge/connector.py),
# so the encoding has to match byte for byte.  json.dumps() would produce
# '{"type": "peer_disconnected"}' -- an extra space after the colon -- and the
# comparison on the other side would silently never match, leaving the phone
# stuck as "online" forever.  Do not "tidy" this into json.dumps().
PEER_DISCONNECTED = '{"type":"peer_disconnected"}'

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

# In-memory only.  Maps token -> list[WebSocket].
# A plain dict (not defaultdict) so that merely *looking up* a token never
# creates an entry that would then be leaked if the connection is refused.
# Nothing is written to disk at any point.
_connections: dict[str, list[WebSocket]] = {}

# Rate tracking: Maps websocket id -> list of message timestamps (floats)
_rate_tracker: dict[int, list[float]] = defaultdict(list)


def _check_rate_limit(ws_id: int) -> bool:
    """Return True if the connection is within the rate limit, False if exceeded."""
    now = time.monotonic()
    timestamps = _rate_tracker[ws_id]
    # Discard timestamps outside the current window
    _rate_tracker[ws_id] = [t for t in timestamps if now - t < RATE_WINDOW]
    if len(_rate_tracker[ws_id]) >= RATE_LIMIT:
        return False
    _rate_tracker[ws_id].append(now)
    return True


def is_gps_message(payload: dict) -> bool:
    """
    Return True if *payload* has the shape of a gps-bridge message.

    Deliberately permissive: the value of "type" is not validated, because the
    phone app may send control types this relay has never heard of.  The size
    limit is the primary defence against abuse; this check only rules out
    arbitrary JSON blobs that carry neither a control type nor an encrypted
    envelope.

    Never inspects, logs or stores the message *content*.
    """
    if isinstance(payload.get("type"), str):
        return True
    return all(field in payload for field in ENCRYPTED_ENVELOPE_FIELDS)


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
    # Fix 1: reject short tokens before accepting the connection
    if len(token) < MIN_TOKEN_LENGTH:
        await websocket.close(code=4008, reason="Token too short (min 32 chars).")
        return

    # Fix 3: reject if token already has too many connections.
    # `.get()` on a plain dict, so a refused connection leaves no entry behind.
    peers_for_token = _connections.get(token)
    if peers_for_token is not None and len(peers_for_token) >= MAX_CONNECTIONS_PER_TOKEN:
        await websocket.close(code=4009, reason="Too many connections for this token.")
        return

    # Fix 5: global cap on distinct tokens, so nobody can flood RAM with rooms
    if peers_for_token is None and len(_connections) >= MAX_TOTAL_TOKENS:
        await websocket.close(code=4030, reason="Server at capacity.")
        return

    ws_id = id(websocket)
    registered = False
    try:
        # accept() and the registration below live inside the try block so that
        # a failure in either one still runs the cleanup in `finally`.
        await websocket.accept()
        _connections.setdefault(token, []).append(websocket)
        registered = True

        while True:
            data = await websocket.receive_text()

            # Fix 2: rate limit per connection
            if not _check_rate_limit(ws_id):
                await websocket.close(
                    code=4029, reason="Rate limit exceeded. Slow down."
                )
                break

            # Fix 6a: size limit — a GPS packet is never this big
            if len(data.encode("utf-8", "surrogatepass")) > MAX_MESSAGE_BYTES:
                await websocket.close(
                    code=4013, reason="Message too large (max 8KB)."
                )
                break

            # Fix 6b: must be a JSON object
            try:
                payload = json.loads(data)
            except ValueError:
                payload = None
            if not isinstance(payload, dict):
                await websocket.close(
                    code=4003, reason="Only JSON objects are relayed."
                )
                break

            # Fix 6c: must look like a gps-bridge message
            if not is_gps_message(payload):
                await websocket.close(
                    code=4003, reason="Unrecognised message shape."
                )
                break

            # Content is forwarded verbatim and never inspected further.
            del payload

            peers = [ws for ws in _connections.get(token, []) if ws is not websocket]
            for peer in peers:
                try:
                    await peer.send_text(data)
                except Exception:
                    pass  # peer disconnected between check and send
    except WebSocketDisconnect:
        pass
    finally:
        # Bookkeeping first, notification second: if sending the notification
        # were to fail, the room and rate-tracker entries are already released.
        peers_to_notify: list[WebSocket] = []
        if registered:
            remaining = _connections.get(token)
            if remaining is not None:
                if websocket in remaining:
                    remaining.remove(websocket)
                if not remaining:
                    _connections.pop(token, None)
                else:
                    # Snapshot, so the loop below is unaffected by concurrent
                    # joins or departures.
                    peers_to_notify = list(remaining)
        _rate_tracker.pop(ws_id, None)

        # Tell whoever is left that a peer went away.  This is generated by the
        # server, not received from a client, so it is deliberately not counted
        # against anybody's rate limit.
        for peer in peers_to_notify:
            try:
                await peer.send_text(PEER_DISCONNECTED)
            except Exception:
                pass  # that peer is gone too


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> JSONResponse:
    """
    Returns the number of currently active tokens (not the tokens themselves).
    Safe to expose publicly.
    """
    return JSONResponse({"status": "ok", "active_tokens": len(_connections)})

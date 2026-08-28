# gps-relay

Zero-storage WebSocket relay for [gps-bridge](https://github.com/luna61ouo/gps-bridge).

## What it does

```
Phone ──[encrypted GPS]──► /ws/{token} ──► OpenClaw (gps-bridge)
```

- Messages are forwarded in real-time between paired connections
- **Nothing is ever written to disk** — not even the token
- Active connections are held in RAM only and disappear when disconnected
- Open-source so anyone can verify the zero-storage guarantee
- Only gps-bridge-shaped messages are relayed, so it cannot be repurposed
  as a general chat / file-transfer channel
- When a connection drops, the others in the same room are told, so a client
  can tell "peer is offline" from "peer is quiet"

## Requirements

- Python 3.10+
- A server with a public IP / domain (behind Nginx with TLS recommended)

## Setup

```bash
git clone https://github.com/luna61ouo/gps-relay.git
cd gps-relay
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8767 --ws-max-size 16384
```

## Nginx (TLS)

```nginx
location /relay/ {
    proxy_pass http://127.0.0.1:8767/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

Phone and OpenClaw connect to:
```
wss://yourdomain.com/relay/ws/{token}
```

## Peer disconnect notification

When a connection leaves a room, every connection still in that room receives
exactly:

```
{"type":"peer_disconnected"}
```

This is the only message the relay originates itself. It says nothing about
who left, is not counted against any rate limit, and is not sent when the room
is left empty.

The byte encoding is part of the contract: gps-bridge compares incoming frames
against this literal with `==`, so the relay sends a fixed string rather than
re-serialising a dict. `json.dumps({"type": "peer_disconnected"})` would insert
a space after the colon and the comparison would silently never match.

## Health check

```
GET /health
→ {"status": "ok", "active_tokens": 2}
```

## Security

The relay is deliberately narrow: it will only carry gps-bridge traffic.
Every check below inspects **shape and size only** — message content is never
read, logged or stored, and a rejection reason never echoes any part of the
message back to the sender.

### Connection limits

| Check | Close code |
|---|---|
| Token shorter than 32 characters | 4008 |
| More than 3 simultaneous connections on one token | 4009 |
| More than 500 distinct tokens (rooms) server-wide | 4030 |
| More than 10 messages per connection per 30 seconds | 4029 |

### Message filter

Every message is checked before it is forwarded:

1. **Size** — larger than `MAX_MESSAGE_BYTES` (8 KB) → close `4013`.
   Real GPS packets are 400–600 bytes, so this leaves ~13x headroom.
   Run uvicorn with `--ws-max-size 16384` so anything grossly oversized is
   dropped a layer earlier, before it reaches the application.
2. **JSON object** — not parseable as JSON, or not an object → close `4003`.
3. **gps-bridge shape** — must have either a string `type` field, or all four
   fields of an encrypted envelope (`ephemeral_pub`, `nonce`, `ciphertext`,
   `tag`) → otherwise close `4003`.

The value of `type` is deliberately **not** validated. Phone apps may send
control messages this relay has never heard of, and rejecting them would break
working setups. The size limit is the primary defence against abuse.

Note: checks that run before the WebSocket handshake completes (4008, 4009,
4030) are surfaced by uvicorn as an HTTP `403` handshake rejection, so clients
see `403` rather than the close code.

## Tests

```bash
python3 tests/test_message_filter.py
```

Starts a second relay instance on port 8768 and drives it with real WebSocket
clients, including a genuine encrypted packet built with gps-bridge's own
crypto module. Requires `websockets` and `cryptography`.

## License

MIT

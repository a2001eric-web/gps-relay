# gps-relay

Zero-storage WebSocket relay for [gps-bridge](https://github.com/luna61ouo/gps-bridge).

## What it does

```
Phone ──[encrypted GPS]──► /ws/{token} ──► OpenClaw (gps-bridge)
```

- Messages are forwarded in real-time between paired connections
- **The relay process never writes to disk** — not the token, not a message
- Active connections are held in RAM only and disappear when disconnected
- Open-source so anyone can verify the zero-storage guarantee
- The guarantee covers this process only. The token is part of the URL path,
  so **your reverse proxy will log it** unless you turn that off — see
  [Nginx](#nginx-tls) below
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

    # The token is in the request path, so the default access log writes every
    # user's token to disk in plaintext, indefinitely. The token is the room
    # key: anyone holding it can join the room and receive its traffic.
    # The relay itself stores nothing; this line is what keeps that true for
    # the deployment as a whole.
    access_log off;
}
```

Phone and OpenClaw connect to:
```
wss://yourdomain.com/relay/ws/{token}
```

### Keeping the log but masking the token

If you want request logging for the relay, log a masked path instead of the
real one. `map` and `log_format` go at `http` level, not inside `location`:

```nginx
map $request_uri $relay_uri_masked {
    "~^(/relay/(?:ws|chat)/)"  "$1***";
    default           $request_uri;
}

log_format relay_masked '$remote_addr [$time_local] '
                        '"$request_method $relay_uri_masked" $status $body_bytes_sent';
```

then in the `location` block, replace `access_log off;` with:

```nginx
access_log /var/log/nginx/relay.log relay_masked;
```

Two things this does not cover:

- `error_log` at `info` or `debug` level records the full URI. Keep it at
  `warn` or higher.
- Any log already on disk from before. Existing tokens stay valid, so rotating
  the old logs out is not enough on its own — re-pair to retire them.

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

## Sovereign native chat

Sovereign native-chat clients may use the isolated streaming room:
```
wss://yourdomain.com/relay/chat/{token}
```

The legacy `/ws` room recognizes structurally valid native-chat envelopes and
applies their separate bounded streaming quota, so existing installed clients
remain compatible. GPS/device messages keep their original low-frequency
and 8 KiB limits. Native chat is capped at 512 KiB, 360 messages per 30
seconds, and three connections per room. The `/chat` room accepts only the
native-chat envelope shape; it is not a general file relay.

Set the WebSocket server's frame ceiling above the application ceiling. For
the combined deployment use `--ws-max-size 1048576`; GPS-only deployments may
keep the smaller 16384-byte setting.

## Health check

```
GET /health
→ {"status": "ok", "active_tokens": 2, "active_rooms": 3}
```

## Security

The relay is deliberately narrow: it carries gps-bridge traffic and
Sovereign's encrypted native-chat envelope shape.
Every check below inspects **shape and size only** — message content is never
read, logged or stored, and a rejection reason never echoes any part of the
message back to the sender.

### Connection limits

| Check | Close code |
|---|---|
| Token shorter than 32 characters | 4008 |
| More than 3 simultaneous connections in one room | 4009 |
| More than 500 distinct tokens (rooms) server-wide | 4030 |
| More than 10 GPS messages per connection per 30 seconds | 4029 |
| More than 360 chat messages per connection per 30 seconds | 4029 |

### Message filter

Every message is checked before it is forwarded:

1. **Size** — GPS larger than 8 KiB or native chat larger than 512 KiB →
   close `4013`.
   Real GPS packets are 400–600 bytes, so this leaves ~13x headroom.
   Run uvicorn with `--ws-max-size 16384` so anything grossly oversized is
   dropped a layer earlier, before it reaches the application.
2. **JSON object** — not parseable as JSON, or not an object → close `4003`.
3. **room protocol shape** — `/ws` accepts gps-bridge messages plus the native
   chat migration envelope; `/chat` accepts only a complete native-chat
   envelope → otherwise close `4003`.

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

The two cases that need real encrypted packets look for a gps-bridge checkout
next to this repository. If it is somewhere else, point `GPS_BRIDGE_ROOT` at
it:

```bash
GPS_BRIDGE_ROOT=/path/to/gps-bridge python3 tests/test_message_filter.py
```

If gps-bridge cannot be found those two cases are reported as `SKIP`, every
other case still runs, and the script still exits `0` — a missing optional
dependency is not a test failure.

## License

MIT

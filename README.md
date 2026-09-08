# gps-relay

Zero-storage WebSocket relay for [gps-bridge](https://github.com/myasaliu/gps-bridge).

## What it does

```
Phone ──[encrypted GPS]──► /ws/{token} ──► OpenClaw (gps-bridge)
```

- Messages are forwarded in real-time between paired connections
- **Nothing is ever written to disk** — not even the token
- Active connections are held in RAM only and disappear when disconnected
- Open-source so anyone can verify the zero-storage guarantee

## Requirements

- Python 3.10+
- A server with a public IP / domain (behind Nginx with TLS recommended)

## Setup

```bash
git clone https://github.com/myasaliu/gps-relay.git
cd gps-relay
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8767
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

Sovereign native-chat clients may use the isolated streaming room:
```
wss://yourdomain.com/relay/chat/{token}
```

The legacy `/ws` room recognizes authenticated native-chat envelopes and
applies their separate bounded streaming quota, so existing installed clients
remain compatible. GPS/device messages keep their original low-frequency
limit. Every frame is capped at 512 KiB and the relay still stores nothing.

## Health check

```
GET /health
→ {"status": "ok", "active_tokens": 2, "active_rooms": 3}
```

## License

MIT

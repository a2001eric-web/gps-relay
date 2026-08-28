#!/usr/bin/env python3
"""
Deterministic probe for the connection-registry leak.

Runs `relay()` directly against a stub WebSocket, so we can force the exact
failure the fix is about: `accept()` raising after the token has been looked up.

Before the fix, `_connections` was a defaultdict and the token was registered
*outside* the try/finally, so a failed accept() left an empty room behind that
was never cleaned up.  Reconnect churn made that grow without bound.

Must be run with the project venv (it imports fastapi via main.py):

    venv/bin/python3 tests/accept_failure_probe.py

Prints one JSON line; exits non-zero if anything leaked.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import main  # noqa: E402

ROUNDS = 25
LONG_TOKEN = "T" * 40


class StubWebSocket:
    """Minimal stand-in for starlette's WebSocket."""

    def __init__(self, fail_accept: bool) -> None:
        self.fail_accept = fail_accept
        self.closed_with: tuple[int, str] | None = None

    async def accept(self) -> None:
        if self.fail_accept:
            raise RuntimeError("simulated handshake failure")

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed_with = (code, reason)

    async def receive_text(self) -> str:
        # Behave like a client that hung up right after connecting.
        raise main.WebSocketDisconnect(code=1006)

    async def send_text(self, data: str) -> None:  # pragma: no cover
        pass


async def drive(fail_accept: bool) -> int:
    """Run `relay()` ROUNDS times, each with a distinct token; return rooms left."""
    for index in range(ROUNDS):
        stub = StubWebSocket(fail_accept=fail_accept)
        try:
            await main.relay(stub, f"{LONG_TOKEN}{index:04d}")
        except Exception:
            # The old code let the accept() error escape; that is the scenario.
            pass
    return len(main._connections)


async def run() -> int:
    leaked_on_accept_failure = await drive(fail_accept=True)
    main._connections.clear()
    leaked_on_normal_disconnect = await drive(fail_accept=False)

    result = {
        "rounds": ROUNDS,
        "rooms_left_after_accept_failure": leaked_on_accept_failure,
        "rooms_left_after_normal_disconnect": leaked_on_normal_disconnect,
    }
    print(json.dumps(result))
    return 0 if leaked_on_accept_failure == 0 and leaked_on_normal_disconnect == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))

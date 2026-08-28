#!/usr/bin/env python3
"""
End-to-end test for the gps-relay message filter.

This is NOT a unit test: it starts a real uvicorn instance of main.py on a
spare port (default 8768, so the production instance on 8767 is untouched) and
drives it with real WebSocket clients.

The "happy path" case uses a genuine end-to-end encrypted envelope produced by
gps-bridge's own crypto module, so the test proves the filter accepts real
traffic rather than a hand-written imitation of it.

Run:
    python3 tests/test_message_filter.py

Interpreters:
    * the relay is started with the project venv (venv/bin/uvicorn) --
      that is the exact binary production uses;
    * this script itself needs `websockets` + `cryptography` (for gps-bridge's
      crypto module).  On Luke's box the system python3 has both, so the usual
      invocation is `/usr/bin/python3 tests/test_message_filter.py`.

Nothing is written to disk by the relay; this script only prints a result table.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GPS_BRIDGE_ROOT = Path(
    os.environ.get("GPS_BRIDGE_ROOT", "/mnt/SPSSD/luke/gps-bridge")
)

PORT = int(os.environ.get("RELAY_TEST_PORT", "8768"))
HOST = "127.0.0.1"
WS_MAX_SIZE = 16384  # must match the production uvicorn flag

sys.path.insert(0, str(GPS_BRIDGE_ROOT))

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
except ImportError:  # pragma: no cover
    sys.exit("This test needs the `websockets` package (try /usr/bin/python3).")

try:
    from gps_bridge.crypto import encrypt_payload, generate_keypair
except ImportError as exc:  # pragma: no cover
    sys.exit(
        f"Cannot import gps_bridge.crypto from {GPS_BRIDGE_ROOT} ({exc}).\n"
        "This test needs the `cryptography` package (try /usr/bin/python3)."
    )


# ---------------------------------------------------------------------------
# Test payloads
# ---------------------------------------------------------------------------


def real_encrypted_packet() -> str:
    """Build a genuine gps-bridge encrypted GPS packet (not a fake)."""
    _receiver_private, receiver_public = generate_keypair()
    plaintext = json.dumps(
        {
            "lat": 25.033964,
            "lng": 121.564468,
            "timestamp": int(time.time()),
            "accuracy": 12.5,
            "speed": 0.0,
        }
    ).encode()
    return json.dumps(encrypt_payload(plaintext, receiver_public))


PASS = "PASS"  # expected to be relayed


def build_cases() -> list[tuple[str, str, object]]:
    """Return [(description, raw_message, expectation)] where expectation is
    PASS or the expected WebSocket close code."""
    big_json = json.dumps({"type": "ping", "pad": "A" * 9000})
    assert 8192 < len(big_json.encode()) < WS_MAX_SIZE, len(big_json)

    return [
        ("Real encrypted GPS packet (gps-bridge crypto)", real_encrypted_packet(), PASS),
        ('{"type":"ping"}', '{"type":"ping"}', PASS),
        ('{"type":"location_request"}', '{"type":"location_request"}', PASS),
        (
            '{"type":"settings_update", ...}',
            json.dumps(
                {
                    "type": "settings_update",
                    "confirm_mode": True,
                    "update_interval_seconds": 60,
                    "history_granularity_seconds": 300,
                    "retention_hours": 24,
                }
            ),
            PASS,
        ),
        ('{"type":"peer_disconnected"}', '{"type":"peer_disconnected"}', PASS),
        (
            'Unknown type string (deliberately allowed)',
            '{"type":"some_type_we_have_never_seen"}',
            PASS,
        ),
        ("9 KB of valid JSON", big_json, 4013),
        ("Plain text 'hello world'", "hello world", 4003),
        ("JSON array [1,2,3]", "[1,2,3]", 4003),
        ('{"foo":"bar"} (no type, not an envelope)', '{"foo":"bar"}', 4003),
    ]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def new_token() -> str:
    """A fresh >=32 char token per case, so cases cannot interfere."""
    return secrets.token_urlsafe(32)[:43]


async def run_case(description: str, message: str, expectation: object) -> tuple[bool, str]:
    token = new_token()
    url = f"ws://{HOST}:{PORT}/ws/{token}"
    try:
        async with websockets.connect(url, max_size=WS_MAX_SIZE) as receiver:
            async with websockets.connect(url, max_size=WS_MAX_SIZE) as sender:
                await sender.send(message)

                if expectation is PASS:
                    try:
                        got = await asyncio.wait_for(receiver.recv(), timeout=5)
                    except asyncio.TimeoutError:
                        return False, "not forwarded (timed out waiting on peer)"
                    except ConnectionClosed as exc:
                        return False, f"peer closed unexpectedly ({exc.code})"
                    if got != message:
                        return False, "forwarded content differs from what was sent"
                    return True, "relayed verbatim"

                # Rejection cases: the sender must be closed with the right code
                try:
                    await asyncio.wait_for(sender.recv(), timeout=5)
                except ConnectionClosed as exc:
                    if exc.code == expectation:
                        return True, f"closed {exc.code}: {exc.reason}"
                    return False, f"closed {exc.code} (expected {expectation}): {exc.reason}"
                except asyncio.TimeoutError:
                    return False, f"still open (expected close {expectation})"
                return False, f"got a message back (expected close {expectation})"
    except Exception as exc:  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


def active_tokens() -> int:
    """Ask /health how many rooms the relay is holding in RAM."""
    import urllib.request

    with urllib.request.urlopen(f"http://{HOST}:{PORT}/health", timeout=5) as resp:
        return json.load(resp)["active_tokens"]


def check_no_leak_on_accept_failure() -> tuple[bool, str]:
    """
    Delegate to accept_failure_probe.py, which drives relay() directly with a
    stub WebSocket whose accept() raises -- the exact failure the leak fix is
    about.  Aborting a real TCP handshake does not work as a probe: uvicorn
    never dispatches to the app, so the buggy code path is never entered.

    The probe is run with the project venv because it imports main.py (fastapi).
    Verified to be a real instrument: against the pre-fix main.py it reports 25
    leaked rooms out of 25 rounds.
    """
    probe = REPO_ROOT / "tests" / "accept_failure_probe.py"
    proc = subprocess.run(
        [str(REPO_ROOT / "venv" / "bin" / "python3"), str(probe)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    output = proc.stdout.strip().splitlines()
    if not output:
        return False, f"probe produced no output (rc={proc.returncode})"
    try:
        data = json.loads(output[-1])
    except ValueError:
        return False, f"unparseable probe output: {output[-1][:80]}"
    leaked = data["rooms_left_after_accept_failure"]
    leaked_normal = data["rooms_left_after_normal_disconnect"]
    if leaked == 0 and leaked_normal == 0:
        return True, f"{data['rounds']} failed accepts + {data['rounds']} clean hangups left 0 rooms"
    return False, f"leaked {leaked} room(s) on accept failure, {leaked_normal} on hangup"


def _constant(name: str) -> int:
    """Read a constant out of main.py without importing fastapi."""
    import re

    source = (REPO_ROOT / "main.py").read_text()
    match = re.search(rf"^{name}\s*=\s*(\d+)", source, re.MULTILINE)
    if not match:
        raise RuntimeError(f"{name} not found in main.py")
    return int(match.group(1))


async def check_total_token_cap() -> tuple[bool, str]:
    """
    Fill the relay to MAX_TOTAL_TOKENS rooms, then check the next new room is
    refused.

    Note on the observed wire behaviour: the cap (like the pre-existing 4008
    token-length and 4009 per-token checks) rejects *before* accept(), and
    uvicorn turns a pre-accept close into an HTTP 403 handshake rejection -- so
    the client sees 403, not the 4030 code.  Both outcomes count as "refused".
    """
    cap = _constant("MAX_TOTAL_TOKENS")
    held = []
    try:
        for _ in range(cap):
            held.append(await websockets.connect(f"ws://{HOST}:{PORT}/ws/{new_token()}"))
        if active_tokens() != cap:
            return False, f"expected {cap} rooms, /health says {active_tokens()}"
        try:
            extra = await websockets.connect(f"ws://{HOST}:{PORT}/ws/{new_token()}")
        except ConnectionClosed as exc:
            if exc.code == 4030:
                return True, f"room #{cap + 1} closed 4030: {exc.reason}"
            return False, f"room #{cap + 1} closed {exc.code} (expected 4030)"
        except websockets.exceptions.InvalidStatus as exc:
            status = exc.response.status_code
            if status == 403:
                return True, f"room #{cap + 1} refused pre-accept (HTTP {status})"
            return False, f"room #{cap + 1} refused with HTTP {status} (expected 403)"
        await extra.close()
        return False, f"room #{cap + 1} was accepted (expected refusal)"
    finally:
        for ws in held:
            try:
                await ws.close()
            except Exception:
                pass
        await asyncio.sleep(1.0)


async def wait_for_server(proc: subprocess.Popen, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"ws://{HOST}:{PORT}/ws/{new_token()}"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"relay exited early (rc={proc.returncode})")
        try:
            async with websockets.connect(url):
                return
        except Exception:
            await asyncio.sleep(0.3)
    raise RuntimeError("relay did not become ready in time")


async def main() -> int:
    uvicorn_bin = REPO_ROOT / "venv" / "bin" / "uvicorn"
    if not uvicorn_bin.exists():
        return int(bool(print(f"missing {uvicorn_bin}; create the venv first")))

    print(f"Starting test relay on {HOST}:{PORT} (production 8767 untouched)...")
    proc = subprocess.Popen(
        [
            str(uvicorn_bin),
            "main:app",
            "--host",
            HOST,
            "--port",
            str(PORT),
            "--ws-max-size",
            str(WS_MAX_SIZE),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    results: list[tuple[str, object, bool, str]] = []
    try:
        await wait_for_server(proc)
        print("Relay ready.\n")
        for description, message, expectation in build_cases():
            ok, detail = await run_case(description, message, expectation)
            results.append((description, expectation, ok, detail))

        # Resource hygiene (memory-leak fix + global room cap)
        ok, detail = check_no_leak_on_accept_failure()
        results.append(("No room leak when accept() fails", "0 rooms", ok, detail))

        ok, detail = await check_total_token_cap()
        results.append(("Global room cap (MAX_TOTAL_TOKENS)", "refuse", ok, detail))

        left = active_tokens()
        results.append(
            (
                "All rooms released at the end",
                "0 rooms",
                left == 0,
                f"/health active_tokens = {left}",
            )
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()

    width = max(len(r[0]) for r in results)
    print(f"{'CASE'.ljust(width)} | EXPECT  | RESULT | DETAIL")
    print("-" * (width + 48))
    for description, expectation, ok, detail in results:
        expect = "relay" if expectation is PASS else str(expectation)
        mark = "ok  " if ok else "FAIL"
        print(f"{description.ljust(width)} | {expect:<7} | {mark}   | {detail}")

    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

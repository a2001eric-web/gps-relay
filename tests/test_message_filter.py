#!/usr/bin/env python3
"""
End-to-end test for the gps-relay message filter.

This is NOT a unit test: it starts a real uvicorn instance of main.py on a
spare port (default 8768, so the production instance on 8767 is untouched) and
drives it with real WebSocket clients.

The "happy path" case uses a genuine end-to-end encrypted envelope produced by
gps-bridge's own crypto module, so the test proves the filter accepts real
traffic rather than a hand-written imitation of it.

It also covers the peer_disconnected notification.  The literal the relay sends
is compared against the literal gps-bridge actually tests for -- read straight
out of gps_bridge/connector.py, not retyped here -- so a whitespace change on
either side fails the test instead of silently breaking phone-offline
detection in production.

Run:
    python3 tests/test_message_filter.py

Interpreters:
    * the relay is started with the project venv (venv/bin/uvicorn) --
      that is the exact binary production uses;
    * this script itself needs `websockets` + `cryptography` (for gps-bridge's
      crypto module).  If your system python3 has both, `python3
      tests/test_message_filter.py` is enough; otherwise run it from a venv
      that does.

Set GPS_BRIDGE_ROOT to point at a gps-bridge checkout if it is not a sibling
directory of this repository.  Tests that need real encrypted payloads are
skipped when it cannot be found.

Nothing is written to disk by the relay; this script only prints a result table.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GPS_BRIDGE_ROOT = Path(
    os.environ.get("GPS_BRIDGE_ROOT", str(REPO_ROOT.parent / "gps-bridge"))
)

PORT = int(os.environ.get("RELAY_TEST_PORT", "8768"))
HOST = "127.0.0.1"
WS_MAX_SIZE = 16384  # must match the production uvicorn flag

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
except ImportError:  # pragma: no cover
    sys.exit("This test needs the `websockets` package (try /usr/bin/python3).")

#: Sentinel used in the result table for cases that could not be run because
#: an optional dependency (gps-bridge) is absent.  Skipped != failed.
SKIP = "SKIP"

#: How many cases in this file need a real gps-bridge checkout.
BRIDGE_DEPENDENT_CASES = 2

BRIDGE_CONNECTOR = GPS_BRIDGE_ROOT / "gps_bridge" / "connector.py"
BRIDGE_CRYPTO = GPS_BRIDGE_ROOT / "gps_bridge" / "crypto.py"

encrypt_payload = generate_keypair = None

# The checkout is looked for on disk *before* importing, and GPS_BRIDGE_ROOT is
# put at the front of sys.path, so this test always exercises the gps-bridge it
# was pointed at -- never some other copy that happens to be installed on the
# host.
if not (BRIDGE_CRYPTO.is_file() and BRIDGE_CONNECTOR.is_file()):
    GPS_BRIDGE_ERROR = f"no gps-bridge checkout at {GPS_BRIDGE_ROOT}"
else:
    sys.path.insert(0, str(GPS_BRIDGE_ROOT))
    try:
        from gps_bridge.crypto import encrypt_payload, generate_keypair
    except ImportError as exc:  # pragma: no cover - depends on the host
        GPS_BRIDGE_ERROR = (
            f"cannot import gps_bridge.crypto from {GPS_BRIDGE_ROOT} ({exc}); "
            "it also needs the `cryptography` package"
        )
    else:
        GPS_BRIDGE_ERROR = None

#: True when everything this test needs from gps-bridge is present.  When it is
#: False the cases that need real encrypted packets are reported as SKIP and
#: every other case still runs; the script still exits 0.
GPS_BRIDGE_AVAILABLE = GPS_BRIDGE_ERROR is None


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


#: The comparison gps-bridge performs on every incoming frame, extracted from
#: its source rather than retyped, so this test tracks the real consumer:
#:     if raw == '{"type":"peer_disconnected"}':
BRIDGE_COMPARISON_RE = re.compile(
    r"""raw\s*==\s*(?P<q>['"])(?P<literal>.*?peer_disconnected.*?)(?P=q)"""
)


def bridge_expected_literal() -> str:
    """Return the exact string gps-bridge's connector compares raw frames to."""
    match = BRIDGE_COMPARISON_RE.search(BRIDGE_CONNECTOR.read_text())
    if not match:
        raise RuntimeError(
            f"no peer_disconnected comparison found in {BRIDGE_CONNECTOR}"
        )
    return match.group("literal")


PASS = "PASS"  # expected to be relayed


def build_cases() -> list[tuple[str, object, object]]:
    """Return [(description, raw_message, expectation)] where expectation is
    PASS or the expected WebSocket close code.

    A raw_message of None means "this case needs gps-bridge and gps-bridge is
    not available" -- the caller reports it as SKIP instead of running it.
    """
    big_json = json.dumps({"type": "ping", "pad": "A" * 9000})
    assert 8192 < len(big_json.encode()) < WS_MAX_SIZE, len(big_json)

    return [
        (
            "Real encrypted GPS packet (gps-bridge crypto)",
            real_encrypted_packet() if GPS_BRIDGE_AVAILABLE else None,
            PASS,
        ),
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


# ---------------------------------------------------------------------------
# peer_disconnected notification
# ---------------------------------------------------------------------------


async def check_peer_disconnected_pair() -> tuple[bool, str]:
    """Two connections in a room; one leaves, the other must be told."""
    url = f"ws://{HOST}:{PORT}/ws/{new_token()}"
    async with websockets.connect(url, max_size=WS_MAX_SIZE) as survivor:
        leaver = await websockets.connect(url, max_size=WS_MAX_SIZE)
        await leaver.close()
        try:
            got = await asyncio.wait_for(survivor.recv(), timeout=5)
        except asyncio.TimeoutError:
            return False, "survivor was never notified (timed out after 5s)"
        except ConnectionClosed as exc:
            return False, f"survivor was closed instead ({exc.code})"
    if got != '{"type":"peer_disconnected"}':
        return False, f"received {got!r}"
    return True, f"received {got!r}"


async def check_peer_disconnected_matches_bridge() -> tuple[object, str]:
    """
    The single most important case: feed what the relay actually sent into the
    comparison gps-bridge actually performs, and require True.

    Needs gps-bridge on disk (the comparison is read out of its connector.py).
    Whether the notification is *sent at all* is covered without gps-bridge by
    check_peer_disconnected_pair / _three, which compare against a literal.
    """
    if not GPS_BRIDGE_AVAILABLE:
        return SKIP, f"needs gps-bridge -- {GPS_BRIDGE_ERROR}"

    expected = bridge_expected_literal()
    url = f"ws://{HOST}:{PORT}/ws/{new_token()}"
    async with websockets.connect(url, max_size=WS_MAX_SIZE) as survivor:
        leaver = await websockets.connect(url, max_size=WS_MAX_SIZE)
        await leaver.close()
        try:
            raw = await asyncio.wait_for(survivor.recv(), timeout=5)
        except asyncio.TimeoutError:
            return False, "nothing received to compare"

    # This is gps-bridge's connector.py line, verbatim.
    matched = raw == expected
    if not matched:
        return False, f"relay sent {raw!r}, bridge tests for {expected!r}"
    return True, f"raw == {expected!r} -> True"


async def check_peer_disconnected_three() -> tuple[bool, str]:
    """Three connections in a room; one leaves, both survivors must be told."""
    url = f"ws://{HOST}:{PORT}/ws/{new_token()}"
    async with websockets.connect(url, max_size=WS_MAX_SIZE) as first:
        async with websockets.connect(url, max_size=WS_MAX_SIZE) as second:
            leaver = await websockets.connect(url, max_size=WS_MAX_SIZE)
            await leaver.close()
            received = []
            for label, ws in (("first", first), ("second", second)):
                try:
                    received.append(await asyncio.wait_for(ws.recv(), timeout=5))
                except asyncio.TimeoutError:
                    return False, f"{label} survivor was not notified"
    wrong = [r for r in received if r != '{"type":"peer_disconnected"}']
    if wrong:
        return False, f"unexpected payload {wrong[0]!r}"
    return True, f"both survivors notified ({len(received)}/2)"


async def check_peer_disconnected_solo(log_path: Path) -> tuple[bool, str]:
    """
    A lone connection leaving has nobody to notify.  The room must still be
    released and the relay must not raise -- checked by scanning the relay's
    own stderr for a traceback appearing during this window.
    """
    before_log = log_path.read_text() if log_path.exists() else ""
    before = active_tokens()

    url = f"ws://{HOST}:{PORT}/ws/{new_token()}"
    solo = await websockets.connect(url, max_size=WS_MAX_SIZE)
    await solo.close()
    await asyncio.sleep(0.5)

    after = active_tokens()
    new_log = (log_path.read_text() if log_path.exists() else "")[len(before_log):]
    if "Traceback" in new_log or "Exception in" in new_log:
        first_line = new_log.strip().splitlines()[0][:80]
        return False, f"relay logged an error: {first_line}"
    if after != before:
        return False, f"room not released (active_tokens {before} -> {after})"

    # Still serving afterwards?
    try:
        async with websockets.connect(
            f"ws://{HOST}:{PORT}/ws/{new_token()}", max_size=WS_MAX_SIZE
        ):
            pass
    except Exception as exc:
        return False, f"relay unusable afterwards: {type(exc).__name__}"
    return True, f"no traceback, active_tokens {before} -> {after}, relay still serving"


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

    if not GPS_BRIDGE_AVAILABLE:
        print(
            f"gps-bridge not found ({GPS_BRIDGE_ERROR}); "
            f"{BRIDGE_DEPENDENT_CASES} test(s) needing real encrypted packets "
            "were skipped -- set GPS_BRIDGE_ROOT to enable them.\n"
        )

    print(f"Starting test relay on {HOST}:{PORT} (production 8767 untouched)...")
    # The relay's own stderr, so the solo-disconnect case can prove no
    # exception was raised rather than merely assuming it.  Deleted at the end.
    log_fd, log_name = tempfile.mkstemp(prefix="gps-relay-test-", suffix=".log")
    log_path = Path(log_name)
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
        stdout=log_fd,
        stderr=log_fd,
    )
    os.close(log_fd)

    results: list[tuple[str, object, bool, str]] = []
    try:
        await wait_for_server(proc)
        print("Relay ready.\n")
        for description, message, expectation in build_cases():
            if message is None:
                results.append(
                    (description, expectation, SKIP, f"needs gps-bridge -- {GPS_BRIDGE_ERROR}")
                )
                continue
            ok, detail = await run_case(description, message, expectation)
            results.append((description, expectation, ok, detail))

        # Resource hygiene (memory-leak fix + global room cap)
        ok, detail = check_no_leak_on_accept_failure()
        results.append(("No room leak when accept() fails", "0 rooms", ok, detail))

        ok, detail = await check_total_token_cap()
        results.append(("Global room cap (MAX_TOTAL_TOKENS)", "refuse", ok, detail))

        # peer_disconnected notification
        ok, detail = await check_peer_disconnected_pair()
        results.append(("2 in room, 1 leaves -> peer notified", "notify", ok, detail))

        ok, detail = await check_peer_disconnected_matches_bridge()
        results.append(
            ("Sent literal passes gps-bridge's `raw ==` test", "True", ok, detail)
        )

        ok, detail = await check_peer_disconnected_three()
        results.append(("3 in room, 1 leaves -> both notified", "notify", ok, detail))

        ok, detail = await check_peer_disconnected_solo(log_path)
        results.append(("Lone connection leaves -> clean, no raise", "clean", ok, detail))

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
        log_path.unlink(missing_ok=True)

    width = max(len(r[0]) for r in results)
    print(f"{'CASE'.ljust(width)} | EXPECT  | RESULT | DETAIL")
    print("-" * (width + 48))
    for description, expectation, ok, detail in results:
        expect = "relay" if expectation is PASS else str(expectation)
        mark = SKIP if ok is SKIP else ("ok  " if ok else "FAIL")
        print(f"{description.ljust(width)} | {expect:<7} | {mark}   | {detail}")

    failed = [r for r in results if r[2] is not SKIP and not r[2]]
    skipped = [r for r in results if r[2] is SKIP]
    passed = len(results) - len(failed) - len(skipped)

    summary = f"{passed} passed"
    if failed:
        summary += f", {len(failed)} failed"
    if skipped:
        summary += f", {len(skipped)} skipped"
    print(f"\n{summary} (of {len(results)} cases).")

    # Skipped is not failed: a missing optional dependency must not turn the
    # whole run red.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import main

TOKEN = "t" * 40


@pytest.fixture(autouse=True)
def clear_runtime_state():
    main._connections.clear()
    main._rate_tracker.clear()
    yield
    main._connections.clear()
    main._rate_tracker.clear()


def test_legacy_room_keeps_gps_limit_but_native_chat_has_own_lane() -> None:
    client = TestClient(main.app)
    chat_frame = json.dumps(
        {
            "type": main.NATIVE_CHAT_WIRE_TYPE,
            "v": 1,
            "direction": "mac_to_phone",
            "nonce": "n",
            "ciphertext": "c",
            "tag": "t",
        }
    )
    with (
        client.websocket_connect(f"/ws/{TOKEN}") as sender,
        client.websocket_connect(f"/ws/{TOKEN}") as receiver,
    ):
        for _ in range(main.GPS_RATE_LIMIT + 2):
            sender.send_text(chat_frame)
            assert receiver.receive_text() == chat_frame

        for index in range(main.GPS_RATE_LIMIT):
            payload = json.dumps({"gps": index})
            sender.send_text(payload)
            assert receiver.receive_text() == payload

        sender.send_text('{"gps":"over-limit"}')
        with pytest.raises(WebSocketDisconnect) as caught:
            sender.receive_text()
        assert caught.value.code == 4029


def test_dedicated_chat_room_accepts_streaming_and_is_separate() -> None:
    client = TestClient(main.app)
    with (
        client.websocket_connect(f"/chat/{TOKEN}") as sender,
        client.websocket_connect(f"/chat/{TOKEN}") as receiver,
    ):
        for index in range(main.GPS_RATE_LIMIT + 2):
            payload = json.dumps({"delta": index})
            sender.send_text(payload)
            assert receiver.receive_text() == payload


def test_oversized_frame_is_closed_before_forwarding() -> None:
    client = TestClient(main.app)
    with client.websocket_connect(f"/ws/{TOKEN}") as sender:
        sender.send_text("x" * (main.MAX_MESSAGE_BYTES + 1))
        with pytest.raises(WebSocketDisconnect) as caught:
            sender.receive_text()
        assert caught.value.code == 1009


def test_health_counts_tokens_not_rooms() -> None:
    client = TestClient(main.app)
    with (
        client.websocket_connect(f"/ws/{TOKEN}"),
        client.websocket_connect(f"/chat/{TOKEN}"),
    ):
        response = client.get("/health")
        assert response.json() == {
            "status": "ok",
            "active_tokens": 1,
            "active_rooms": 2,
        }


def test_native_chat_marker_without_envelope_fields_stays_in_gps_lane() -> None:
    raw = json.dumps({"type": main.NATIVE_CHAT_WIRE_TYPE})
    assert main._traffic_lane(raw, channel="legacy") == "gps"

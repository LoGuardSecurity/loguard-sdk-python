"""AI wire compatibility and error privacy. All content and credentials are synthetic."""
import hashlib
import hmac
from dataclasses import asdict
from datetime import datetime, timezone

import httpx
import pytest

from loguard import _transport
from loguard.exceptions import LoGuardError
from loguard._signing import build_body, sign
from loguard.monitor import _Monitor


@pytest.mark.parametrize("event_type,meta", [
    ("ai_llm_request", {"prompt": "Synthetic հայկական request"}),
    ("ai_llm_response", {"response": "Synthetic response", "usage": {"output_tokens": 2}}),
    ("ai_tool_call", {"tool_name": "search_documents", "tool_args": {}, "success": True}),
])
def test_ai_wire_and_exact_body_signature(event_type, meta):
    monitor = _Monitor()
    monitor._env = "test"
    monitor._default_service = None
    event = monitor._build_event(type=event_type, ip="203.0.113.10", path="/ai/test",
                                 status_code=200, meta=meta,
                                 ts=datetime(2026, 1, 1, tzinfo=timezone.utc))
    wire = asdict(event)
    assert wire["type"] == event_type
    assert all(wire["meta"][key] == value for key, value in meta.items())
    body = build_body({"events": [wire]})
    sent, headers = sign("synthetic-key", body)
    expected = hmac.new(b"synthetic-key", headers["X-LoGuard-Timestamp"].encode() + b"." + body,
                        hashlib.sha256).hexdigest()
    assert sent == body
    assert headers["X-LoGuard-Signature"] == "sha256=" + expected


@pytest.mark.parametrize("status", [403, 404, 409, 422, 429, 500])
def test_http_error_does_not_expose_response_content(status):
    marker = "SYNTHETIC_PRIVATE_MARKER"
    response = httpx.Response(status, json={"detail": {
        "err": "usage_limit_exceeded", "plan": marker, "input": marker}})
    with pytest.raises(LoGuardError) as error:
        _transport._raise_for_status(response)
    assert marker not in str(error.value)

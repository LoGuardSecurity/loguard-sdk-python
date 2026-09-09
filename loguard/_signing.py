"""
loguard/_signing.py

Request signing for LoGuard SDK.
Adds HMAC-SHA256 signature to every outbound request.

Server verifies:
  1. Timestamp is fresh (< 5 min)
  2. Signature matches body
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Tuple


def sign(api_key: str, body_bytes: bytes) -> Tuple[bytes, dict]:
    """
    Sign a request body and return (body_bytes, signed_headers).

    Args:
        api_key:    Raw API key
        body_bytes: JSON-encoded request body

    Returns:
        Tuple of (body_bytes, headers_dict)
    """
    timestamp      = int(time.time())
    signed_payload = f"{timestamp}.".encode() + body_bytes

    signature = hmac.new(
        api_key.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "X-Api-Key":              api_key,
        "X-LoGuard-Timestamp":   str(timestamp),
        "X-LoGuard-Signature":   f"sha256={signature}",
        "X-Request-ID":           str(uuid.uuid4()),
        "Content-Type":           "application/json",
        "User-Agent":             "loguard-python-sdk/2.0.0",
    }
    return body_bytes, headers


def build_body(payload: dict) -> bytes:
    """Serialize payload to deterministic JSON bytes."""
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
"""Bounded HTTP field capture shared by framework integrations."""

from __future__ import annotations

import json
import math
from itertools import islice
from urllib.parse import parse_qsl

DEFAULT_STATUSES = frozenset({400, 401, 403, 404, 429, 500, 502, 503})
KNOWN_EXPLOIT_HEADERS = (
    "user-agent",
    "referer",
    "x-beresource",
    "x-anonresource-backend",
)
FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)
FORBIDDEN_FIELDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "csrf",
    "xsrf",
    "private_key",
    "ssn",
    "card_number",
    "card_num",
    "cvv",
    "cvc",
    "credit_card",
    "pin",
    "otp",
)
MAX_FIELDS = 64
MAX_VALUE_BYTES = 4096
MAX_QUERY_BYTES = 32768


def truncate(value: str, limit: int) -> str:
    return (
        value[:limit]
        .encode("utf-8", errors="replace")[:limit]
        .decode("utf-8", errors="ignore")
    )


def forbidden(name: str) -> bool:
    return any(part in name.lower() for part in FORBIDDEN_FIELDS)


def clean(value, depth: int, budget: list[int]):
    if isinstance(value, (dict, list)):
        if depth <= 0:
            return "[depth-limited]"
        out = {} if isinstance(value, dict) else []
        items = value.items() if isinstance(value, dict) else enumerate(value)
        for key, child in items:
            if budget[0] <= 0:
                break
            budget[0] -= 1
            if isinstance(key, str) and forbidden(key):
                continue
            child = clean(child, depth - 1, budget)
            if isinstance(out, dict):
                out[truncate(str(key), MAX_VALUE_BYTES)] = child
            else:
                out.append(child)
        return out
    if isinstance(value, str):
        return truncate(value, MAX_VALUE_BYTES)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value if value is None or isinstance(value, (int, float, bool)) else None


def _depth_exceeded(value, limit: int) -> bool:
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > limit:
                return True
            children = node.values() if isinstance(node, dict) else node
            stack.extend(
                (child, depth + 1)
                for child in children
                if isinstance(child, (dict, list))
            )
    return False


def _bounded_pairs(text: str):
    for field in text.split("&", MAX_FIELDS)[:MAX_FIELDS]:
        for name, value in parse_qsl(field, keep_blank_values=True, max_num_fields=1):
            if name:
                yield name, value


def _reject_json_constant(_):
    raise ValueError("Non-standard JSON constant")


class CapturePolicy:
    """Explicit opt-in capture. Field-name filtering is not a PII classifier."""

    def __init__(self, *, max_body_bytes=32768, max_json_depth=8):
        for name, value, ceiling in (
            ("max_body_bytes", max_body_bytes, 1048576),
            ("max_json_depth", max_json_depth, 32),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{name} must be an integer in 1..{ceiling}")
        self.max_body_bytes = max_body_bytes
        self.max_json_depth = max_json_depth

    def query(self, pairs) -> dict:
        # Bound inspection, including forbidden names, rather than only output.
        selected = {}
        for name, value in islice(pairs, MAX_FIELDS):
            if name and not forbidden(name):
                selected[truncate(name, MAX_VALUE_BYTES)] = truncate(
                    value, MAX_VALUE_BYTES
                )
        return selected

    def raw_query(self, raw: bytes) -> dict:
        if len(raw) > MAX_QUERY_BYTES:
            return {"query_too_large": True}
        pairs = _bounded_pairs(raw.decode("utf-8", errors="replace"))
        query = self.query(pairs)
        return {"query": query} if query else {}

    def body(self, raw: bytes, content_type: str) -> dict:
        media = content_type.split(";", 1)[0].strip().lower()
        if not self.supports(media):
            return {"body_unsupported_content_type": True}
        if len(raw) > self.max_body_bytes:
            return {"body_too_large": True}
        if not raw:
            return {}
        try:
            text = raw.decode("utf-8")
            if (
                media == "application/x-www-form-urlencoded"
                and not text.lstrip().startswith(("{", "["))
            ):
                decoded = dict(_bounded_pairs(text))
            else:
                decoded = json.loads(text, parse_constant=_reject_json_constant)
            if not isinstance(decoded, (dict, list)):
                return {"body_parse_error": True}
            if _depth_exceeded(decoded, self.max_json_depth):
                return {"body_depth_exceeded": True}
            fields = clean(decoded, self.max_json_depth, [MAX_FIELDS])
            return {"body": fields} if fields else {}
        except RecursionError:
            return {"body_depth_exceeded": True}
        except (ValueError, UnicodeError):
            return {"body_parse_error": True}

    @staticmethod
    def supports(content_type: str) -> bool:
        media = content_type.split(";", 1)[0].strip().lower()
        return media in {"application/json", "application/x-www-form-urlencoded"} or (
            media.startswith("application/") and media.endswith("+json")
        )

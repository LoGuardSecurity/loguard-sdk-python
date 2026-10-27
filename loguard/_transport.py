from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .exceptions import (
    LoGuardAuthError,
    LoGuardConnectionError,
    LoGuardConflictError,
    LoGuardNotFoundError,
    LoGuardQuotaError,
    LoGuardValidationError,
)
from .models import AlertOut, IngestResult
from ._signing import sign, build_body

log = logging.getLogger("loguard")

_RETRY_STATUSES = {500, 502, 503, 504}


def _safe_json(resp: httpx.Response) -> Tuple[Any, str]:
    text = ""
    try:
        text = resp.text or ""
    except Exception:
        pass
    snippet = text[:400]
    try:
        j = resp.json()
        return j, snippet
    except Exception:
        return None, snippet


def _raise_for_status(resp: httpx.Response) -> Any:
    data, snippet = _safe_json(resp)
    d = data if isinstance(data, dict) else {}

    if resp.status_code == 401:
        raise LoGuardAuthError("Invalid API key")
    if resp.status_code == 402:
        raise LoGuardAuthError("Subscription expired — renew at loguard.org")
    if resp.status_code == 403:
        detail = d.get("detail", snippet)
        if detail == "subscription_expired":
            raise LoGuardAuthError("Subscription expired — renew at loguard.org")
        raise LoGuardAuthError("Access denied")
    if resp.status_code == 404:
        raise LoGuardNotFoundError("Not found")
    if resp.status_code == 409:
        raise LoGuardConflictError("Conflict")
    if resp.status_code == 422:
        raise LoGuardValidationError("Validation error")
    if resp.status_code == 429:
        detail = d.get("detail", {})
        if isinstance(detail, dict) and detail.get("err") == "usage_limit_exceeded":
            raise LoGuardQuotaError(
                "Monthly quota exceeded"
            )
        raise LoGuardConnectionError("Rate limited")
    if resp.status_code >= 500:
        raise LoGuardConnectionError(f"Server error ({resp.status_code})")

    return data


def parse_ingest_response(data: Any) -> IngestResult:
    d = data if isinstance(data, dict) else {}
    alerts = [AlertOut(**a) for a in (d.get("alerts") or [])]
    return IngestResult(
        ok=bool(d.get("ok", False)),
        inserted=int(d.get("accepted", d.get("inserted", 0))),
        dropped=int(d.get("dropped", 0)),
        alerts_fired=len(d.get("alerts") or []),
        alerts=alerts,
        plan=str(d.get("plan", "")),
        usage=dict(d.get("usage", {}) or {}),
    )


# Signed transport

def send_sync(
    url: str,
    headers: dict,
    payload: dict,
    timeout: float,
    retries: int,
    method: str = "POST",
    api_key: str = "",          # ← NEW: for signing
) -> Any:
    """
    Send signed POST request.
    If api_key provided — signs request with HMAC-SHA256.
    Falls back to json= if no api_key (backward compat).
    """
    last_exc: Exception = LoGuardConnectionError("Unknown error")

    for attempt in range(1, retries + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                if api_key and method == "POST":
                    # Signed request
                    body_bytes, signed_headers = sign(api_key, build_body(payload))
                    resp = client.post(url, content=body_bytes, headers=signed_headers)
                else:
                    # Unsigned (GET/PUT/DELETE or no key)
                    fn = getattr(client, method.lower())
                    resp = fn(url, json=payload, headers=headers)

            if resp.status_code not in _RETRY_STATUSES:
                return _raise_for_status(resp)

            last_exc = LoGuardConnectionError(f"Server error {resp.status_code}")
            log.warning("Attempt %d/%d failed status=%d", attempt, retries, resp.status_code)

        except (httpx.RequestError, httpx.TimeoutException) as e:
            last_exc = LoGuardConnectionError("Connection error")
            log.warning("Attempt %d/%d connection error", attempt, retries)

        if attempt < retries:
            time.sleep(0.4 * attempt)

    raise last_exc


def send_sync_no_body(
    url: str,
    headers: dict,
    timeout: float,
    retries: int,
    method: str = "GET",
) -> Any:
    """GET/DELETE requests — no body, no signing needed."""
    last_exc: Exception = LoGuardConnectionError("Unknown error")
    for attempt in range(1, retries + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                fn = getattr(client, method.lower())
                resp = fn(url, headers=headers)
            if resp.status_code not in _RETRY_STATUSES:
                return _raise_for_status(resp)
            last_exc = LoGuardConnectionError(f"Server error {resp.status_code}")
        except (httpx.RequestError, httpx.TimeoutException) as e:
            last_exc = LoGuardConnectionError("Connection error")
        if attempt < retries:
            time.sleep(0.4 * attempt)
    raise last_exc


async def send_async(
    url: str,
    headers: dict,
    payload: dict,
    timeout: float,
    retries: int,
    method: str = "POST",
    api_key: str = "",
) -> Any:
    last_exc: Exception = LoGuardConnectionError("Unknown error")
    for attempt in range(1, retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if api_key and method == "POST":
                    # Signed request
                    body_bytes, signed_headers = sign(api_key, build_body(payload))
                    resp = await client.post(url, content=body_bytes, headers=signed_headers)
                else:
                    fn = getattr(client, method.lower())
                    resp = await fn(url, json=payload, headers=headers)

            if resp.status_code not in _RETRY_STATUSES:
                return _raise_for_status(resp)

            last_exc = LoGuardConnectionError(f"Server error {resp.status_code}")

        except (httpx.RequestError, httpx.TimeoutException) as e:
            last_exc = LoGuardConnectionError("Connection error")

        if attempt < retries:
            await asyncio.sleep(0.4 * attempt)

    raise last_exc


async def send_async_no_body(
    url: str,
    headers: dict,
    timeout: float,
    retries: int,
    method: str = "GET",
) -> Any:
    last_exc: Exception = LoGuardConnectionError("Unknown error")
    for attempt in range(1, retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                fn = getattr(client, method.lower())
                resp = await fn(url, headers=headers)
            if resp.status_code not in _RETRY_STATUSES:
                return _raise_for_status(resp)
            last_exc = LoGuardConnectionError(f"Server error {resp.status_code}")
        except (httpx.RequestError, httpx.TimeoutException) as e:
            last_exc = LoGuardConnectionError("Connection error")
        if attempt < retries:
            await asyncio.sleep(0.4 * attempt)
    raise last_exc
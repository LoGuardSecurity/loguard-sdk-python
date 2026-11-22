"""FastAPI/Starlette integration using transparent ASGI message observation."""
from __future__ import annotations

import logging
from time import monotonic

from starlette.requests import Request

from .._capture import (
    CapturePolicy, DEFAULT_STATUSES, FORBIDDEN_HEADERS,
    KNOWN_EXPLOIT_HEADERS, truncate,
)
from .._ip_utils import _get_real_ip
from ..monitor import monitor as _monitor

log = logging.getLogger("loguard.fastapi")
# Retained for integrations importing the previous private constant.
_FORBIDDEN_TRACK_HEADERS = FORBIDDEN_HEADERS


class LoGuardMiddleware:
    """Queue HTTP telemetry without waiting for ingest.

    Set security_capture=True to capture bounded query/body fields for all
    statuses. Bodies are observed only as the application reads them. Header
    capture remains an explicit allowlist; credential headers are blocked.
    """

    def __init__(self, app, *, track_statuses=None, get_user_id=None,
                 track_headers=None, trusted_proxies=None, track_all=False,
                 security_capture=False, max_body_bytes=32768, max_json_depth=8):
        self.app = app
        self._track_statuses = DEFAULT_STATUSES if track_statuses is None else frozenset(track_statuses)
        self._get_user_id = get_user_id
        self._track_headers = tuple(dict.fromkeys(
            h.strip().lower() for h in (track_headers or ())
            if h.strip().lower() not in FORBIDDEN_HEADERS
        ))[:64]
        self._trusted_proxies = tuple(trusted_proxies or ())
        self._track_all = track_all
        self._security_capture = security_capture
        self._policy = CapturePolicy(max_body_bytes=max_body_bytes, max_json_depth=max_json_depth)

    def _collect_tracked_headers(self, request):
        return {name: truncate(request.headers[name], 512)
                for name in self._track_headers if name in request.headers}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        started = monotonic()
        status = None
        failed = False
        raw = bytearray()
        complete = False
        too_large = False
        capture_failed = False
        content_type = request.headers.get("content-type", "")
        supported = self._policy.supports(content_type)

        async def observed_receive():
            nonlocal complete, too_large, capture_failed
            message = await receive()
            if self._security_capture and message["type"] == "http.request":
                try:
                    chunk = message.get("body", b"")
                    if supported and not too_large:
                        if len(raw) + len(chunk) > self._policy.max_body_bytes:
                            raw.clear()
                            too_large = True
                        else:
                            raw.extend(chunk)
                    complete = not message.get("more_body", False)
                except Exception:
                    raw.clear()
                    capture_failed = True
            return message

        async def observed_send(message):
            nonlocal status
            await send(message)
            if message["type"] == "http.response.start":
                status = message["status"]

        try:
            await self.app(scope, observed_receive, observed_send)
        except Exception:
            failed = True
            raise
        finally:
            try:
                effective_status = status if status is not None else (500 if failed else None)
                if effective_status is not None and (
                    self._security_capture or self._track_all or effective_status in self._track_statuses
                ):
                    meta = {"method": request.method, "duration_ms": round((monotonic() - started) * 1000, 3)}
                    headers = self._collect_tracked_headers(request)
                    if headers:
                        meta["headers"] = headers
                    if self._security_capture:
                        meta.update(self._policy.raw_query(scope.get("query_string", b"")))
                        if capture_failed:
                            meta["body_capture_error"] = True
                        elif too_large:
                            meta["body_too_large"] = True
                        elif not supported:
                            meta["body_unsupported_content_type"] = True
                        elif complete:
                            meta.update(self._policy.body(bytes(raw), content_type))
                        else:
                            meta["body_unavailable"] = True
                    user_id = None
                    if self._get_user_id:
                        try:
                            user_id = self._get_user_id(request)
                        except Exception:
                            pass
                    # Preserve legacy event names outside the new capture mode.
                    event_type = "login_failed" if effective_status == 401 else (
                        "http_request" if self._security_capture else "http_error"
                    )
                    _monitor.event_fire_and_forget(
                        type=event_type, ip=_get_real_ip(request, self._trusted_proxies),
                        path=request.url.path, status_code=effective_status,
                        user_id=user_id, meta=meta,
                    )
            except Exception:
                # Telemetry failures must not replace application results/errors.
                log.debug("HTTP telemetry could not be queued")
            finally:
                raw.clear()

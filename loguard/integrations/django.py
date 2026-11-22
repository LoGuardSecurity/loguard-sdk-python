"""Sync/async Django middleware with optional bounded HTTP field capture."""

from __future__ import annotations

import logging
from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from time import monotonic

from .._body_stream import ObservedBodyStream
from .._capture import (
    CapturePolicy,
    DEFAULT_STATUSES,
    FORBIDDEN_HEADERS,
    KNOWN_EXPLOIT_HEADERS as KNOWN_EXPLOIT_HEADERS,
    MAX_QUERY_BYTES,
    truncate,
)
from .._ip_utils import _parse_trusted_proxies, _resolve_proxy_chain
from ..monitor import monitor as _monitor

log = logging.getLogger("loguard.django")
_FORBIDDEN_TRACK_HEADERS = FORBIDDEN_HEADERS
_WSGI_NO_PREFIX_HEADERS = frozenset({"content-type", "content-length"})
_MISSING = object()


def _header_to_meta_key(header_name: str) -> str:
    normalized = header_name.strip().lower()
    key = normalized.upper().replace("-", "_")
    return key if normalized in _WSGI_NO_PREFIX_HEADERS else "HTTP_" + key


def _resolve_client_ip(request, trusted_proxy_nets: tuple) -> str:
    return _resolve_proxy_chain(
        request.META.get("REMOTE_ADDR", "unknown"),
        request.META.get("HTTP_X_FORWARDED_FOR", ""),
        trusted_proxy_nets,
    )


def _settings() -> dict:
    try:
        from django.conf import settings

        if not settings.configured:
            return {}
        values = {}
        for name in (
            "TRACK_ALL",
            "TRACK_STATUSES",
            "TRACK_HEADERS",
            "TRUSTED_PROXIES",
            "SECURITY_CAPTURE",
            "MAX_BODY_BYTES",
            "MAX_JSON_DEPTH",
        ):
            current, legacy = f"LOGUARD_{name}", f"LOGGUARD_{name}"
            if hasattr(settings, current):
                values[name] = getattr(settings, current)
            elif hasattr(settings, legacy):
                log.warning("Django setting %s is deprecated; use %s", legacy, current)
                values[name] = getattr(settings, legacy)
        return values
    except ImportError:
        return {}


def _user_id(request):
    # Do not evaluate Django's lazy auth proxy: telemetry must not trigger an
    # additional authentication database query, especially from an async view.
    user = request.__dict__.get("_cached_user")
    if user is None:
        user = request.__dict__.get("_acached_user")
    if user is None:
        user = request.__dict__.get("user")
    if user is None:
        return None
    from django.utils.functional import LazyObject, empty

    if isinstance(user, LazyObject):
        user = object.__getattribute__(user, "_wrapped")
        if user is empty:
            return None
    return str(user.pk) if user.is_authenticated else None


class _RequestBodyCapture:
    def __init__(self, request, policy):
        self.request = request
        self.policy = policy
        self.content_type = request.META.get("CONTENT_TYPE", "")
        self.original = None
        self.observed = None
        if not policy.supports(self.content_type):
            return
        if getattr(request, "_body", _MISSING) is not _MISSING:
            return
        if getattr(request, "_read_started", False):
            return
        original = getattr(request, "_stream", None)
        if original is None:
            return
        expected = None
        value = request.META.get("CONTENT_LENGTH", "")
        try:
            parsed = int(value)
            if parsed >= 0:
                expected = parsed
        except (ValueError, TypeError):
            pass
        self.original = original
        self.observed = ObservedBodyStream(original, policy.max_body_bytes, expected)
        # Django has no public stream-observation hook. Keep this dependency
        # confined to the adapter and verify it against supported releases.
        request._stream = self.observed

    def metadata(self):
        if not self.policy.supports(self.content_type):
            return {"body_unsupported_content_type": True}
        if self.observed is not None:
            if self.observed.failed:
                return {"body_capture_error": True}
            if self.observed.unavailable:
                return {"body_unavailable": True}
            if self.observed.too_large:
                return {"body_too_large": True}
        cached = getattr(self.request, "_body", _MISSING)
        if cached is not _MISSING:
            return self.policy.body(cached, self.content_type)
        if self.observed is not None and self.observed.complete:
            return self.policy.body(self.observed.captured(), self.content_type)
        return {"body_unavailable": True}

    def release(self):
        if self.observed is not None:
            if getattr(self.request, "_stream", None) is self.observed:
                self.request._stream = self.original
            # Django may have replaced _stream with its body cache. Preserve it.
            self.observed.release()


class LoGuardMiddleware:
    """Queue HTTP telemetry without waiting for ingest.

    LOGUARD_SECURITY_CAPTURE opts into bounded query/body capture for all
    statuses. The middleware observes application reads and never pre-reads,
    drains or buffers streaming responses. Sync and async handlers are supported.
    """

    sync_capable = True
    async_capable = True

    def __init__(
        self,
        get_response,
        *,
        track_statuses=None,
        track_all=None,
        track_headers=None,
        trusted_proxies=None,
        security_capture=None,
        max_body_bytes=None,
        max_json_depth=None,
    ):
        self.get_response = get_response
        self._async_mode = iscoroutinefunction(get_response) or iscoroutinefunction(
            getattr(get_response, "__call__", None)
        )
        if self._async_mode:
            markcoroutinefunction(self)
        settings = _settings()

        def select(value, name, default):
            return value if value is not None else settings.get(name, default)

        self._track_all = select(track_all, "TRACK_ALL", False)
        statuses = select(track_statuses, "TRACK_STATUSES", None)
        self._track_statuses = (
            DEFAULT_STATUSES if statuses is None else frozenset(statuses)
        )
        self._security_capture = select(security_capture, "SECURITY_CAPTURE", False)
        self._policy = CapturePolicy(
            max_body_bytes=select(max_body_bytes, "MAX_BODY_BYTES", 32768),
            max_json_depth=select(max_json_depth, "MAX_JSON_DEPTH", 8),
        )
        requested = select(track_headers, "TRACK_HEADERS", ()) or ()
        self._track_headers = tuple(
            dict.fromkeys(
                h.strip().lower()
                for h in requested
                if h.strip().lower() not in FORBIDDEN_HEADERS
            )
        )[:64]
        self._trusted_proxy_nets = _parse_trusted_proxies(
            select(trusted_proxies, "TRUSTED_PROXIES", ())
        )

    def _collect_tracked_headers(self, request) -> dict:
        collected = {}
        for name in self._track_headers:
            value = request.META.get(_header_to_meta_key(name))
            if value:
                collected[name] = truncate(str(value), 512)
        return collected

    def _begin_capture(self, request):
        if not self._security_capture:
            return None
        try:
            return _RequestBodyCapture(request, self._policy)
        except Exception:
            log.debug("HTTP body observation could not be initialized")
            return None

    def _report(self, request, response, failed, capture, started):
        try:
            status = (
                response.status_code
                if response is not None
                else (500 if failed else None)
            )
            if status is None or not (
                self._security_capture
                or self._track_all
                or status in self._track_statuses
            ):
                return
            meta = {
                "method": request.method,
                "duration_ms": round((monotonic() - started) * 1000, 3),
            }
            headers = self._collect_tracked_headers(request)
            if headers:
                meta["headers"] = headers
            if self._security_capture:
                query = request.META.get("QUERY_STRING", "")
                if len(query) > MAX_QUERY_BYTES:
                    meta["query_too_large"] = True
                else:
                    meta.update(
                        self._policy.raw_query(query.encode("utf-8", errors="replace"))
                    )
                meta.update(
                    capture.metadata()
                    if capture is not None
                    else {"body_capture_error": True}
                )
            try:
                user_id = _user_id(request)
            except Exception:
                user_id = None
            _monitor.event_fire_and_forget(
                type="login_failed" if status == 401 else "http_request",
                ip=_resolve_client_ip(request, self._trusted_proxy_nets),
                path=request.path,
                status_code=status,
                user_id=user_id,
                meta=meta,
            )
        except Exception:
            log.debug("HTTP telemetry could not be queued")
        finally:
            if capture is not None:
                try:
                    capture.release()
                except Exception:
                    log.debug("HTTP body observation could not be released")

    def __call__(self, request):
        if self._async_mode:
            return self._acall(request)
        started = monotonic()
        capture = self._begin_capture(request)
        response = None
        failed = False
        try:
            response = self.get_response(request)
            return response
        except Exception:
            failed = True
            raise
        finally:
            self._report(request, response, failed, capture, started)

    async def _acall(self, request):
        started = monotonic()
        capture = self._begin_capture(request)
        response = None
        failed = False
        try:
            response = await self.get_response(request)
            return response
        except Exception:
            failed = True
            raise
        finally:
            self._report(request, response, failed, capture, started)

from __future__ import annotations

import logging
from typing import Callable, Optional, Sequence, Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..monitor import monitor as _monitor
from ..exceptions import LoGuardError, LoGuardNotInitializedError
from .._ip_utils import _get_real_ip

log = logging.getLogger("loguard.fastapi")

# Not exhaustive, just a reasonable starting point. Each of these has shown
# up carrying real exploits at some point: User-Agent and Referer for
# ShellShock (CVE-2014-6271), X-BEResource / X-AnonResource-Backend for the
# ProxyLogon SSRF chain against Exchange (CVE-2021-26855). New techniques
# targeting other headers show up over time, so treat this as a default
# you can extend, not a final list.
KNOWN_EXPLOIT_HEADERS: tuple[str, ...] = (
    "user-agent",
    "referer",
    "x-beresource",
    "x-anonresource-backend",
)

# The docstring above tells people not to put Authorization/Cookie/etc in
# track_headers, but a warning in a docstring only helps if someone reads
# it. This is the actual enforcement — these headers are dropped even if
# explicitly requested, so the SDK can't become a credential-leak vector
# by accident.
_FORBIDDEN_TRACK_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
})


class LoGuardMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware that automatically tracks HTTP errors
    from your application as LoGuard security events.

    Basic setup:
        from fastapi import FastAPI
        from loguard import monitor
        from loguard.integrations.fastapi import LoGuardMiddleware

        app = FastAPI()
        monitor.init(api_key="lg_live_xxx", env="production")

        app.add_middleware(
            LoGuardMiddleware,
            track_statuses={400, 401, 403, 404, 429, 500, 502, 503},
        )

    Forwarding request headers (optional, off by default)

    A handful of severe vulnerabilities — ShellShock, ProxyLogon — only
    show up inside specific HTTP headers, never in the URL path or the
    request body. Out of the box, LoGuard doesn't look at any of your
    request headers beyond what it already needs internally (the
    X-Forwarded-For value, used solely to resolve the visitor's real IP —
    that header's content is never forwarded to LoGuard as data).

    If you'd like LoGuard's detectors to also scan specific headers for
    known exploit patterns, opt in by naming exactly which ones to send:

        from loguard.integrations.fastapi import KNOWN_EXPLOIT_HEADERS

        app.add_middleware(
            LoGuardMiddleware,
            track_headers=KNOWN_EXPLOIT_HEADERS,  # the curated starter set above
            # or pick your own:
            # track_headers=["User-Agent", "Referer", "X-My-Custom-Header"],
        )

    You're always in control of exactly what gets sent. Leaving
    track_headers unset (the default) means nothing is collected — no
    surprises, no implicit data sharing.

    Please never list "Authorization", "Cookie", "X-Api-Key", or any
    header that might carry credentials, session tokens, or personal data.
    LoGuard forwards whatever you name here verbatim — it has no way to
    tell a sensitive header from a harmless one, so that judgment call is
    yours to make.
    """

    def __init__(
        self,
        app,
        *,
        track_statuses: Optional[Set[int]] = None,
        get_user_id: Optional[Callable[[Request], Optional[str]]] = None,
        track_headers: Optional[Sequence[str]] = None,
        trusted_proxies: Optional[Sequence[str]] = None,
    ):
        super().__init__(app)
        self._track_statuses = track_statuses or {400, 401, 403, 404, 429, 500, 502, 503}
        self._get_user_id = get_user_id
        # Normalized once up front so header lookups stay simple below.
        _requested = tuple(h.lower() for h in track_headers) if track_headers else ()
        _blocked = [h for h in _requested if h in _FORBIDDEN_TRACK_HEADERS]
        if _blocked:
            log.warning(
                "LoGuardMiddleware: refusing to track sensitive header(s) %s "
                "even though explicitly requested -- these can carry credentials "
                "and are never forwarded, regardless of configuration.",
                _blocked,
            )
        self._track_headers: tuple[str, ...] = tuple(
            h for h in _requested if h not in _FORBIDDEN_TRACK_HEADERS
        )
        # Empty by default means X-Forwarded-For is never trusted — without
        # naming your reverse proxy's IP here, anyone could spoof their
        # tracked IP just by setting that header themselves.
        self._trusted_proxies: tuple[str, ...] = (
            tuple(trusted_proxies) if trusted_proxies else ()
        )

    def _collect_tracked_headers(self, request: Request) -> dict:
        """
        Returns only the headers you opted into via track_headers — an
        empty dict if you never set it. Each value is truncated defensively
        so a single oversized header can't bloat the payload.
        """
        if not self._track_headers:
            return {}
        collected = {}
        for name in self._track_headers:
            val = request.headers.get(name)
            if val is not None:
                collected[name] = val[:512]
        return collected

    async def dispatch(self, request: Request, call_next) -> Response:
        # Trusted-proxy-aware IP resolution — see _ip_utils.py. Won't trust
        # X-Forwarded-For unless the direct peer is a named trusted proxy,
        # so a visitor can't just spoof whatever IP gets tracked.
        ip = _get_real_ip(request, list(self._trusted_proxies))

        # Let the request through
        response = await call_next(request)

        # Track errors of interest
        if response.status_code in self._track_statuses:
            try:
                user_id = None
                if self._get_user_id:
                    try:
                        user_id = self._get_user_id(request)
                    except Exception:
                        pass

                event_type = "login_failed" if response.status_code == 401 else "http_error"

                meta = {}
                tracked = self._collect_tracked_headers(request)
                if tracked:
                    meta["headers"] = tracked

                await _monitor.aevent(
                    type=event_type,
                    ip=ip,
                    path=request.url.path,
                    status_code=response.status_code,
                    user_id=user_id,
                    meta=meta or None,
                )
            except LoGuardNotInitializedError:
                log.warning("LoGuardMiddleware: monitor not initialized")
            except LoGuardError as e:
                log.debug("LoGuardMiddleware track failed: %r", e)

        return response
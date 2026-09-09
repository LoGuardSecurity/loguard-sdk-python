from __future__ import annotations

import ipaddress
import logging
import threading
from typing import Callable, Optional, Sequence, Set

from ..monitor import monitor as _monitor
from ..exceptions import LoGuardError, LoGuardNotInitializedError

log = logging.getLogger("loguard.django")

# Same header list used by the FastAPI integration below — historically
# real RCE payloads (ShellShock, ProxyLogon) have shown up in exactly these
# headers, not in the URL or body. Not exhaustive, just a sane default.
KNOWN_EXPLOIT_HEADERS: tuple[str, ...] = (
    "user-agent",
    "referer",
    "x-beresource",
    "x-anonresource-backend",
)

# Same list as in fastapi.py. Enforced in code, not just documented,
# because "please don't put Authorization in here" in a docstring isn't
# worth much once someone copy-pastes a header list from Stack Overflow.
_FORBIDDEN_TRACK_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
})


# WSGI (PEP 3333), not a Django quirk: Content-Type and Content-Length are
# the only two headers that DON'T get an HTTP_ prefix in request.META —
# everything else follows the usual HTTP_FOO_BAR pattern. Doesn't affect
# KNOWN_EXPLOIT_HEADERS above (neither header is in that list), but if
# someone adds "content-type" to their own track_headers, this is the
# difference between it working and _collect_tracked_headers() silently
# looking up the wrong META key forever.
_WSGI_NO_PREFIX_HEADERS = frozenset({"content-type", "content-length"})


def _header_to_meta_key(header_name: str) -> str:
    """
    Django exposes incoming headers through request.META using keys like
    HTTP_USER_AGENT — dashes become underscores, everything uppercase, with
    an HTTP_ prefix. This converts "User-Agent" into that lookup key.

    Two WSGI-mandated exceptions (PEP 3333): Content-Type and
    Content-Length have NO "HTTP_" prefix in request.META.
    """
    normalized = header_name.strip().lower()
    if normalized in _WSGI_NO_PREFIX_HEADERS:
        return normalized.upper().replace("-", "_")
    return "HTTP_" + header_name.upper().replace("-", "_")


def _parse_trusted_proxies(value) -> tuple:
    """Same idea as _get_real_ip() in _ip_utils.py (used by the FastAPI
    integration): only trust X-Forwarded-For from an explicit allowlist,
    never unconditionally. This version also accepts CIDR ranges like
    "10.0.0.0/8", not just single IPs."""
    nets = []
    for raw in (value or []):
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                nets.append(ipaddress.ip_network(raw, strict=False))
            else:
                ip = ipaddress.ip_address(raw)
                prefix = 32 if ip.version == 4 else 128
                nets.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        except ValueError:
            log.warning("bad_trusted_proxy_entry entry=%r", raw)
    return tuple(nets)


def _resolve_client_ip(request, trusted_proxy_nets: tuple) -> str:
    """Resolve the real client IP, trusting X-Forwarded-For only if the
    request's REMOTE_ADDR is in trusted_proxy_nets."""
    remote_addr = request.META.get("REMOTE_ADDR", "unknown")
    if trusted_proxy_nets:
        try:
            src = ipaddress.ip_address(remote_addr)
            if any(src in net for net in trusted_proxy_nets):
                xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
                if xff:
                    candidate = xff.split(",")[0].strip()
                    try:
                        ipaddress.ip_address(candidate)
                        return candidate
                    except ValueError:
                        pass
        except ValueError:
            pass
    return remote_addr


class LoGuardMiddleware:
    """
    Django middleware that automatically tracks HTTP requests as LoGuard
    security events.

    Setup in settings.py:
        MIDDLEWARE = [
            "loguard.integrations.django.LoGuardMiddleware",
            ...
        ]

    Optional settings.py configuration:
        LOGUARD_TRACK_ALL      = False       # track every request, not just errors
        LOGUARD_TRACK_STATUSES = {400, 401, 403, 404, 429, 500, 502, 503}
        LOGUARD_TRACK_HEADERS  = None        # see below — off by default
        LOGUARD_TRUSTED_PROXIES = None       # IPs/CIDRs of proxies you control
        # (the old "LOGGUARD_" double-g prefix still works but is deprecated)

    And during app startup (for example in AppConfig.ready()):
        from loguard import monitor
        monitor.init(api_key="lg_live_xxx", env="production")

    Forwarding request headers (optional, off by default)

    A handful of severe vulnerabilities — ShellShock, ProxyLogon — only
    show up inside specific HTTP headers, never in the URL path or the
    request body. Out of the box, LoGuard doesn't look at any of your
    request headers beyond what it already needs internally.

    If you'd like LoGuard's detectors to also scan specific headers for
    known exploit patterns, opt in by naming exactly which ones to send:

        from loguard.integrations.django import KNOWN_EXPLOIT_HEADERS

        # settings.py
        LOGUARD_TRACK_HEADERS = KNOWN_EXPLOIT_HEADERS
        # or pick your own:
        # LOGUARD_TRACK_HEADERS = ["User-Agent", "X-My-Custom-Header"]

    You're always in control of exactly what gets sent. Leaving this unset
    (the default) means nothing is collected — no surprises, no implicit
    data sharing.

    Please never list "Authorization", "Cookie", "X-Api-Key", or any
    header that might carry credentials, session tokens, or personal data.
    LoGuard forwards whatever you name here verbatim — it has no way to
    tell a sensitive header from a harmless one, so that judgment call is
    yours to make.
    """

    def __init__(
        self,
        get_response: Callable,
        *,
        track_statuses: Optional[Set[int]] = None,
        track_all: Optional[bool] = None,
        track_headers: Optional[Sequence[str]] = None,
        trusted_proxies: Optional[Sequence[str]] = None,
    ):
        self.get_response = get_response

        # Fall back to Django settings when these aren't passed explicitly.
        # Settings used to be prefixed "LOGGUARD_" (double g) back when the
        # project was still called that — inconsistent with every other
        # LoGuard env var, which uses "LOGUARD_". We read "LOGUARD_" first
        # and quietly accept "LOGGUARD_" as a deprecated alias so nobody's
        # existing settings.py breaks on upgrade.
        def _setting(name: str, default=None):
            correct = f"LOGUARD_{name}"
            legacy = f"LOGGUARD_{name}"
            if hasattr(_ds, correct):
                return getattr(_ds, correct)
            if hasattr(_ds, legacy):
                log.warning(
                    "Django setting %s is deprecated, use %s instead "
                    "(support for %s will be removed in a future release)",
                    legacy, correct, legacy,
                )
                return getattr(_ds, legacy)
            return default

        try:
            from django.conf import settings as _ds
            _track_all = _setting("TRACK_ALL", False)
            _statuses = _setting("TRACK_STATUSES", None)
            _headers = _setting("TRACK_HEADERS", None)
            _proxies = _setting("TRUSTED_PROXIES", None)
        except Exception:
            _track_all = False
            _statuses = None
            _headers = None
            _proxies = None

        self._track_all      = track_all if track_all is not None else _track_all
        self._track_statuses = track_statuses or _statuses or {
            400, 401, 403, 404, 429, 500, 502, 503
        }

        chosen_headers = track_headers if track_headers is not None else _headers
        _requested = tuple(h.lower() for h in chosen_headers) if chosen_headers else ()
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

        # Secure by default — X-Forwarded-For is never trusted unless
        # trusted_proxies is set explicitly, otherwise we just use REMOTE_ADDR.
        chosen_proxies = trusted_proxies if trusted_proxies is not None else _proxies
        self._trusted_proxy_nets: tuple = _parse_trusted_proxies(chosen_proxies)

    def _collect_tracked_headers(self, request) -> dict:
        """
        Returns only the headers you opted into via track_headers /
        LOGUARD_TRACK_HEADERS — an empty dict if you never configured it.
        Uses the same output shape as the FastAPI integration (lowercase
        header name mapped to a truncated value), so server-side detectors
        don't need to know which framework sent the event.
        """
        if not self._track_headers:
            return {}
        collected = {}
        for name in self._track_headers:
            meta_key = _header_to_meta_key(name)
            val = request.META.get(meta_key)
            if val:
                collected[name] = str(val)[:512]
        return collected

    def __call__(self, request):
        # Used to trust HTTP_X_FORWARDED_FOR unconditionally, which meant
        # any visitor could spoof their own IP. Now goes through the
        # trusted-proxy allowlist above — same approach the FastAPI
        # integration uses in _ip_utils.py.
        ip = _resolve_client_ip(request, self._trusted_proxy_nets)

        # Let the request through
        response = self.get_response(request)

        # Track events of interest
        should_track = (
            self._track_all
            or response.status_code in self._track_statuses
        )

        if should_track:
            user_id = None
            try:
                if getattr(request, "user", None) and request.user.is_authenticated:
                    user_id = str(request.user.pk)
            except Exception:
                pass

            event_type = "login_failed" if response.status_code == 401 else "http_request"

            meta = {
                "method": request.method,
            }
            tracked = self._collect_tracked_headers(request)
            if tracked:
                meta["headers"] = tracked

            # fire_and_forget uses the SDK's internal queue, so this never
            # spins up a new thread per request.
            try:
                _monitor.event_fire_and_forget(
                    type=event_type,
                    ip=ip,
                    path=request.path,
                    status_code=response.status_code,
                    user_id=user_id,
                    meta=meta,
                )
            except LoGuardNotInitializedError:
                log.warning("LoGuardMiddleware: monitor not initialized")
            except LoGuardError as e:
                log.debug("LoGuardMiddleware track failed: %r", e)

        return response
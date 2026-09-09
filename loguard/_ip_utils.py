"""
loguard/_ip_utils.py

Trusted-proxy-aware real-client-IP resolution for the FastAPI/Starlette
integration (loguard/integrations/fastapi.py). Previously this lived
inside shield.py, which made fastapi.py depend on a file that had
nothing to do with IP resolution -- moved out on its own so removing
shield.py (Tor/VPN/phishing verdict middleware, now superseded by the
server-side agent) doesn't take this down with it.

Django's integration (integrations/django.py) has its own, separate,
CIDR-aware implementation (_resolve_client_ip/_parse_trusted_proxies) --
it does NOT use this module, so this file stays Starlette-Request-shaped
only, not genericized for a request type nothing here actually uses.

X-Forwarded-For is attacker-controlled by default — any visitor can set
it to whatever they want in their own request. It's only safe to trust
when the request's direct TCP peer is a proxy you actually control
(named explicitly via trusted_proxies). Skip this check and a visitor
can spoof their IP through the header and walk right past any IP-based
enforcement — rate limiting, per-IP alerting, whatever.

Secure by default: empty/unset trusted_proxies means the header is never
trusted, full stop.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable


def _get_real_ip(request, trusted_proxies: Iterable[str]) -> str:
    """
    Returns the best-effort real client IP for a Starlette/FastAPI
    `request`. Falls back to "127.0.0.1" if request.client is unset
    (e.g. certain test clients / ASGI transports that don't populate it)
    -- matches the original shield.py behavior, not an empty string,
    since downstream code (monitor._build_event) treats an empty ip as
    a validation error.

    trusted_proxies: IPs of proxies YOU control (e.g. your load
    balancer). If the request's DIRECT peer is not in this list,
    X-Forwarded-For is ignored entirely and the direct peer IP is
    returned as-is -- the safe path, and the only path taken when
    trusted_proxies is empty.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    if client_ip in (trusted_proxies or ()):
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            candidate = xff.split(",")[0].strip()
            try:
                # Reject anything that isn't a real parseable IP —
                # an attacker-controlled header value shouldn't flow
                # through unchecked into "the IP" used downstream for
                # alerting or enforcement.
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass

    return client_ip
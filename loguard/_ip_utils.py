"""Resolve client addresses through explicitly trusted proxy chains."""
from __future__ import annotations

import ipaddress
import logging

log = logging.getLogger("loguard")


def _parse_trusted_proxies(values):
    networks = []
    for value in values or ():
        try:
            networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            log.warning("Invalid trusted proxy entry ignored")
    return tuple(networks)


def _resolve_proxy_chain(peer, forwarded, networks):
    try:
        current = ipaddress.ip_address(peer)
        if not networks or not any(current in net for net in networks):
            return peer
        # Bound parsing independently of the web server's header limits.
        if len(forwarded) > 4096 or forwarded.count(',') >= 64:
            return peer
        chain = [ipaddress.ip_address(part.strip()) for part in forwarded.split(',')] if forwarded else []
        for candidate in reversed(chain):
            if not any(current in net for net in networks):
                break
            current = candidate
        return str(current)
    except ValueError:
        return peer


def _get_real_ip(request, trusted_proxies):
    peer = request.client.host if request.client else "127.0.0.1"
    return _resolve_proxy_chain(peer, request.headers.get("x-forwarded-for", ""),
                                _parse_trusted_proxies(trusted_proxies))

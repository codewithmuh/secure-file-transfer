"""The client's address, by the rule of ADR-0002: rate limits and audit records both use it.

A request that comes from our load balancer (an address in `TRUSTED_PROXIES`) has the client's
address in the last `X-Forwarded-For` entry, the one the load balancer appended; entries before it
are whatever the client sent, so they are never read. Any other request's client is its socket
peer. Locally nothing is trusted, and the peer is the client.

For rate limits an IPv6 address stands for its /64, the block one subscriber usually holds
(abuse and rate limits 2.1); the load balancer is IPv4-only in v1, so this only matters later.
"""

from __future__ import annotations

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from starlette.requests import Request

UNKNOWN = "unknown"


def client_address(
    request: Request, trusted: Sequence[IPv4Network | IPv6Network]
) -> IPv4Address | IPv6Address | None:
    peer = _parse(request.client.host if request.client else None)
    if peer is None or not any(peer in network for network in trusted):
        return peer
    forwarded = request.headers.getlist("x-forwarded-for")
    if not forwarded:
        return peer
    return _parse(forwarded[-1].split(",")[-1].strip()) or peer


def rate_limit_ip(request: Request, trusted: Sequence[IPv4Network | IPv6Network]) -> str:
    """The value a per-IP limit counts per: an IPv4 address, or an IPv6 /64."""
    address = client_address(request, trusted)
    if address is None:
        return UNKNOWN
    if isinstance(address, IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ip_network(f"{address}/64", strict=False))
    return str(address)


def _parse(value: str | None) -> IPv4Address | IPv6Address | None:
    if not value:
        return None
    try:
        return ip_address(value)
    except ValueError:
        return None

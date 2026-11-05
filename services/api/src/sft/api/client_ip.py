"""The client's address, by the rule of ADR-0002: rate limits and audit records both use it.

A request that comes from our load balancer (an address in `TRUSTED_PROXIES`) has the client's
address in the last `X-Forwarded-For` entry, the one the load balancer appended; entries before it
are whatever the client sent, so they are never read. Any other request's client is its socket
peer. Locally nothing is trusted, and the peer is the client.

Addresses are read as the load balancer and a dual-stack socket may write them: an IPv4-mapped IPv6
address (`::ffff:203.0.113.9`) is its IPv4 address, for the trusted-proxy check too, and an entry
may carry a port (`203.0.113.9:4321`, `[2001:db8::9]:4321`). A request from the load balancer
without a usable entry keeps the load balancer's own address and logs a warning, without either
address: every client would then share one count, so it means the load balancer is misconfigured.

For rate limits an IPv6 address stands for its /64, the block one subscriber usually holds
(abuse and rate limits 2.1); the load balancer is IPv4-only in v1, so this only matters later.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from starlette.requests import Request

log = logging.getLogger(__name__)

UNKNOWN = "unknown"


def client_address(
    request: Request, trusted: Sequence[IPv4Network | IPv6Network]
) -> IPv4Address | IPv6Address | None:
    peer = _parse(request.client.host if request.client else None)
    if peer is None or not any(peer in network for network in trusted):
        return peer
    forwarded = request.headers.getlist("x-forwarded-for")
    client = _parse(_without_port(forwarded[-1].split(",")[-1].strip())) if forwarded else None
    if client is None:
        reason = "unreadable" if forwarded else "missing"
        log.warning("no usable X-Forwarded-For from a trusted proxy", extra={"reason": reason})
        return peer
    return client


def rate_limit_ip(request: Request, trusted: Sequence[IPv4Network | IPv6Network]) -> str:
    """The value a per-IP limit counts per: an IPv4 address, or an IPv6 /64."""
    address = client_address(request, trusted)
    if address is None:
        return UNKNOWN
    if isinstance(address, IPv6Address):
        return str(ip_network(f"{address}/64", strict=False))
    return str(address)


def _without_port(entry: str) -> str:
    """`a.b.c.d:port` and `[v6]:port` without the port; any other entry as it is."""
    if entry.startswith("["):
        host, bracket, rest = entry[1:].partition("]")
        port = rest.removeprefix(":")
        return host if bracket and (not rest or (port != rest and _is_port(port))) else entry
    host, colon, port = entry.partition(":")
    # One colon is IPv4 with a port; an IPv6 address has at least two.
    return host if colon and ":" not in port and _is_port(port) else entry


def _is_port(value: str) -> bool:
    return value.isascii() and value.isdigit() and int(value) <= 65535


def _parse(value: str | None) -> IPv4Address | IPv6Address | None:
    if not value:
        return None
    try:
        address = ip_address(value)
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address

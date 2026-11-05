"""Rate limits on routes: one line per route (abuse and rate limits 2.2, 2.4).

    @router.post("/v1/auth/sign-in", dependencies=[rate_limit(SIGN_IN_START)])
    @router.get("/v1/me", dependencies=[rate_limit(TENANT_OPERATION, caller=member_session)])

`rate_limit` counts the request against a bundle of `sft.service.rate_limits.limits` before the
handler runs. Each per-IP limit counts per the client's address (`client_ip`); every other key
comes from `caller`, the route's authentication dependency, whose result has `rate_limit_keys()`.
FastAPI runs a dependency once per request, so the handler can depend on `caller` too.

Limits whose key is only known inside the handler (a link's subject, an invited address) use the
limiter there: `await limiter.check(REQUEST_CODE, keys)` with `limiter = Depends(get_rate_limiter)`.

Refusals are `sft.core.errors` exceptions, which `sft.api.errors` answers: `429` with
`Retry-After`, or `503` with `Retry-After: 5` for a fail-closed limit during a store outage.

`CountFailedAuthentications` records every failed authentication against the client's IP (group
H: 100 in 5 minutes block the IP for 15): a `401 credentials_invalid`, which the API answers only
when a credential was presented and no live one has it (an unknown session cookie, a bearer token
it doesn't know). Other `401`s guess nothing, so an office behind one NAT can't block itself with
them: `authentication_required` (no credential sent, as on every signed-out page load),
`session_expired` (a real session that ended) and `reauthentication_required` (a step-up). It
checks the block before the app runs, so a blocked IP gets `429` on every route, before
authentication: a bad credential can't get its `401` back and keep guessing.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from ipaddress import IPv4Network, IPv6Network
from typing import Annotated, Any, Protocol

from fastapi import Depends, FastAPI, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sft.api.client_ip import rate_limit_ip
from sft.api.errors import problem_for
from sft.core.errors import ProblemError
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import (
    EVERY_REQUEST,
    H_FAILED_AUTH,
    KeyType,
    KeyValue,
    Limit,
)

log = logging.getLogger(__name__)


class RateLimitCaller(Protocol):
    """What an authentication dependency returns: the caller's keys for the limits."""

    def rate_limit_keys(self) -> Mapping[KeyType, KeyValue]: ...


def get_rate_limiter(request: Request) -> RateLimiter:
    """The FastAPI dependency for the process's limiter: `Depends(get_rate_limiter)`."""
    limiter = getattr(request.app.state, "rate_limiter", None)
    if not isinstance(limiter, RateLimiter):
        raise RuntimeError("this app was created without settings, so it has no rate limiter")
    return limiter


def _trusted(request: Request) -> Sequence[IPv4Network | IPv6Network]:
    trusted: Sequence[IPv4Network | IPv6Network] = getattr(request.app.state, "trusted_proxies", ())
    return trusted


def client_ip(request: Request) -> str:
    """The value per-IP limits count per, by ADR-0002's rule; worked out once per request."""
    ip = getattr(request.state, "client_ip", None)
    if not isinstance(ip, str):
        ip = request.state.client_ip = rate_limit_ip(request, _trusted(request))
    return ip


def rate_limit(limits: Sequence[Limit], *, caller: Callable[..., Any] | None = None) -> Any:
    """A route dependency that applies `limits`, in order, before the handler."""
    bundle = tuple(limits)

    if caller is None:

        async def by_ip(
            request: Request, limiter: Annotated[RateLimiter, Depends(get_rate_limiter)]
        ) -> None:
            await limiter.check(bundle, {KeyType.IP: client_ip(request)})

        return Depends(by_ip)

    async def by_caller(
        request: Request,
        limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
        # A default, not `Annotated`: the module's postponed annotations can't see `caller`.
        who: RateLimitCaller = Depends(caller),  # noqa: B008
    ) -> None:
        await limiter.check(bundle, {**who.rate_limit_keys(), KeyType.IP: client_ip(request)})

    return Depends(by_caller)


FAILED_AUTHENTICATIONS = frozenset({"credentials_invalid"})
"""The `401` codes that count against `H_FAILED_AUTH`: a credential was presented, and no live one
matches it. Every other `401` sent none, or a real one that has ended or is too old for a
step-up."""


class CountFailedAuthentications:
    """Refuses a blocked IP before the app runs, and records each `401` against the client's IP."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope) if scope["type"] == "http" else None
        limiter = getattr(request.app.state, "rate_limiter", None) if request else None
        if request is None or not isinstance(limiter, RateLimiter):
            await self.app(scope, receive, send)
            return
        ip = client_ip(request)
        # Shared with the request the error handler sees, which notes the problem's code here.
        state: dict[str, Any] = scope.setdefault("state", {})
        try:
            await limiter.check(EVERY_REQUEST, {KeyType.IP: ip})
        except ProblemError as refused:
            await problem_for(refused)(scope, receive, send)
            return
        status = 0

        async def watch(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        await self.app(scope, receive, watch)
        if status == 401 and state.get("problem_code") in FAILED_AUTHENTICATIONS:
            await limiter.record(H_FAILED_AUTH, ip)


def install_rate_limits(app: FastAPI) -> None:
    """Count failed authentications and refuse blocked IPs. The limiter opens with the lifespan."""
    app.add_middleware(CountFailedAuthentications)

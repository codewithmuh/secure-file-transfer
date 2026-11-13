"""`auth_failures_total{scheme}`: every failed authentication, by the credential presented (#260).

A failed authentication is a credential presented that no live one matches (abuse and rate limits
2.2, H), never a missing one, an ended session or a step-up. Each is counted once, by scheme:

- `session`: a `__Host-sft_session` cookie no session ever had (`401 credentials_invalid`);
- `api_key`: a bearer token that is no live API key (`401 credentials_invalid` with a bearer
  challenge and no session cookie);
- `link`: a link token no link has (`404 link_not_found`), a verification code that doesn't
  match (`code_invalid`), or a credential sent with a link session (`401 credentials_invalid` with
  `X-Link-Session`);
- `operator`: an operator token that isn't live, or a token exchange refused
  (`401 credentials_invalid` on the operator API).

The public app counts from the answer: `sft.api.rate_limits.CountFailedAuthentications` sees each
response's problem code and calls `observe`, the place group H already counts a failure. The
operator API counts where its authentication refuses (`sft.api.operator.app`). The counter starts
at zero for every scheme, so a rate alert has a series from the first scrape. OPS documents it and
its alert (docs/operations/metrics.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from fastapi import Request
from prometheus_client import CollectorRegistry, Counter

LINK_HEADER: Final = "x-link-session"
SESSION_COOKIE: Final = "__Host-sft_session"


class Scheme(StrEnum):
    SESSION = "session"
    API_KEY = "api_key"
    OPERATOR = "operator"
    LINK = "link"


_LINK_CODES: Final = frozenset({"link_not_found", "code_invalid"})


def scheme_of(request: Request, status: int, code: object) -> Scheme | None:
    """The scheme a response's failed authentication counts under, or None for any other."""
    if code in _LINK_CODES:
        return Scheme.LINK
    if status != 401 or code != "credentials_invalid":
        return None
    headers = request.headers
    if LINK_HEADER in headers:
        return Scheme.LINK
    if headers.get("authorization") is not None and not request.cookies.get(SESSION_COOKIE):
        return Scheme.API_KEY
    return Scheme.SESSION


@dataclass(frozen=True, slots=True)
class AuthFailures:
    counter: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> AuthFailures:
        counter = Counter(
            "auth_failures_total",
            "Failed authentications: a credential presented that no live one matches, by scheme "
            "(session, api_key, operator, link).",
            ["scheme"],
            registry=registry,
        )
        for scheme in Scheme:
            counter.labels(scheme=scheme.value)
        return cls(counter)

    def count(self, scheme: Scheme) -> None:
        self.counter.labels(scheme=scheme.value).inc()

    def observe(self, request: Request, status: int, code: object) -> None:
        """Count a response of the public app, if it is a failed authentication."""
        scheme = scheme_of(request, status, code)
        if scheme is not None:
            self.count(scheme)


def of(request: Request) -> AuthFailures | None:
    """The app's counter; None for an app created without settings, as in most tests."""
    found = getattr(request.app.state, "auth_failures", None)
    return found if isinstance(found, AuthFailures) else None

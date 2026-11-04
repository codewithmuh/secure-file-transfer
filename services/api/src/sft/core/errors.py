"""Errors that become Problem responses (docs/api/README.md section 3).

Any layer may raise them; only `sft.api.errors` knows their HTTP status. This is the seam issue #96
builds: the classes and signatures here match its `sft.core.errors`, and at merge its module
replaces this one.
"""

from __future__ import annotations


class ProblemError(Exception):
    """An error the API answers with a Problem document. `code` is the contract's stable code."""

    code: str = "internal_error"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.code)
        self.detail = detail


class RateLimited(ProblemError):  # noqa: N818 - the name #96 gives it
    """`429 rate_limited`, with `Retry-After` in whole seconds, at least 1."""

    code = "rate_limited"

    def __init__(self, retry_after: int, detail: str | None = None) -> None:
        super().__init__(detail)
        self.retry_after = max(1, retry_after)


class ServiceUnavailable(ProblemError):  # noqa: N818 - the name #96 gives it
    """`503 service_unavailable`, with `Retry-After` in whole seconds, at least 1."""

    code = "service_unavailable"

    def __init__(self, retry_after: int, detail: str | None = None) -> None:
        super().__init__(detail)
        self.retry_after = max(1, retry_after)

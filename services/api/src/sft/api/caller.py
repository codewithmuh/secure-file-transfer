"""The caller of a request, for `Depends(get_caller)` (authn and authz 6.1, point 1).

`get_caller` is a placeholder until member sessions land (#113), whose module replaces it: it
resolves the session cookie into a `Caller` and answers 401 itself when there is none. Until then
no request carries a credential this service accepts, so every route that needs a caller answers
`401 authentication_required`. Tests override the dependency.

`get_tenant_caller` is the caller of the tenant API, a member session or an API key: what its
routes' rate limits count per (abuse and rate limits 2.2, H). Any other credential is one those
routes don't read, so it is `401` too, before a limit runs, as `authorize` would answer it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from sft.core.errors import Unauthenticated
from sft.service.caller import Caller, CallerKind


async def get_caller() -> Caller:
    """The request's caller; 401 when it carries no credential the API accepts."""
    raise Unauthenticated("authentication_required")


async def get_tenant_caller(caller: Annotated[Caller, Depends(get_caller)]) -> Caller:
    """A member session or an API key of a tenant; 401 for any other caller."""
    if caller.kind not in (CallerKind.MEMBER, CallerKind.API_KEY) or caller.tenant_id is None:
        raise Unauthenticated("authentication_required")
    return caller

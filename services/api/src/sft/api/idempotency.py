"""The `Idempotency-Key` header, for every creating operation the contract gives it (#144).

A route takes `IdempotencyDep` and passes it to its service function, which runs its work through
`sft.service.idempotency.once`. The dependency declares the contract's header, so the generated
OpenAPI document shows it, and returns the key with the request's fingerprint: the method, the
path with its resource IDs, and the body (architecture 5.4). FastAPI has read the body by then, so
reading it here costs nothing.

A route answers with the status `once` returns (`Outcome.status`), so a replay has the first
request's status, and builds its `Location` from the resource, as the first answer did.
"""

from __future__ import annotations

from typing import Annotated, Final

from fastapi import Depends, Header, Request

from sft.service.idempotency import IdempotentRequest, fingerprint

KEY_PATTERN: Final = r"^[\x21-\x7E]+$"


async def idempotency_key(
    request: Request,
    key: Annotated[
        str | None,
        Header(alias="Idempotency-Key", min_length=1, max_length=255, pattern=KEY_PATTERN),
    ] = None,
) -> IdempotentRequest | None:
    """The request's key and fingerprint, or None without the header."""
    if key is None:
        return None
    return IdempotentRequest(
        key, fingerprint(request.method, request.url.path, await request.body())
    )


IdempotencyDep = Annotated[IdempotentRequest | None, Depends(idempotency_key)]

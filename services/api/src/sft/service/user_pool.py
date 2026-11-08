"""The user pool's admin side, as the notification worker uses it (authn and authz 2.5; #197).

A local member signs in through the user pool (ADR-0016). The worker creates their pool user when
they are invited, with our user ID as the username, the address marked verified, the tenant in
`custom:tenant_id` and a temporary password the worker makes, which the pool makes them replace at
the first sign-in; it records the identity `(pool connection, sub)` from the pool's answer, then
emails the invitation. A sign-in reset deletes the pool user and creates it again the same way.

Only the notification worker holds pool admin credentials; the API never does (2.5). `UserPool` is
the port: `sft.runtime.keycloak.KeycloakUserPool` locally, where Keycloak stands in for Cognito;
Cognito's own adapter arrives with #193 (M4). Without a pool the worker records invitations and
sends nothing, as before.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final, Literal, Protocol
from uuid import UUID

INVITATION_ENROLMENT: Final = "invitation"
"""The enrolment a first invitation's pool user is made for; a sign-in reset's is the reset's ID."""

TEMPORARY_PASSWORD_DAYS: Final = 3
"""How long a temporary password works, in Cognito (authn and authz 2.1); the invitation says so.
Keycloak's never expire on their own, a difference of the local stand-in."""


def new_temporary_password() -> str:
    """24 characters from the operating system's generator (144 bits): within the pool's password
    policy (15 to 99 characters) and the email catalog's rule for a temporary password."""
    return secrets.token_urlsafe(18)


class UserPoolError(Exception):
    """The pool couldn't be reached or refused the call; the message is delivered again."""


class PoolUserExistsError(UserPoolError):
    """Another user of the pool has this address: another tenant's local member, since an address
    holds one local sign-in (2.5). A user with this username is ours, from an earlier delivery, and
    is no conflict: `create_user` takes it over."""

    def __init__(self, kind: Literal["email"] = "email") -> None:
        super().__init__(f"the pool has another user with this {kind}")
        self.kind = kind


@dataclass(frozen=True, slots=True)
class PoolUser:
    subject: str
    enrolment: str | None
    """What the worker made the user for: `invitation`, or a sign-in reset's ID."""


class UserPool(Protocol):
    """The calls the notification worker makes on the pool."""

    provider_name: str
    """The pool's `idp_connections.provider_name`, whose connection the identity names."""

    async def find_user(self, *, username: str) -> PoolUser | None:
        """The user with this username, if any."""
        ...

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        tenant_id: UUID,
        temporary_password: str,
        enrolment: str,
    ) -> str:
        """Create the user with a temporary password, made for `enrolment`; its subject (`sub`).
        A user with this username already (an earlier delivery's) gets the password and the
        enrolment instead: idempotent. `PoolUserExistsError` if another user has the address."""
        ...

    async def delete_user(self, *, username: str) -> bool:
        """Delete the user, if there is one; whether there was."""
        ...

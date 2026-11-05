"""Who is calling: the `Caller` every service function takes (authn and authz 6.1, ADR-0002).

The API resolves a credential into a `Caller` (a FastAPI dependency, `sft.api.caller`), and workers
build one for their named system actor. A `Caller` says who the caller is and how they signed in;
it decides nothing. The service layer checks it against the permission registry
(`sft.service.permissions`) before it acts.

The role is the user's role as read from `users` on this request, never one copied into a session
(authn and authz 3.2). Whether that role acts as an admin depends on how the session signed in
(3.3): a local admin needs a passkey, an SSO admin has their identity provider's assurance.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import UUID

from sft.data.audit import Actor
from sft.data.models import ActorType, Role
from sft.data.scope import Subject
from sft.service.rate_limits.limits import KeyType, KeyValue

STEP_UP_WINDOW: Final = timedelta(minutes=15)
"""How recent a sign-in a step-up operation needs (authn and authz 3.3)."""


class CallerKind(StrEnum):
    """The caller types of authn and authz 1."""

    MEMBER = "member"
    """A member or admin with a web session."""
    API_KEY = "api_key"
    RECIPIENT = "recipient"
    UPLOADER = "uploader"
    OPERATOR = "operator"
    SYSTEM = "system"


class AuthMethod(StrEnum):
    """How a member session signed in, from the ID token's `amr` (authn and authz 3.2, 3.3)."""

    PASSKEY = "passkey"
    PASSWORD_TOTP = "password_totp"  # noqa: S105 - a sign-in method, not a password
    LOCAL = "local"
    """Cognito reported no method."""
    SSO = "sso"


ADMIN_METHODS: Final = frozenset({AuthMethod.PASSKEY, AuthMethod.SSO})
"""The sign-ins in which a local or SSO admin acts as an admin while the passkey rule is on."""


@dataclass(frozen=True, slots=True)
class Caller:
    """The resolved caller of one request or job. Build one with the class methods."""

    kind: CallerKind
    tenant_id: UUID | None = None
    user_id: UUID | None = None
    """The member, or an API key's owner."""
    role: Role | None = None
    """The user's role, read from `users` on this request."""
    auth_method: AuthMethod | None = None
    auth_time: datetime | None = None
    """When the session's sign-in happened, for step-up."""
    credential_id: UUID | None = None
    """The member session, API key, link session or operator session the request carried."""
    scopes: frozenset[str] = field(default_factory=frozenset)
    """An API key's scopes, such as `transfers:read`."""
    subject: Subject | None = None
    """A link session's recipient or upload request."""
    passkey_rule: bool = True
    """The launch-gated rule of authn and authz 3.3, from the API's settings."""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CallerKind):
            raise TypeError("kind must be a CallerKind")
        if self.role is not None:
            object.__setattr__(self, "role", Role(self.role))

    @classmethod
    def member(
        cls,
        *,
        tenant_id: UUID,
        user_id: UUID,
        role: Role,
        auth_method: AuthMethod,
        auth_time: datetime,
        session_id: UUID,
        passkey_rule: bool = True,
    ) -> Caller:
        """A member session's caller (authn and authz 3)."""
        return cls(
            CallerKind.MEMBER,
            tenant_id=tenant_id,
            user_id=user_id,
            role=role,
            auth_method=auth_method,
            auth_time=auth_time,
            credential_id=session_id,
            passkey_rule=passkey_rule,
        )

    @property
    def is_admin(self) -> bool:
        """The user holds the admin role, whatever the session's sign-in."""
        return self.role is Role.ADMIN

    @property
    def acts_as_admin(self) -> bool:
        """The session may use the admin role: an admin signed in with a passkey or SSO, or any
        admin while the passkey rule is off (authn and authz 3.3)."""
        if not self.is_admin or self.kind is not CallerKind.MEMBER:
            return False
        return not self.passkey_rule or self.auth_method in ADMIN_METHODS

    def signed_in_since(self, now: datetime, window: timedelta = STEP_UP_WINDOW) -> bool:
        """The session's sign-in is recent enough for a step-up operation."""
        return self.auth_time is not None and now - self.auth_time <= window

    def rate_limit_keys(self) -> Mapping[KeyType, KeyValue]:
        """What the caller's rate limits count per (abuse and rate limits 2.1), for `rate_limit`.

        A member counts per account, an API key per key, both with their tenant; an operator per
        operator session; a link session per itself, with no tenant, since recipients and
        uploaders don't use their tenant's budget (2.2, H). The system has no limits.
        """
        keys: dict[KeyType, KeyValue] = {}
        if self.kind is CallerKind.MEMBER and self.user_id is not None:
            keys[KeyType.ACCOUNT] = str(self.user_id)
        elif self.kind is CallerKind.API_KEY and self.credential_id is not None:
            keys[KeyType.API_KEY] = str(self.credential_id)
        elif self.kind is CallerKind.OPERATOR and self.credential_id is not None:
            keys[KeyType.OPERATOR] = str(self.credential_id)
        elif self.kind in (CallerKind.RECIPIENT, CallerKind.UPLOADER) and self.credential_id:
            keys[KeyType.LINK_SESSION] = str(self.credential_id)
        if self.kind in (CallerKind.MEMBER, CallerKind.API_KEY) and self.tenant_id is not None:
            keys[KeyType.TENANT] = str(self.tenant_id)
        return keys

    def actor(self) -> Actor:
        """The audit actor: an admin acting as one, a member, a key, a link session, an operator."""
        if self.kind is CallerKind.MEMBER:
            kind = ActorType.ADMIN if self.acts_as_admin else ActorType.MEMBER
            return Actor(kind, self.user_id)
        if self.kind is CallerKind.SYSTEM:
            return Actor(ActorType.SYSTEM)
        if self.kind in (CallerKind.RECIPIENT, CallerKind.UPLOADER):
            kind = ActorType(self.kind.value)
            return Actor(kind, self.subject.id if self.subject else self.credential_id)
        # An API key is its key's ID, an operator their operator session's.
        return Actor(ActorType(self.kind.value), self.credential_id)

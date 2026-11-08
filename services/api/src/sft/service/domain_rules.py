"""Recipient domain rules: the tenant's allowed and blocked domains (#217; FR-24, FR-45, T-17;
data model 2.1).

**A rule** is a domain in its ASCII form, lower-case: an internationalised domain is stored as its
IDNA A-label (`xn--…`, Python's IDNA 2003 codec, so a U-label and its A-label are one rule), and a
trailing dot is dropped. A rule covers the domain and every subdomain: `example.com` covers
`a@example.com` and `a@mail.example.com`, never `a@badexample.com`. Each list holds at most 500
rules. `normalize_rules` refuses a malformed one with `422 validation_failed` and a pointer to it.

**The decision** (`DomainRules.allows`): a blocked domain is refused; then, if the allowed list
isn't empty, any address outside it is refused; otherwise every domain is allowed. Blocked wins
over allowed.

**Where it applies** (FR-45: first, at creation and again at send):

- `createTransfer` and `sendTransfer` (`sft.service.transfers`, `sft.service.sending`), against
  the policy as it is at that moment, so a domain blocked after a draft was made is refused at
  send.
- `createUploadRequest` (#212): `await domain_rules.check_addresses(session, [uploader_email],
  pointer=lambda _: json_pointer("uploader_email"))`, in its transaction, before the request is
  made.

A refusal is `422 recipient_domain_not_allowed`, pointing at the first address refused. The
answer names the address's place, never which list refused it.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import FieldError, Unprocessable, json_pointer
from sft.data import tenants

MAX_RULES: Final = 500
"""Each list's most domains (the contract's `TenantPolicy`)."""
MAX_DOMAIN: Final = 253
_LABEL: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class DomainError(ValueError):
    """Not a domain a rule can name."""


def normalize_domain(value: str) -> str:
    """`value` as a rule: lower-case, ASCII (IDNA), without a trailing dot. Raises
    `DomainError` for anything that isn't a domain of at least two labels."""
    candidate = value.strip().rstrip(".")
    if not candidate or any(c.isspace() for c in candidate):
        raise DomainError("a domain is one word, without spaces")
    try:
        ascii_form = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DomainError("not a valid internationalised domain") from exc
    labels = ascii_form.split(".")
    if len(ascii_form) > MAX_DOMAIN or len(labels) < 2:
        raise DomainError("a domain has at least two labels and at most 253 characters")
    if not all(_LABEL.fullmatch(label) for label in labels):
        raise DomainError("a label is 1 to 63 letters, digits or hyphens, not at either end")
    return ascii_form


def domain_of(address: str) -> str | None:
    """The domain of an email address, as a rule would name it; None if it has none."""
    _, at, domain = address.rpartition("@")
    if not at:
        return None
    try:
        return normalize_domain(domain)
    except DomainError:
        return None


def normalize_rules(values: Sequence[str], field: str) -> tuple[str, ...]:
    """A list of rules as `updateTenantPolicy` takes it: each normalised, at most 500, no two
    alike after normalising. Raises `422 validation_failed` pointing at the first bad one."""
    if len(values) > MAX_RULES:
        raise _invalid(json_pointer(field), f"{field} holds at most {MAX_RULES} domains.")
    seen: dict[str, int] = {}
    for index, value in enumerate(values):
        try:
            rule = normalize_domain(value)
        except DomainError:
            raise _invalid(
                json_pointer(field, index), "Not a domain, such as example.com."
            ) from None
        if rule in seen:
            raise _invalid(json_pointer(field, index), "This domain is in the list already.")
        seen[rule] = index
    return tuple(seen)


def _invalid(pointer: str, detail: str) -> Unprocessable:
    return Unprocessable("validation_failed", detail, errors=[FieldError(detail, pointer=pointer)])


def _covers(rule: str, domain: str) -> bool:
    return domain == rule or domain.endswith("." + rule)


@dataclass(frozen=True, slots=True)
class DomainRules:
    """The tenant's allowed and blocked domains (module docstring)."""

    allowed: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()

    @classmethod
    def of(cls, policy: tenants.Policy) -> DomainRules:
        return cls(tuple(policy.allowed_domains), tuple(policy.blocked_domains))

    def allows(self, address: str) -> bool:
        domain = domain_of(address)
        if domain is None:
            return False
        if any(_covers(rule, domain) for rule in self.blocked):
            return False
        return not self.allowed or any(_covers(rule, domain) for rule in self.allowed)

    def first_refused(self, addresses: Sequence[str]) -> int | None:
        """The index of the first address the rules refuse, or None."""
        if not self.allowed and not self.blocked:
            return None
        return next((i for i, a in enumerate(addresses) if not self.allows(a)), None)


def not_allowed(pointer: str) -> Unprocessable:
    """`422 recipient_domain_not_allowed`, pointing at the address (FR-24)."""
    detail = "The tenant's policy doesn't allow this address's domain."
    return Unprocessable(
        "recipient_domain_not_allowed", detail, errors=[FieldError(detail, pointer=pointer)]
    )


def check(rules: DomainRules, addresses: Sequence[str], pointer: Callable[[int], str]) -> None:
    """Raise `recipient_domain_not_allowed` for the first address `rules` refuse."""
    refused = rules.first_refused(addresses)
    if refused is not None:
        raise not_allowed(pointer(refused))


async def check_addresses(
    session: AsyncSession, addresses: Sequence[str], *, pointer: Callable[[int], str]
) -> None:
    """Check `addresses` against the scope's tenant's rules as they are now, in `session`'s
    transaction; raise `422 recipient_domain_not_allowed` for the first one refused. The one call
    each operation that names a recipient or uploader makes (module docstring)."""
    check(DomainRules.of(await tenants.get_policy(session)), addresses, pointer)

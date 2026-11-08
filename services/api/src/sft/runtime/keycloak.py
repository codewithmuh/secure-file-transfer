"""Keycloak's admin REST API as the user pool, in the local stack (`sft.service.user_pool`; #197).

Keycloak stands in for the Cognito user pool locally (ADR-0016, docs/local-development.md 4). The
notification worker signs in to it as the confidential client `sft-notify-local`, whose service
account may only manage the realm's users, with the client credentials grant, and calls the admin
API in-network (`http://oidc:8080`). Cognito's adapter (`AdminCreateUser`, `AdminDeleteUser`)
replaces it with #193 in M4.

A temporary password goes to Keycloak with `temporary: true`, so the first sign-in makes the member
choose their own, as Cognito's does. It is never logged; neither is the client secret. Each user
carries the enrolment the worker made it for (the `enrolment_id` attribute, declared in the
realm's user profile), so a redelivery can tell its own user from an older one.

**Conflicts are looked up, not parsed.** Keycloak answers `409` for a username or an address in use,
with a message meant for people. The adapter asks which: a user with this username is ours, from
an earlier delivery, and gets this delivery's password and enrolment (idempotent); otherwise a user
with this address belongs to someone else (`PoolUserExistsError`).
"""

from __future__ import annotations

import time
from typing import Any, Final
from urllib.parse import quote
from uuid import UUID

import httpx2 as httpx

from sft.service.user_pool import PoolUser, PoolUserExistsError, UserPoolError

TIMEOUT: Final = httpx.Timeout(5.0)
TOKEN_MARGIN_SECONDS: Final = 30
ENROLMENT: Final = "enrolment_id"


class KeycloakUserPool:
    def __init__(
        self,
        *,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        provider_name: str,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.provider_name = provider_name
        self._base = base_url.rstrip("/")
        self._realm = quote(realm, safe="")
        self._client = (client_id, client_secret)
        self._http = http or httpx.AsyncClient(timeout=TIMEOUT)
        self._token: tuple[str, float] | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _access_token(self) -> str:
        if self._token is not None and self._token[1] > time.monotonic():
            return self._token[0]
        try:
            response = await self._http.post(
                f"{self._base}/realms/{self._realm}/protocol/openid-connect/token",
                data={"grant_type": "client_credentials"},
                auth=self._client,
            )
        except httpx.HTTPError as exc:
            raise UserPoolError("the user pool can't be reached") from exc
        if response.status_code != httpx.codes.OK:
            raise UserPoolError(
                f"the user pool refused the worker's sign-in ({response.status_code})"
            )
        body = response.json()
        lifetime = float(body.get("expires_in", 60)) - TOKEN_MARGIN_SECONDS
        self._token = (str(body["access_token"]), time.monotonic() + max(lifetime, 0.0))
        return self._token[0]

    async def _call(
        self, method: str, path: str, *, json: Any = None, params: dict[str, str] | None = None
    ) -> httpx.Response:
        url = f"{self._base}/admin/realms/{self._realm}{path}"
        for attempt in (1, 2):
            token = await self._access_token()
            try:
                response = await self._http.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError as exc:
                raise UserPoolError("the user pool can't be reached") from exc
            if response.status_code == httpx.codes.UNAUTHORIZED and attempt == 1:
                self._token = None  # expired early: sign in again once
                continue
            return response
        raise UserPoolError("the user pool refused the worker")  # pragma: no cover - loop returns

    async def _users(self, **query: str) -> list[dict[str, Any]]:
        response = await self._call("GET", "/users", params={**query, "exact": "true"})
        if response.status_code != httpx.codes.OK:
            raise UserPoolError(f"the user pool couldn't find a user ({response.status_code})")
        found: list[dict[str, Any]] = response.json()
        return found

    async def find_user(self, *, username: str) -> PoolUser | None:
        found = [
            u for u in await self._users(username=username) if u.get("username") == username.lower()
        ]
        if not found:
            return None
        enrolment = (found[0].get("attributes") or {}).get(ENROLMENT) or [None]
        return PoolUser(str(found[0]["id"]), enrolment[0])

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        tenant_id: UUID,
        temporary_password: str,
        enrolment: str,
    ) -> str:
        attributes = {"tenant_id": [str(tenant_id)], ENROLMENT: [enrolment]}
        response = await self._call(
            "POST",
            "/users",
            json={
                "username": username,
                "email": email,
                "emailVerified": True,
                "enabled": True,
                "attributes": attributes,
                "credentials": [
                    {"type": "password", "value": temporary_password, "temporary": True}
                ],
            },
        )
        if response.status_code == httpx.codes.CONFLICT:
            return await self._take_over(username, email, attributes, temporary_password)
        if response.status_code != httpx.codes.CREATED:
            raise UserPoolError(f"the user pool didn't create the user ({response.status_code})")
        location = response.headers.get("Location", "")
        subject = location.rstrip("/").rsplit("/", 1)[-1]
        if not subject:
            raise UserPoolError("the user pool didn't say which user it created")
        return subject

    async def _take_over(
        self, username: str, email: str, attributes: dict[str, list[str]], password: str
    ) -> str:
        """After a `409`: our own user from an earlier delivery gets this delivery's password and
        enrolment; another user with the address is a conflict."""
        mine = await self.find_user(username=username)
        if mine is None:
            if await self._users(email=email):
                raise PoolUserExistsError("email")
            raise UserPoolError("the user pool refused the user, and has no such user")
        subject = quote(mine.subject, safe="")
        updated = await self._call("PUT", f"/users/{subject}", json={"attributes": attributes})
        if updated.status_code != httpx.codes.NO_CONTENT:
            raise UserPoolError(f"the user pool didn't update the user ({updated.status_code})")
        await self._set_password(mine.subject, password)
        return mine.subject

    async def _set_password(self, subject: str, password: str) -> None:
        response = await self._call(
            "PUT",
            f"/users/{quote(subject, safe='')}/reset-password",
            json={"type": "password", "value": password, "temporary": True},
        )
        if response.status_code != httpx.codes.NO_CONTENT:
            raise UserPoolError(f"the user pool didn't set the password ({response.status_code})")

    async def delete_user(self, *, username: str) -> bool:
        found = await self.find_user(username=username)
        if found is None:
            return False
        response = await self._call("DELETE", f"/users/{quote(found.subject, safe='')}")
        if response.status_code not in (httpx.codes.NO_CONTENT, httpx.codes.NOT_FOUND):
            raise UserPoolError(f"the user pool didn't delete the user ({response.status_code})")
        return response.status_code == httpx.codes.NO_CONTENT

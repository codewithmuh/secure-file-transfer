"""Cognito's admin API as the user pool, in AWS (`sft.service.user_pool`; #193, ADR-0016).

The notification worker's own role calls `AdminCreateUser`, `AdminGetUser`,
`AdminUpdateUserAttributes`, `AdminSetUserPassword` and `AdminDeleteUser` on its region's pool,
and nothing else (authn and authz 2.5): the API and operator API roles have no Cognito
permissions. The calls leave through the egress proxy's notifier listener (ADR-0021).

- **Our email, not Cognito's.** `AdminCreateUser` runs with `MessageAction=SUPPRESS`, so Cognito
  sends nothing; the worker emails the catalog's `member_invitation` in the tenant's language with
  the temporary password it made (`sft.service.notifications`).
- **Our user ID is the username**; the address is a verified `email` alias, so the member signs in
  with it. `custom:tenant_id` (immutable) and `custom:enrolment_id` are declared in the pool's
  schema (infra/modules/user-pool). The temporary password expires after
  `TEMPORARY_PASSWORD_DAYS`, the pool's setting.
- **Conflicts by their error code.** `UsernameExistsException` is our own user from an earlier
  delivery: it gets this delivery's enrolment and password (`AdminSetUserPassword` with
  `Permanent=False`, so the first sign-in still replaces it). `AliasExistsException` is another
  user with the address, another tenant's local member (`PoolUserExistsError`):
  `ForceAliasCreation` stays off, so the alias is never moved from them.

boto3 is synchronous, so each call runs in this adapter's small thread pool, as the SQS adapter's do
(`sft.workers.queues`). The password and the address are never logged, and an error names only
AWS's error code.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Final
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sft.core.telemetry import trace_aws_client
from sft.service.user_pool import PoolUser, PoolUserExistsError, UserPoolError

if TYPE_CHECKING:
    from types_boto3_cognito_idp.client import CognitoIdentityProviderClient
    from types_boto3_cognito_idp.type_defs import AttributeTypeTypeDef

TENANT: Final = "custom:tenant_id"
ENROLMENT: Final = "custom:enrolment_id"


def _code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", "ClientError"))


class CognitoUserPool:
    def __init__(
        self,
        client: CognitoIdentityProviderClient,
        *,
        user_pool_id: str,
        provider_name: str,
        threads: int = 2,
    ) -> None:
        self.provider_name = provider_name
        self._client = client
        self._pool = user_pool_id
        self._executor = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="cognito")

    @classmethod
    def create(
        cls, *, region: str, user_pool_id: str, provider_name: str, threads: int = 2
    ) -> CognitoUserPool:
        """A client for this region's pool. Credentials come from the pod's IAM role."""
        config = Config(
            region_name=region,
            connect_timeout=2,
            read_timeout=5,
            retries={"mode": "standard", "max_attempts": 3},
            max_pool_connections=threads,
        )
        client = boto3.session.Session().client("cognito-idp", config=config)
        trace_aws_client(client)
        return cls(client, user_pool_id=user_pool_id, provider_name=provider_name, threads=threads)

    async def aclose(self) -> None:
        await asyncio.to_thread(self._executor.shutdown, wait=True)

    async def _call[T](self, fn: Callable[..., T], /, **kwargs: object) -> T:
        """`fn` in the thread pool; a `ClientError` passes through for the caller to read, any
        other failure of the SDK is a `UserPoolError`."""
        loop = asyncio.get_running_loop()
        call = functools.partial(contextvars.copy_context().run, fn, **kwargs)
        try:
            return await loop.run_in_executor(self._executor, call)
        except BotoCoreError as exc:
            raise UserPoolError(f"the user pool can't be reached ({type(exc).__name__})") from None

    async def find_user(self, *, username: str) -> PoolUser | None:
        try:
            found = await self._call(
                self._client.admin_get_user, UserPoolId=self._pool, Username=username
            )
        except ClientError as exc:
            if _code(exc) == "UserNotFoundException":
                return None
            raise UserPoolError(f"the user pool couldn't find a user ({_code(exc)})") from None
        attributes = {a["Name"]: a.get("Value", "") for a in found.get("UserAttributes", [])}
        if not attributes.get("sub"):
            raise UserPoolError("the user pool's user has no subject")
        return PoolUser(attributes["sub"], attributes.get(ENROLMENT) or None)

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        tenant_id: UUID,
        temporary_password: str,
        enrolment: str,
    ) -> str:
        attributes: list[AttributeTypeTypeDef] = [
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
            {"Name": TENANT, "Value": str(tenant_id)},
            {"Name": ENROLMENT, "Value": enrolment},
        ]
        try:
            created = await self._call(
                self._client.admin_create_user,
                UserPoolId=self._pool,
                Username=username,
                UserAttributes=attributes,
                TemporaryPassword=temporary_password,
                MessageAction="SUPPRESS",
                ForceAliasCreation=False,
            )
        except ClientError as exc:
            code = _code(exc)
            if code == "AliasExistsException":
                raise PoolUserExistsError("email") from None
            if code == "UsernameExistsException":
                return await self._take_over(username, enrolment, temporary_password)
            raise UserPoolError(f"the user pool didn't create the user ({code})") from None
        user_attributes = created.get("User", {}).get("Attributes", [])
        subject = next((a.get("Value") for a in user_attributes if a["Name"] == "sub"), None)
        if subject:
            return subject
        mine = await self.find_user(username=username)  # the answer should name it; look it up
        if mine is None:
            raise UserPoolError("the user pool didn't say which user it created")
        return mine.subject

    async def _take_over(self, username: str, enrolment: str, password: str) -> str:
        """Our own user from an earlier delivery: this delivery's enrolment and password."""
        mine = await self.find_user(username=username)
        if mine is None:
            raise UserPoolError("the user pool refused the user, and has no such user")
        try:
            await self._call(
                self._client.admin_update_user_attributes,
                UserPoolId=self._pool,
                Username=username,
                UserAttributes=[{"Name": ENROLMENT, "Value": enrolment}],
            )
            await self._call(
                self._client.admin_set_user_password,
                UserPoolId=self._pool,
                Username=username,
                Password=password,
                Permanent=False,
            )
        except ClientError as exc:
            raise UserPoolError(f"the user pool didn't update the user ({_code(exc)})") from None
        return mine.subject

    async def delete_user(self, *, username: str) -> bool:
        try:
            await self._call(
                self._client.admin_delete_user, UserPoolId=self._pool, Username=username
            )
        except ClientError as exc:
            if _code(exc) == "UserNotFoundException":
                return False
            raise UserPoolError(f"the user pool didn't delete the user ({_code(exc)})") from None
        return True

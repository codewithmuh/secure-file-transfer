"""FastAPI dependencies for what the app's lifespan opens, so routes needn't import the app.

`get_database` is the process's `Database`, and `get_email_keyring` its `email-hmac` keyring, which
per-address rate limits count under. `get_objects` is the files buckets' object store and
`get_upload_policy` what the settings decide about uploads (#114). The rate limiter's dependency,
`get_rate_limiter`, lives with the limits in rate_limits.py. All need an app created with settings.
"""

from __future__ import annotations

from fastapi import Request

from sft.core.pseudonyms import EmailKeyring
from sft.data.database import Database
from sft.service.objects import ObjectStore
from sft.service.uploads import UploadPolicy


def get_database(request: Request) -> Database:
    """The FastAPI dependency for the process's database: `Depends(get_database)`."""
    database = getattr(request.app.state, "database", None)
    if not isinstance(database, Database):
        raise RuntimeError("this app was created without settings, so it has no database")
    return database


def get_email_keyring(request: Request) -> EmailKeyring:
    """The FastAPI dependency for the `email-hmac` keyring: `Depends(get_email_keyring)`."""
    keyring = getattr(request.app.state, "email_keyring", None)
    if not isinstance(keyring, EmailKeyring):
        raise RuntimeError("this app was created without settings, so it has no email keyring")
    return keyring


def get_objects(request: Request) -> ObjectStore:
    """The FastAPI dependency for the files buckets: `Depends(get_objects)`."""
    objects: ObjectStore | None = getattr(request.app.state, "objects", None)
    if objects is None:
        raise RuntimeError("this app was created without settings, so it has no object store")
    return objects


def get_upload_policy(request: Request) -> UploadPolicy:
    """The FastAPI dependency for the upload policy: `Depends(get_upload_policy)`."""
    policy = getattr(request.app.state, "upload_policy", None)
    if not isinstance(policy, UploadPolicy):
        raise RuntimeError("this app was created without settings, so it has no upload policy")
    return policy

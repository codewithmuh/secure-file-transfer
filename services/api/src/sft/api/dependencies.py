"""FastAPI dependencies for what the app's lifespan opens, so routes needn't import the app.

`get_database` is the process's `Database`, and `get_email_keyring` its `email-hmac` keyring, which
per-address rate limits count under. The rate limiter's dependency, `get_rate_limiter`, lives with
the limits in rate_limits.py. All need an app created with settings.
"""

from __future__ import annotations

from fastapi import Request

from sft.core.pseudonyms import EmailKeyring
from sft.data.database import Database


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

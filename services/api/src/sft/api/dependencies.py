"""FastAPI dependencies for what the app's lifespan opens, so routes needn't import the app.

`get_database` is the process's `Database`. The rate limiter's dependency, `get_rate_limiter`,
lives with the limits in rate_limits.py. Both need an app created with settings.
"""

from __future__ import annotations

from fastapi import Request

from sft.data.database import Database


def get_database(request: Request) -> Database:
    """The FastAPI dependency for the process's database: `Depends(get_database)`."""
    database = getattr(request.app.state, "database", None)
    if not isinstance(database, Database):
        raise RuntimeError("this app was created without settings, so it has no database")
    return database

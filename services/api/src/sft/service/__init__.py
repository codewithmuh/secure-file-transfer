"""Service layer: the business rules and the permission checks (ADR-0002).

Every service function takes the caller, or a named system actor for a worker or a job, and checks
the permission itself, so HTTP routes and workers go through the same checks. A state change writes
its audit record (architecture 5.2) and its outbox rows (5.3) in the same transaction.

It may import `sft.data` and `sft.core`, never `sft.api`, and never FastAPI, Starlette or uvicorn:
the workers run it on asyncio without HTTP (enforced by `lint-imports`).
"""

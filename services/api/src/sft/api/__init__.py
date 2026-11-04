"""API layer: the HTTP side of the service, with FastAPI and uvicorn (ADR-0002).

Routes, the FastAPI dependencies that work out who the caller is (member session, link session,
API key or operator), and the runtime contract of architecture 8: probes, metrics, request logs and
graceful shutdown. Permission checks and business rules are not here: a route resolves the caller
and calls `sft.service`.

It may import `sft.service`, `sft.data` and `sft.core`; nothing imports it (enforced by
`lint-imports`). Run it with `python -m sft.api`.
"""

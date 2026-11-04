"""secure-file-transfer backend: one codebase for the API service and the workers (ADR-0002).

Layers, from the top; a layer imports only the layers below it (`lint-imports` checks this):

- `sft.api`: FastAPI routes, and the dependencies that work out who the caller is. The workers,
  when they arrive, sit beside it as `sft.workers`.
- `sft.service`: business rules and permission checks.
- `sft.data`: data access with SQLAlchemy.
- `sft.core`: settings and logging, shared by every layer.
"""

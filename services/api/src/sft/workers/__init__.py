"""Workers: asyncio processes that use the service layer without HTTP (ADR-0002).

Each worker is an entry point in the same image as the API, started with `python -m`:

- `relay`: the outbox relay, `python -m sft.workers.relay` (ADR-0013).

The building blocks for the workers to come:

- `process`: `WorkerProcess`, the pod side of every worker: probes and metrics on the internal port,
  SIGTERM, and the drain (architecture 8).
- `queues`: SQS behind a thin adapter, boto3 in a thread pool of its own.
- `consumer`: `Consumer`, the idempotent consumer base class, and `ConsumerLoop`.

It sits beside `sft.api`: neither imports the other (enforced by `lint-imports`).
"""

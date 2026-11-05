"""Core: the building blocks every layer shares: settings, logging, traces (`telemetry`), the errors
that become Problem responses (`errors`) and email pseudonyms (`pseudonyms`).

The lowest layer. It imports nothing from `sft.api`, `sft.service` or `sft.data`, and nothing from
FastAPI, Starlette or uvicorn, so the workers can use it without HTTP (ADR-0002, enforced by
`lint-imports`).
"""

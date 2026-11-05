"""The operator API (FR-34): its own app and entry point, `python -m sft.api.operator`.

It sits in the `api` layer beside the public app and shares its runtime (`sft.api.server`): the
same two listeners, probes, metrics, logs and shutdown (architecture 8). `app.py` holds the routes,
`schemas.py` the bodies, `sts.py` the STS adapter.
"""

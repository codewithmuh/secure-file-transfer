"""Runtime: what every entry point needs to run as a pod (architecture 8), shared by the API and
the workers.

- `internal`: the internal listener, `/healthz`, `/readyz` and `/metrics` on their own port, and a
  uvicorn server that leaves signals to its entry point.
- `s3`: the files buckets behind `sft.service.objects.ObjectStore`, for the API's uploads now and
  the scan worker later (#114).

It sits below `sft.api` and `sft.workers`, which may not import each other, and above
`sft.service`: only entry points use it, so the service, data and core layers stay free of HTTP
(enforced by `lint-imports`).
"""

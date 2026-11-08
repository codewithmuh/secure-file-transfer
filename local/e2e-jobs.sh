#!/usr/bin/env bash
# Runs the lifecycle jobs the browser journey asks for (#200), on the host, for `make web-e2e`: the Playwright
# container has no Docker. The journey writes `<id>.request` into the folder given, holding "<job> <offset seconds>"
# (web/e2e/support/stack.ts, runJob); this runs that job against the local stack with the clock's test hook moved on,
# as `make jobs` does with CLOCK_OFFSET_SECONDS (#181, #182), and answers `<id>.done` or `<id>.failed` with its output.
# Only the jobs the journey needs, and a whole number of seconds, are accepted. It stops when `make web-e2e` ends.
set -euo pipefail

dir=${1:?usage: e2e-jobs.sh <folder>}
cd "$(dirname "$0")/.."

# The jobs image once, here, not on every job: `make up` builds only the services it starts, and the jobs service has
# its own tag of the API image (Makefile, `jobs`). The build is cached, so it is quick when the image is current.
docker compose --profile jobs build --quiet jobs >&2 || echo "e2e-jobs: building the jobs image failed" >&2

while [[ -d $dir ]]; do
  for request in "$dir"/*.request; do
    [[ -e $request ]] || continue
    name=${request%.request}
    job="" offset=""
    read -r job offset <"$request" || true
    rm -f "$request"
    if [[ ! $job =~ ^(expiry|deletion)$ || ! $offset =~ ^[0-9]{1,7}$ ]]; then
      echo "refused: only the expiry and deletion jobs, with an offset in seconds" >"$name.failed"
      continue
    fi
    if docker compose --profile jobs run --rm --no-deps -T -e "CLOCK_OFFSET_SECONDS=$offset" jobs "$job" \
      >"$name.log" 2>&1; then
      mv "$name.log" "$name.done"
    else
      mv "$name.log" "$name.failed"
    fi
  done
  sleep 1
done

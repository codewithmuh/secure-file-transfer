#!/usr/bin/env bash
# Renders the admission policies with tests/values.yaml and runs the Kyverno CLI test against them, from the pinned
# CLI image (the same Kyverno version as the cluster's, images.tf). Needs helm and Docker; reaches no cluster.
#
# Usage: infra/modules/cluster-bootstrap/charts/kyverno-policies/tests/run.sh
set -euo pipefail

KYVERNO_CLI_IMAGE="reg.kyverno.io/kyverno/kyverno-cli:v1.19.2@sha256:322ec5044d600930cb3af0e56dc33154a2d1d1fba58f4cadad3f47be7e78b11c"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../../.." && pwd)"
chart=infra/modules/cluster-bootstrap/charts/kyverno-policies
cd "$repo"

rendered=$(mktemp -d)
trap 'rm -rf "$rendered"' EXIT
# The signature policy needs a registry to verify against, so it isn't rendered here.
helm template sft-policies "$chart" --values "$chart/tests/values.yaml" \
  --show-only templates/images.yaml --show-only templates/pod-security.yaml \
  --show-only templates/system-pool.yaml --show-only templates/namespaces.yaml >"$rendered/policies.yaml"

docker run --rm --network none --user "$(id -u):$(id -g)" --env HOME=/tmp \
  --volume "$repo:/repo:ro" --volume "$rendered:/policies:ro" --workdir "/repo/$chart/tests" "$KYVERNO_CLI_IMAGE" test . --detailed-results

#!/usr/bin/env bash
# Checks that the vendored Prometheus Operator CRDs are the pinned kube-prometheus-stack chart's, byte for byte (#264):
# it reads the chart's repository and version from infra/modules/cluster-bootstrap/images.tf, which Terraform installs
# the operator from, pulls that chart, and compares its CRD bundle (charts/crds/files/crds.bz2) with
# deploy/observability/crds/kube-prometheus-stack-<version>.crds.bz2, the bundle the upgrade procedure applies
# (docs/operations/observability.md, section 11). It fails when the chart is bumped without the bundle, when an old
# bundle is left behind, and when the bundle differs from the chart's. deploy/check.sh runs it, so CI's deploy job does.
#
# Usage: deploy/observability/crds/check.sh [IMAGES_TF]   (default: cluster-bootstrap's images.tf; needs helm and the
# network)
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
dir="$root/deploy/observability/crds"
images="${1:-$root/infra/modules/cluster-bootstrap/images.tf}"

pinned() { sed -n '/kube_prometheus_stack = {/,/}/p' "$images" | sed -n "s/^ *$1 *= \"\\([^\"]*\\)\".*/\\1/p"; }
repository="$(pinned repository)"
version="$(pinned version)"
if [[ -z $repository || -z $version ]]; then
  echo "FAIL no kube_prometheus_stack repository and version in $images" >&2
  exit 1
fi

bundle="kube-prometheus-stack-$version.crds.bz2"
found="$(find "$dir" -maxdepth 1 -name '*.crds.bz2' -exec basename {} \; | sort)"
if [[ $found != "$bundle" ]]; then
  echo "FAIL $dir holds [${found//$'\n'/ }], expected only $bundle for the pinned chart $version." >&2
  echo "     Vendor its CRDs as section 11 of docs/operations/observability.md says." >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
helm pull kube-prometheus-stack --repo "$repository" --version "$version" --destination "$work"
tar -xzf "$work/kube-prometheus-stack-$version.tgz" -C "$work" \
  kube-prometheus-stack/charts/crds/files/crds.bz2
if ! cmp -s "$work/kube-prometheus-stack/charts/crds/files/crds.bz2" "$dir/$bundle"; then
  echo "FAIL $bundle is not the CRD bundle of kube-prometheus-stack $version from $repository." >&2
  exit 1
fi
echo "ok   $bundle is the pinned chart's CRD bundle (kube-prometheus-stack $version)"

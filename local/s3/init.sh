#!/bin/sh
# One-shot seed for the local S3 stand-in (ADR-0012), run by the s3-init service on every `make up`; safe to repeat.
# Creates the buckets with versioning on, and Object Lock on the audit archive with dev's governance-mode default.
# S3Mock doesn't check signatures, so plain curl is enough. Local only.
set -eu

S3="${S3_URL:-http://s3:9090}"
NS='xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
LOCATION="<CreateBucketConfiguration $NS><LocationConstraint>ap-northeast-1</LocationConstraint></CreateBucketConfiguration>"

# put <path> <body> [header]: PUT and fail loudly on anything but 200 (or 409 when the bucket already exists).
put() {
  if [ -n "${3:-}" ]; then
    code=$(curl -sS -o /tmp/s3-init.out -w '%{http_code}' -X PUT -H "$3" --data "$2" "$S3/$1")
  else
    code=$(curl -sS -o /tmp/s3-init.out -w '%{http_code}' -X PUT --data "$2" "$S3/$1")
  fi
  case "$code" in
    200) ;;
    409) grep -q BucketAlreadyOwnedByYou /tmp/s3-init.out || { cat /tmp/s3-init.out; exit 1; } ;;
    *) echo "PUT $1 returned $code"; cat /tmp/s3-init.out; exit 1 ;;
  esac
}

for bucket in sft-local-files sft-local-large-files; do
  put "$bucket" "$LOCATION"
  put "$bucket?versioning" "<VersioningConfiguration $NS><Status>Enabled</Status></VersioningConfiguration>"
  echo "s3-init: $bucket ready (versioning on)"
done

# The audit archive, and a second one standing in for Osaka's (#177): security-critical records go to both.
for bucket in sft-local-audit-archive sft-local-audit-archive-osaka; do
  put "$bucket" "$LOCATION" "x-amz-bucket-object-lock-enabled: true"
  put "$bucket?versioning" "<VersioningConfiguration $NS><Status>Enabled</Status></VersioningConfiguration>"
  put "$bucket?object-lock" "<ObjectLockConfiguration $NS><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>"
  echo "s3-init: $bucket ready (versioning on, Object Lock governance 1 day)"
done

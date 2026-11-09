# Field keys: decrypt mismatches, KMS failures, and the field key job

| | |
|---|---|
| Alerts | `FieldDecryptScopeMismatch`, `FieldKeysUnavailable` ([`deploy/alerts/field-encryption.rules.yaml`](../../deploy/alerts/field-encryption.rules.yaml)) |
| Design | [Encryption and key management](../security/encryption-and-keys.md) 3.2, 3.3, 7.2; [data model](../design/data-model.md) 2.1, 2.7, 6 |
| Code | `sft.service.fields`, `sft.service.field_keys`, `sft.workers.field_keys`, `sft.runtime.kms` |
| Issues | [#236](https://github.com/codewithmuh/secure-file-transfer/issues/236), [#233](https://github.com/codewithmuh/secure-file-transfer/issues/233) |

File names, messages, justifications, approvers' comments, DLP finding details and detector definitions are stored
only as AES-256-GCM ciphertext under per-tenant data keys, which KMS wraps under the fields key. Nothing on this page
needs, or shows, a value or a key. Everything AWS-specific here is **pending the AWS run**.

## `FieldDecryptScopeMismatch`: a value didn't open with the caller's tenant's key

**What it means.** The API or the scan worker read a sealed value, in a tenant's scope, that its key didn't
authenticate: a row of another tenant reached a result (a scoping bug that got past the data layer and row-level
security), a value copied to another row or column, or one changed in the database. Treat it as a possible isolation
breach (NFR-12) until shown otherwise. The caller got a 500; no value was returned.

**Confirm.** The error log line `a sealed value didn't open with the caller's tenant's key` names the tenant, the
column, the row and the key version, by ID. Check whether the row's `tenant_id` is the logged tenant
(`SELECT tenant_id FROM <table> WHERE id = <row>` under break-glass): another tenant's row is the breach case; the same
tenant's row points at tampering or a bug in sealing.

**Mitigate.** For a breach, follow the incident process: find the request (its `request_id` is on the log line), the
route and the query, and fix the scoping. Field encryption did its job: nothing was disclosed. For tampering, compare
with the audit trail and the database's pgaudit log.

## `FieldKeysUnavailable`: KMS refuses or fails data key calls

**What it means.** For 10 minutes, KMS calls for data keys failed: names and messages can't be shown and new ones
can't be written; scans can't record DLP details. The log line `KMS refused a data key call` carries KMS's error code.

**Confirm and mitigate.** `AccessDeniedException`: the fields key's policy or the role's policy changed (check
CloudTrail `PutKeyPolicy` and IAM changes; the key-admin role restores a policy, encryption and keys 4.4). A
`KMSInvalidStateException`: the key is disabled or pending deletion, which pages on its own; cancel it. Throttling: KMS
request quotas; unwrapped keys are cached 15 minutes, so a sustained rate means many tenants at once. Unreachable: the
KMS VPC endpoint (ADR-0021).

## The field key job

`python -m sft.workers.field_keys <step>...`, as the API (its service account, IAM role and `sft_api`). The chart's
`field-keys` CronJob runs `rotate,backfill,purge` daily in Tokyo. Every step reads the stored state first, so running
one again is safe. Its report is one JSON log line of counts; its audit events are `fields.resealed`,
`data_key.rotated`, `data_key.rewrapped` and `data_key.deleted`.

- **After the first deploy of #236 (the backfill).** Run it once by hand, then check that
  `field_plaintext_reads_total` stays at zero:

      kubectl -n sft create job --from=cronjob/field-keys field-keys-backfill-1

  Locally: `make field-keys STEP=backfill`.
- **Suspected exposure of a tenant's data key.** Rotate early and reseal: run the job with `FIELD_KEY_MAX_AGE_DAYS`
  low enough (as below; the job rotates every tenant whose live version is older), and its own `backfill` and `purge`
  move every row to the new version and delete the old one. Without the override, the yearly rotation applies.
- **After a change of the fields key's material** (a manual `RotateKeyOnDemand`, or moving to a new key): run
  `rewrap`, which wraps every stored data key again with `ReEncrypt`; no value changes. `kubectl create job --from`
  can't change the steps, so render the job, set `FIELD_KEY_STEPS` to `rewrap`, and apply it:

      kubectl -n sft create job --from=cronjob/field-keys field-keys-rewrap-1 --dry-run=client -o yaml \
        | yq '(.spec.template.spec.containers[0].env[] | select(.name == "FIELD_KEY_STEPS")).value = "rewrap"' \
        | kubectl apply -f -

  The same way, `FIELD_KEY_MAX_AGE_DAYS` (an extra variable, at least 30) rotates early for a suspected exposure.

A failed run exits 1 and logs `field key job failed`; the next run is the retry.

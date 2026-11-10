# Runbook: KeyringKeyTooOld

The keyring age alert of encryption and keys 6 and 6.5 (#260), defined in
[`deploy/alerts/platform.rules.yaml`](../../deploy/alerts/platform.rules.yaml). Severity: ticket. The `keyring` label
names the keyring as the pods call it (`email`, `code`, `CSRF`, `link`), as for
[keyring-refresh.md](keyring-refresh.md).

## Symptoms

A keyring's active key is older than its rotation period plus 7 days, for an hour
(`keyring_active_key_age_seconds{keyring}`, from each process that loads the keyring):

| Keyring | Period | Fires above |
|---|---|---|
| `code-hmac`, `link-hmac`, `csrf-hmac` | 90 days | 97 days |
| `email-hmac` | 1 year | 372 days |

The key rotation job (`sft.workers.key_rotation`, hourly, Tokyo only) takes one step of 6.5 per keyring a run: stage,
then activate 15 minutes later, then retire after the overlap. A key this old means it hasn't staged or activated a new
one.

## Impact

None at once: the old key still works, and nothing a pod makes with it fails. The risk is the reason for rotating: a
key that leaked keeps working for longer (encryption 6.5). It is a security hygiene ticket, not an outage.

## Confirm

```bash
kubectl -n sft get cronjob key-rotation                      # Tokyo only; suspended in the pilot light and the hold
kubectl -n sft get jobs -l app.kubernetes.io/component=key-rotation --sort-by=.status.startTime | tail -5
kubectl -n sft logs job/<its last run>
```

The job logs each step per keyring, never a key. In Grafana, `keyring_active_key_age_seconds` by `keyring` and pod:
every pod showing the same old key points at the job; one pod alone at a pod that stopped re-reading
([keyring-refresh.md](keyring-refresh.md)).

## Mitigate

1. **The job is suspended** (Tokyo in the pilot light after a failover, or held): it runs again with the workers. After
   a long failover, its first runs catch up one step at a time.
2. **The job fails:** its log names the step and Secrets Manager's or KMS's error code. A refused `PutSecretValue` is
   its IAM role or the secret's resource policy (infra `modules/app-secrets`, encryption 6.4); fix it there, through a
   reviewed change.
3. **`email-hmac` stays old on purpose** when no rotation was due: its year counts from `activated_at`. Its old key
   leaves the keyring only when no suppression row uses it, an operator's step (encryption 6.5), which doesn't hold the
   new key back.
4. Run the job once by hand when it is fixed: `kubectl -n sft create job --from=cronjob/key-rotation key-rotation-now`.

## Escalate

A keyring past twice its period, or a suspected leak of a key: escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS), and rotate at once by running the job's steps by hand.

## Afterwards

Record why the job stopped rotating, and whether the alert came soon enough.

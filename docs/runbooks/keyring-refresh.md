# Runbook: KeyringRefreshFailing

The keyring alert of encryption and keys 6.4 and 6.5 (#184), defined in
[`deploy/alerts/platform.rules.yaml`](../../deploy/alerts/platform.rules.yaml). Severity: ticket. The `keyring` label
names the keyring as the pods call it: `email`, `code` or `CSRF` (the API), `link`, `code` or `email` (the
notification worker).

## Symptoms

Pods have failed to re-read the keyring from Secrets Manager for 15 minutes
(`sft_keyring_refresh_failures_total{keyring}`). Each pod logs `keyring refresh failed; the loaded version stays`, with
the keyring's name and a reason, never a value (`sft.runtime.secrets`).

## Impact

None yet. A failed read keeps the version the pod already holds, so codes, links, CSRF tokens and email pseudonyms keep
working. The risk is the next rotation step: the key rotation job waits three refresh intervals between staging a key
and activating it (6.5). If a pod still can't read when a key it lacks becomes active, it fails closed on values made
with that key. Pods that restart meanwhile refuse to start without their keyrings.

## Confirm

```bash
kubectl -n sft logs deploy/api --since=30m | grep 'keyring refresh failed'
kubectl -n sft logs deploy/notifier --since=30m | grep 'keyring refresh failed'
```

In Grafana: `sft_keyring_refreshed_timestamp_seconds{keyring}` by pod (when each last read it), and the failures by
pod. All pods failing points at the secret, its key or the endpoint; one pod points at that pod or its node.

With the `ReadOnly` profile (pending the AWS run): the secret `sft/<env>/app/<name>-hmac` exists and has a current
version (`aws secretsmanager describe-secret --secret-id sft/<env>/app/<name>-hmac`). `ReadOnly` may not read its
value, and doesn't need to.

## Mitigate

1. **AccessDenied:** the workload role (`sft-<env>-api`, `sft-<env>-notify`) or the secrets key policy changed;
   compare with `infra/modules/eks-cluster/workload-roles.tf` and `infra/modules/kms-keys`, and revert the change.
2. **Malformed version** (the reason says the keyring didn't parse): the key rotation job wrote something the pods
   refuse. Look at its last runs: `kubectl -n sft logs job/<the last key-rotation job>`. A version the pods refuse is
   never used, so nothing is broken; fix the job and let its next hourly run write a good version. Don't edit the
   secret by hand: only the job writes it (6.4).
3. **The endpoint is unreachable:** the Secrets Manager VPC endpoint or its policy (architecture 3.1); one in
   `infra/modules/network`.
4. **If a step must wait** until the pods can read again: the chart has no switch to suspend the `key-rotation` CronJob
   on its own (only `pilotLight` suspends it), so the change is a reviewed commit to its template or schedule. Usually
   unnecessary: the job takes one step an hour, and a pod that missed a staged key fails closed only once that key is
   active and used.
5. For the field data keys, a different mechanism, see [field-keys.md](field-keys.md).

## Escalate

If it lasts past the next rotation step, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the cause, and whether a rotation step was delayed.

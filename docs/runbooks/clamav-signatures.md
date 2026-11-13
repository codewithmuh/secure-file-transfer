# Runbook: ClamavSignaturesStale

The signature age alert of threat model T-27 (ADR-0019; #260), defined in
[`deploy/alerts/scanning.rules.yaml`](../../deploy/alerts/scanning.rules.yaml). Severity: ticket.

## Symptoms

A node's clamd has scanned with ClamAV signatures more than 24 hours old for 30 minutes
(`clamav_signature_age_seconds`). Each scan worker asks the clamd beside it for its `VERSION` every 5 minutes and
exports the age of the daily database it runs, from the database's build time; a clamd that stops answering keeps its
last build time, so the age keeps growing.

## Impact

Files are still scanned and nothing unscanned is shared, but malware whose signatures were published since isn't
caught (T-27, R-04). The signatures reach clamd through the private signature mirror (capacity 3.3): `freshclam` in the
`signature-mirror` pod fetches ClamAV's database through its egress proxy listener and tests each one; the clamd pods
fetch from the mirror.

## Confirm

```bash
kubectl -n sft get deploy signature-mirror
kubectl -n sft logs deploy/signature-mirror -c freshclam --since=24h | tail -50
kubectl -n sft logs -l app.kubernetes.io/component=clamd --since=6h | grep -iE 'database|reload' | tail -20
kubectl -n sft logs -l app.kubernetes.io/component=scan-worker --since=1h | grep "signature version unknown"
```

In Grafana, `clamav_signature_age_seconds` by pod: every node old points at the mirror or ClamAV's own servers; one node
at its clamd.

## Mitigate

1. **The mirror can't fetch:** its proxy listener (`signature-mirror`, 3130, [egress-proxy.md](egress-proxy.md)), or
   ClamAV's servers refusing or rate-limiting the mirror (`freshclam` logs a cooldown). A cooldown ends by itself; a
   proxy problem is the egress proxy's runbook.
2. **A database failed the mirror's test** (freshclam loads each one before serving it): the mirror keeps serving the
   last good one, which is right; it moves on with the next published database.
3. **One clamd is behind:** it didn't reload. Restart that clamd pod; the scan worker beside it retries its scans
   (FR-19), and the node's trio comes back together.
4. **clamd isn't answering at all:** `ScanFailed` pages too; follow [scan-failed.md](scan-failed.md).

## Escalate

Signatures more than 3 days old, or a mirror that can't fetch for a day: escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Record how old the signatures got and which files were scanned meanwhile (the scan results' times), in case a sample
published in that window is reported later.

# Runbook: bring an environment up or down

A procedure, not an alert. Once an environment's one-time setup is done, one command builds it and one command
destroys everything it bills for. Each runs [the environment workflow](../../.github/workflows/environment.yml) on
`main`, as the environment's Terraform deploy role (#295; NFR-19, NFR-20):

```bash
make aws-up ENV=dev       # build: up to 2 hours (NFR-19)
make aws-down ENV=dev     # destroy what it bills for; asks you to type the name
make aws-status ENV=dev   # what it still has: each stack's state and every tagged resource, read-only
```

Each command starts the run and follows it in the terminal, and the run's page shows each job. prod's runs wait for
your approval in GitHub, as its environment's reviewer. The timed log of each `up` and `down` is kept as an artifact
of the run for 90 days.

> [!IMPORTANT]
> **Pending the AWS run.** Every step passes its dry run (`ops/test.sh`), and nothing has been applied yet.

## Why a workflow and not your shell

Only the environment's deploy role may create or delete the environment's IAM roles (SCP `OnlyDeployRolesChangeIam`).
Only it and BreakGlass are cluster admins (ADR-0004). The role trusts only this repository's GitHub environment of the
same name, which accepts `main` alone (T-71). So `Admin`, from a laptop, can't finish a build or a teardown, and
nothing here needs AWS credentials on your machine. The one exception is the bootstrap: those stacks are `Admin`'s
alone (SCP `OnlyAdminChangesBootstrapIam`).

## What each command does

| Command | Jobs, in order | Takes |
|---|---|---|
| `aws-up` | `foundation` ([`ops/rebuild.sh`](../../ops/rebuild.sh) `--stage foundation`: network, data, then network again for its flow log, Tokyo then Osaka), then `platform` (`--stage platform`: cluster, edge and identity). Each is its own job, with its own 2-hour deploy session. Then `cluster-bootstrap` for each cluster ([cluster-bootstrap-apply.yml](../../.github/workflows/cluster-bootstrap-apply.yml)), then `after` (the alarms, the key rotation's first run, and Argo CD's Applications synced and healthy) | ≤ 2 h |
| `aws-down` | dev and staging: [`ops/teardown.sh`](../../ops/teardown.sh) `--scope idle --part layers`, which drains each cluster and destroys `cluster-bootstrap` through the tunnel, gives `data` its teardown apply, destroys every stack, then searches by tag for anything left. prod: first `--part retained` as the retained stack's own role (GitHub environment `prod-retained`), then `--scope final --part layers` | ≤ 1 h |
| `aws-status` | `ops/teardown.sh --inventory`. The log is public: it shows each stack's resource addresses and every tagged resource's ARN, with the account ID masked. The IDs in them aren't secrets (they appear in DNS and in the web app's config), but keep them out of other places | minutes |

A rebuild is safe to run again on a live environment, so a failed `up` is fixed and then run again. It refuses a plan
that destroys or replaces anything: on a live environment that means drift, or a change that needs its own review.
The workflow has no override. Either make the change a reviewed one, or run `down` and then `up`.
(`ops/rebuild.sh --allow-destroy` exists for a dry run's view.)

What `down` leaves, and what still bills afterwards:

- **dev and staging:** the bootstrap stacks (state bucket, tfstate key and key-admin role, about $2 a month), so `up`
  builds them again. The data goes with the environment: Aurora takes no final snapshot, and the user pool, files
  and queues are new on the next `up`.
- **prod:** the retained stack (the audit archive, under $7 a month, NFR-19) and the bootstrap stacks. Destroying
  the bootstrap stacks is the last step of [teardown.md](teardown.md), done by hand as `Admin`.
- **always:** the organization, the shared account's registry and DNS zone (about $8 a month), and the budgets.

## One-time setup, before the first `aws-up`

1. [organization-and-bootstrap.md](organization-and-bootstrap.md): the GitHub environments, the organization,
   Identity Center, and each account's bootstrap stacks. Some of it is console steps.
2. `infra/shared`: the registry and the `sft.<domain>` zone. Then add the zone's 4 name servers as NS records for
   `sft` at your domain's DNS host.
3. An image: a push to `main` builds one (`build.yml`), and merging its pull request pins dev to it. The sign-in
   triggers run that digest, so `up` refuses while the values pin none.
4. SES production access, requested per account and Region in the console a day ahead (ADR-0015). It stays with the
   account through every `down` and `up`.
5. In prod only, the `retained` stack, once, before prod's first `up` ([apply-staging-and-prod.md](apply-staging-and-prod.md)).
   No `down` destroys it.
6. The inputs below. Then add the environment to `LIVE_ENVIRONMENTS`.

### Inputs

| Name | Kind | Where | Value |
|---|---|---|---|
| `LIVE_ENVIRONMENTS` | variable | repository | The environments that exist, space-separated: `dev`, then `dev staging prod` |
| `SHARED_ACCOUNT_ID`, `SFT_DOMAIN` | variables | repository | The shared account, and your domain (the zone is `sft.<domain>`) |
| `AWS_ACCOUNT_ID` | variable | each GitHub environment: `dev`, `staging`, `prod`, `prod-retained` | That environment's account (prod's in `prod-retained`) |
| `ALERT_EMAILS` | secret | `dev`, `staging`, `prod`, `prod-retained` | A JSON list: `["you@example.com"]` |
| `DMARC_REPORT_ADDRESS` | secret | `dev`, `staging`, `prod` | The mailbox for DMARC reports |
| `BUDGET_EMAIL` | secret | `prod-retained` | Who the retained stack's budget emails |
| `TF_VAR_IDENTITY_CENTER_SAML`, `TF_VAR_GITHUB_APP`, `TF_VAR_BREAK_GLASS_RECONCILIATION` | variables, optional | each environment | As in cluster-bootstrap-apply.yml |

## After each `aws-up`

- **Confirm the alert subscriptions.** Every address in `ALERT_EMAILS` gets an email from AWS per alert topic. Until
  someone clicks its link, the alarms reach nobody. The run's log lists this under "Left for the operator".
- **Check that it works:** [apply-staging-and-prod.md](apply-staging-and-prod.md) section 4. Argo CD is checked
  already; the alarms and the probe are what's left.

## If something fails

- **`up` fails in `foundation` or `platform`:** the log names the stack and prints Terraform's error lines. Fix it in a pull request,
  merge, and run `make aws-up` again: the stacks already built show no changes.
- **`up` fails in `cluster-bootstrap`:** the same, and a rerun applies only that layer onward. It can also be run on
  its own: `gh workflow run cluster-bootstrap.yml -f environment=dev`.
- **`down` fails halfway:** run it again. Each destroy picks up from what's left, and `make aws-status` shows what
  that is. If a stack refuses (a non-empty bucket, an ENI left by a deleted pod), [teardown.md](teardown.md) has the
  manual step for it.
- **Billing after a `down`:** `make aws-status` lists every resource still tagged with the environment. Cost Explorer
  by the `environment` tag shows the rest the next day.
- **"Error acquiring the state lock":** a job stopped mid-apply (its timeout, or a cancel) and left the stack's lock file. First make sure no other run is applying that stack (the Actions tab). Then, with BreakGlass, run `terraform -chdir=infra/<root> force-unlock <lock ID from the error>`, and run the command again.
- **A push to `main` while an environment is down:** `cluster-bootstrap.yml` finds no cluster and skips it, saying so in the run's summary. The other environments still get the change, and `make aws-up` applies it when the environment comes back.

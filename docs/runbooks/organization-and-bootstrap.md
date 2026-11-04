# Runbook: create the organization and bootstrap the accounts

A procedure, not an alert: the maintainer runs it once, at the start of M4 (delivery plan 4), to turn the personal AWS
account into the management account of an organization ([ADR-0006](../adr/0006-aws-account-per-environment.md)),
create the member accounts, guardrails and budgets (`infra/organization`, #55), and apply the first bootstrap stacks
(`infra/bootstrap`, #54). Staging and prod are bootstrapped the same way when M7 needs them.

> [!IMPORTANT]
> Nothing here has been run. Every command is for the maintainer, with the profiles he names (CLAUDE.md). The profile
> names below (`sft-bootstrap`, `sft-management-admin`, ...) are suggestions; use the ones you choose, and never the
> default CLI identity.

## What you need

- Terraform 1.17 (`required_version`), AWS CLI 2.32 or later (for `aws login`), and a FIDO2 security key, plus a second
  one as a spare.
- Five email addresses you control, all different: the management account's (it exists already), one per member
  account, and one for the budget alarms (it may be the same as yours). Plus-addressing works, for example
  `you+sft-dev@example.com`. **An account's email can never be reused once the account is closed**, so pick ones you
  will keep.
- `make infra-check` passing on `main`.
- The personal account emptied of workloads. SCPs never apply to the management account, so anything left there runs
  without guardrails (ADR-0006).

Keep the account IDs, emails and user names out of git: pass them as `TF_VAR_...` environment variables or in a
git-ignored `.tfvars` file.

## Profiles

| Profile | Identity | Used for |
|---|---|---|
| `sft-bootstrap` | A temporary IAM user in the management account, through `aws login` | Steps 3 to 5 only, before Identity Center exists. Deleted in step 9. |
| `sft-management-approver` | `BreakGlassApprover` in the management account | Assigning and removing `Admin` and `BreakGlass` |
| `sft-management-admin` | `Admin` in the management account, for at most an hour | Later applies of the organization stack and the management bootstrap |
| `sft-<account>-admin` | `Admin` in shared, dev, staging or prod, for at most an hour | That account's bootstrap stacks |

Every Identity Center profile shares one `sso-session` in `~/.aws/config`:

```ini
[sso-session sft]
sso_start_url = https://<your access portal>.awsapps.com/start
sso_region = ap-northeast-1
sso_registration_scopes = sso:account:access

[profile sft-management-approver]
sso_session = sft
sso_account_id = <management account id>
sso_role_name = BreakGlassApprover
region = ap-northeast-1

[profile sft-dev-admin]
sso_session = sft
sso_account_id = <dev account id>
sso_role_name = Admin
region = ap-northeast-1
```

## Steps

### 1. Secure the management account's root user (console, as root)

1. Register both security keys as root MFA devices. Delete any root access keys.
2. Check **Account → Alternate contacts** (security, billing, operations) reach you.
3. If this account is already in an organization, stop: you need to import the organization in step 5 instead of
   creating one (see "If something already exists").

From here on, root is used again only for the tasks only root can do.

### 2. Create the temporary bootstrap user (console, as root)

IAM → Users → **Create user** `sft-bootstrap`: console access with a password, the `AdministratorAccess` policy, a
security key as its MFA device, **no access keys**. It exists only until Identity Center works (step 9).

### 3. Sign the CLI in as the bootstrap user

```bash
aws login --profile sft-bootstrap          # opens the console sign-in; short-lived credentials, no keys
aws sts get-caller-identity --profile sft-bootstrap   # must show user/sft-bootstrap in the management account
```

If Terraform's provider doesn't read `aws login` credentials yet, make a second profile, `sft-bootstrap-tf`, that holds
only `credential_process = aws configure export-credentials --profile sft-bootstrap --format process`, and use it
wherever this runbook says `sft-bootstrap` for Terraform.

### 4. Bootstrap the management account (`sft-bootstrap`)

Follow [infra/README.md, "Bootstrap an account"](../../infra/README.md#bootstrap-an-account) for
`infra/bootstrap/management/ap-northeast-1`, with:

```bash
export AWS_PROFILE=sft-bootstrap TF_VAR_account_id=<management account id>
export TF_VAR_admin_principal_arn_patterns='["arn:aws:iam::<management account id>:user/sft-bootstrap"]'
```

It creates the state bucket and tfstate key, the GitHub OIDC provider and the plan role with read access to the
organization. The state ends in `sft-management-apne1-tfstate-<management account id>`.

### 5. Apply the organization stack, part one (`sft-bootstrap`)

```bash
cd infra/organization
export AWS_PROFILE=sft-bootstrap TF_VAR_account_id=<management account id>
export TF_VAR_account_emails='{shared="...",dev="...",staging="...",prod="..."}'
export TF_VAR_budget_notification_emails='["..."]'
export TF_VAR_identity_center_enabled=false TF_VAR_activate_cost_allocation_tags=false
terraform init -backend-config="bucket=sft-management-apne1-tfstate-${TF_VAR_account_id}"

# Budgets first: the $6,500 alarm exists before anything can spend (NFR-20).
terraform apply -target='aws_budgets_budget.monthly["total"]'
terraform apply
```

The full apply creates the organization, the `prod`, `nonprod` and `shared` OUs, the four member accounts (each takes a
few minutes), the five SCPs and their attachments, the per-account budgets, centralized root access and the shared
account as CloudTrail's delegated administrator. Read the plan before you type `yes`: it must create, never destroy.

Then check:

- The budget emails don't need confirming, but check spam for the first one.
- `terraform output account_ids` lists all five accounts. Note them; every other stack takes its `TF_VAR_account_id`
  from here.
- **Organizations → Policies → Service control policies**: the root has `FullAWSAccess` and four `sft-management-scp-*`
  policies; the `prod` OU has `sft-management-scp-audit-archive`.
- **IAM → Root access management**: root credentials management and privileged root actions are on. Member accounts
  created here have no root password, so there is no root MFA to set up in them.

Cost allocation tags: AWS can activate a tag key only after it has seen it on a bill, up to a day after the first
tagged resource (step 4). Keep `TF_VAR_activate_cost_allocation_tags=false` until then, and drop it in step 10.

### 6. Enable IAM Identity Center (console, as `sft-bootstrap`)

**Make sure the console's Region is Asia Pacific (Tokyo)** first: the home Region can't be moved later (ADR-0006).
IAM Identity Center → **Enable** → for the organization. Then, under **Settings**:

1. **Identity source**: Identity Center directory (the default).
2. **Authentication → Multi-factor authentication → Configure**: prompt users for MFA **every time they sign in**;
   allow **security keys and built-in authenticators** only (no authenticator apps); if a user has no MFA device,
   **require them to register one at sign-in** (authn-authz 8.1).
3. **Authentication → Session settings**: an access portal session of 4 hours, so a security key touch is needed at
   least that often.

There is no API for these settings, so Terraform can't enforce them; step 11 checks them.

### 7. Create your Identity Center user (console)

Users → **Add user**, with your email and a user name you'll pass to Terraform. Accept the invitation, set the
password and register both security keys.

### 8. Apply the organization stack, part two (`sft-bootstrap`)

```bash
unset TF_VAR_identity_center_enabled
export TF_VAR_identity_center_group_members='{readonly=["<you>"],operators=["<you>"],breakglass_approvers=["<you>"],audit_readers=["<you>"]}'
terraform apply
```

It creates the six permission sets (`Admin`, `BreakGlass`, `BreakGlassApprover`, `ReadOnly`, `Operator`,
`AuditReader`), the four groups, your memberships and the group assignments. It assigns nothing for `Admin` or
`BreakGlass`: those are never standing.

### 9. Move the management account to Identity Center

1. Sign in through the access portal; write the profiles above into `~/.aws/config`.
2. Assign yourself `Admin` in the management account for this step ("Assign and remove Admin" below).
3. Re-apply the management bootstrap **as `sft-bootstrap`**, naming both principals, because the state policy admits
   only the bootstrap user so far:

   ```bash
   cd infra/bootstrap/management/ap-northeast-1
   export AWS_PROFILE=sft-bootstrap
   export TF_VAR_admin_principal_arn_patterns='["arn:aws:iam::<mgmt>:user/sft-bootstrap","arn:aws:iam::<mgmt>:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_Admin_*"]'
   terraform init -backend-config="bucket=sft-management-apne1-tfstate-<mgmt>" && terraform apply
   ```

4. Apply it again **as `sft-management-admin`** with only the `Admin` pattern, so the bootstrap user loses its access:

   ```bash
   export AWS_PROFILE=sft-management-admin
   export TF_VAR_admin_principal_arn_patterns='["arn:aws:iam::<mgmt>:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_Admin_*"]'
   aws sso login --profile sft-management-admin && terraform apply
   ```

5. As `sft-management-admin`, run `terraform plan` in `infra/organization`: it must show no changes.
6. Delete the `sft-bootstrap` IAM user (console, as `Admin`), then remove your `Admin` assignment.

From now on the organization stack is applied with `sft-management-admin` and MFA, never from CI (ADR-0006).

### 10. Activate the cost allocation tags (`sft-management-admin`, a day after step 4)

```bash
cd infra/organization && terraform apply    # TF_VAR_activate_cost_allocation_tags no longer set
```

### 11. Bootstrap each member account (`sft-<account>-admin`)

M4 needs shared and dev; staging and prod follow in M7. For each account, in this order:

1. Assign yourself `Admin` in that account ("Assign and remove Admin" below) and `aws sso login --profile
   sft-<account>-admin`.
2. Apply `infra/bootstrap/<account>/ap-northeast-1` as [infra/README.md](../../infra/README.md#bootstrap-an-account)
   says, with `TF_VAR_account_id` from `terraform output account_ids` in step 5. The admin pattern comes from the
   code; no `TF_VAR_admin_principal_arn_patterns`.
3. Staging and prod only: apply `infra/bootstrap/<account>/ap-northeast-3` with `TF_VAR_tfstate_primary_key_arn` from
   the Tokyo stack's `tfstate_key_arn` output.
4. Remove your `Admin` assignment.

Then check, in that account:

- With `ReadOnly`: `aws ec2 describe-instances --region us-west-2` fails with an explicit deny in a service control
  policy (the region guard). `aws ec2 describe-instances --region ap-northeast-1` works.
- With `BreakGlass` assigned for a few minutes: `aws iam update-assume-role-policy` on
  `sft-<account>-terraform-deploy` fails with an explicit deny (SCP 4). Remove the assignment.
- IAM → Roles: `sft-<account>-terraform-plan`, `-terraform-deploy` and `-keyadmin` under `/sft-bootstrap/`.

### 12. Check Identity Center (console)

Sign out and back in: the portal asks for the security key; an authenticator app isn't offered. Your groups show
`ReadOnly`, `Operator` and `AuditReader` in the member accounts and `BreakGlassApprover` in management, and nothing
else.

## Assign and remove Admin or BreakGlass

Until the break-glass tool exists (FR-35, M6), the approver does it by hand, for at most an hour, and removes it
afterwards. Every assignment will alert once the alert rules exist; with one maintainer, self-approval is the accepted
residual risk R-08 (authn-authz 8.3).

```bash
export AWS_PROFILE=sft-management-approver
aws sso login
instance=$(cd infra/organization && terraform output -raw sso_instance_arn)
admin=$(cd infra/organization && terraform output -json permission_set_arns | jq -r .Admin)   # or .BreakGlass
me=$(aws identitystore get-user-id --identity-store-id "$(cd infra/organization && terraform output -raw identity_store_id)" \
  --alternate-identifier '{"UniqueAttribute":{"AttributePath":"UserName","AttributeValue":"<you>"}}' --query UserId --output text)

aws sso-admin create-account-assignment --instance-arn "$instance" --permission-set-arn "$admin" \
  --principal-type USER --principal-id "$me" --target-type AWS_ACCOUNT --target-id <account id>
# ... the work, within the hour ...
aws sso-admin delete-account-assignment --instance-arn "$instance" --permission-set-arn "$admin" \
  --principal-type USER --principal-id "$me" --target-type AWS_ACCOUNT --target-id <account id>
```

Reading the outputs needs the organization stack's state, so run those `terraform output` commands once with
`sft-management-admin` and keep the ARNs and IDs at hand (they aren't secrets, but keep them out of git).

## Never

- **Destroy the organization stack or remove an account from it.** The organization and the accounts have
  `prevent_destroy`, and accounts are created with `close_on_deletion = false`. Closing an account takes 90 days to
  finish, can't be undone after that, and its email can't be reused. Account closure belongs to the final teardown
  (NFR-19), which keeps the prod account open for the retained stack.
- Apply the organization stack from CI, or with the default CLI identity.
- Keep a standing `Admin` or `BreakGlass` assignment. The approver's own assignment is the only standing access to the
  management account.
- Rename a permission set: bucket and key policies match `Admin` and `BreakGlass` by name.
- Detach `FullAWSAccess`: with deny-only SCPs it is the only allow, and removing it denies everything in that target.

## If something goes wrong

- **An SCP blocks something it shouldn't.** SCPs never bind the management account, so `sft-management-admin` can
  always fix one: change it in `infra/organization/scps.tf` and apply. In an emergency, detach it in the console and
  bring the code back in line with a plan right after.
- **A member account's bucket or queue policy locks everyone out.** From the management account, IAM → Root access
  management → **Take privileged action** on that account (a 15-minute root session; SCP 3 lets it through).
- **Identity Center is unreachable** (a Tokyo outage): authn-authz 8.4. The management account's root user, with its
  security key, still signs in, because IAM is global.
- **Step 5 fails with `TagKeysNotFoundException`:** `TF_VAR_activate_cost_allocation_tags=false` wasn't set.
- **Step 8 fails with "No IAM Identity Center instance":** it was enabled in a Region other than Tokyo. Delete that
  instance and enable it again in Tokyo (step 6).

### If something already exists

- An organization already exists in this account: `terraform import aws_organizations_organization.this <o-id>` before
  step 5, then plan. The plan must not replace it.
- An account already exists and should join: invite it from Organizations, accept it in that account, then
  `terraform import 'aws_organizations_account.member["<name>"]' <account id>`. An invited account keeps its root
  password: remove it from IAM → Root access management in the management account.

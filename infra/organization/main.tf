# AWS Organizations, the OUs and member accounts, IAM Identity Center and its permission sets, the SCPs and the budgets,
# in the management account (ADR-0006, NFR-20, NFR-21). Applied by the maintainer with MFA, never by CI; CI only checks
# it and plans it read-only through the management account's plan role (ADR-0006). SCPs don't bind this account, so
# nothing else lives here but the break-glass reconciliation's read-only roles (break-glass-trail.tf). The apply order
# and the manual steps AWS requires are in docs/runbooks/organization-and-bootstrap.md.
#
# Files: main.tf (organization, OUs, accounts, trusted access), scps.tf (the five SCPs), identity-center.tf
# (permission sets, groups, assignments), budgets.tf (budgets and cost allocation tags), break-glass-trail.tf (each
# environment's read-only role for its break-glass reconciliation, #239).
#
# What this stack deliberately doesn't hold:
# - The organization trail. The shared account is CloudTrail's delegated administrator (below) and the shared stack
#   creates the trail next to its log archive, so the trail, its bucket and its key end together (ADR-0006,
#   encryption 8.4). That trail must log S3 data events on every sft-*-tfstate-* bucket, which the state buckets rely
#   on instead of server access logs (.trivyignore.yaml, AVD-AWS-0089).
# - GuardDuty and AWS Config. Each environment runs its own and tears them down with it (encryption 8.4, capacity
#   7.4), so neither has a delegated administrator or an organization-wide configuration.
# - The NFR-19 budget of $7. The retained stack creates it in the prod account (encryption 8.4).

terraform {
  required_version = "~> 1.17.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.71.0"
    }
  }

  # Partial backend. The bucket names the account, so it comes from -backend-config at init; the key is this
  # directory under infra/ (infra/README.md, "State").
  backend "s3" {
    key          = "organization/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../modules/conventions"

  environment = "management"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "organization"
  component   = "organization"
}

# Tokyo is also Identity Center's home Region (ADR-0006). Organizations, IAM, Budgets and Cost Explorer are global
# services, which the provider reaches from here.
provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

locals {
  # The member accounts and their OUs (ADR-0006). Keys are the environment names used everywhere else.
  member_accounts = {
    shared  = { ou = "shared" }
    dev     = { ou = "nonprod" }
    staging = { ou = "nonprod" }
    prod    = { ou = "prod" }
  }

  organizational_units = toset(["prod", "nonprod", "shared"])

  root_id = aws_organizations_organization.this.roots[0].id

  # Every account by environment name, management included, for assignments and budgets.
  account_ids = merge(
    { management = var.account_id },
    { for name, account in aws_organizations_account.member : name => account.id },
  )
}

# --- Organization ------------------------------------------------------------------------------------------------

resource "aws_organizations_organization" "this" {
  feature_set = "ALL"

  # Trusted access: Identity Center (ADR-0006), CloudTrail for the organization trail the shared account creates, and
  # IAM for centralized root access, so member accounts have no root credentials at all (below).
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "iam.amazonaws.com",
    "sso.amazonaws.com",
  ]

  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]

  # Deleting the organization would detach every account and drop every guard.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_organizational_unit" "this" {
  for_each = local.organizational_units

  name      = each.key
  parent_id = local.root_id
}

# Account emails come in as variables and are never committed. A closed account takes 90 days to go and its email can
# never be used again, so nothing here closes one: close_on_deletion is off and the accounts can't be destroyed.
resource "aws_organizations_account" "member" {
  for_each = local.member_accounts

  name              = "sft-${each.key}" # the global name pattern, sft-<env> (infra/README.md)
  email             = var.account_emails[each.key]
  parent_id         = aws_organizations_organizational_unit.this[each.value.ou].id
  close_on_deletion = false

  # Organizations creates this role in each new account, trusting the management account. SCP 4 lets only Admin change
  # it, like the bootstrap roles. Billing stays visible to the account's own roles.
  role_name                  = "OrganizationAccountAccessRole"
  iam_user_access_to_billing = "ALLOW"

  lifecycle {
    prevent_destroy = true
    # AWS doesn't return these after creation, so an imported account would otherwise plan to be replaced.
    ignore_changes = [role_name, iam_user_access_to_billing]
  }
}

# Centralized root access: member accounts created here have no root password, nobody can recover one, and a
# privileged root task (such as deleting a bucket policy that locks everyone out) runs from this account through
# sts:AssumeRoot for at most 15 minutes. SCP 3 denies root's long-term credentials and lets those sessions through.
resource "aws_iam_organizations_features" "root_access" {
  enabled_features = ["RootCredentialsManagement", "RootSessions"]

  depends_on = [aws_organizations_organization.this]
}

# The shared account creates and owns the organization trail (see the header).
resource "aws_cloudtrail_organization_delegated_admin_account" "shared" {
  account_id = aws_organizations_account.member["shared"].id

  depends_on = [aws_organizations_organization.this]
}

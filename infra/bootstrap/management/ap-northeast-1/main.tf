# Bootstrap for the management account in Tokyo (ADR-0005, ADR-0006): this Region's state bucket and tfstate key, the
# GitHub OIDC provider and the Terraform plan role, which CI uses to check and plan the organization stack read-only.
# There is no deploy role: the maintainer applies the organization stack with MFA, never CI, because no SCP can limit
# a role in this account. There is no key-admin role either: it exists so a key policy can be repaired where SCPs bind
# every administrator, and SCPs don't bind this account's.
#
# Applied first of all stacks, by the maintainer, starting from local state (infra/README.md, "Bootstrap an account").

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
    key          = "bootstrap/management/ap-northeast-1/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../modules/conventions"

  environment = "management"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "bootstrap/management/ap-northeast-1"
  component   = "bootstrap"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# What a read-only plan of the organization stack reads (#55): Organizations, Identity Center and its identity store,
# Budgets, the cost allocation tags and the root access settings. Read and list actions only; the stack's state comes
# through the bucket and key policies.
data "aws_iam_policy_document" "plan_organization" {
  statement {
    sid       = "ReadTheOrganization"
    actions   = ["organizations:Describe*", "organizations:List*", "iam:ListOrganizationsFeatures"]
    resources = ["*"]
  }

  statement {
    sid = "ReadIdentityCenter"
    actions = [
      "identitystore:DescribeGroup", "identitystore:DescribeGroupMembership", "identitystore:DescribeUser",
      "identitystore:GetUserId",
      "sso:DescribePermissionSet", "sso:GetInlinePolicyForPermissionSet", "sso:ListAccountAssignments",
      "sso:ListInstances", "sso:ListManagedPoliciesInPermissionSet", "sso:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ReadBudgetsAndCostAllocationTags"
    actions   = ["budgets:ListTagsForResource", "budgets:ViewBudget", "ce:ListCostAllocationTags"]
    resources = ["*"]
  }
}

module "terraform_roles" {
  source = "../../../modules/terraform-oidc-roles"

  conventions = module.conventions

  account_id         = var.account_id
  github_repository  = module.conventions.github_repository
  github_environment = null
  iam_path           = module.conventions.bootstrap_iam_path
  plan_role_name     = module.conventions.bootstrap_role_names.terraform_plan
  deploy_role_name   = module.conventions.bootstrap_role_names.terraform_deploy
  plan_policy_json   = data.aws_iam_policy_document.plan_organization.json
}

module "state" {
  source = "../../../modules/tfstate-backend"

  account_id                   = var.account_id
  bucket_name                  = module.conventions.state_bucket_name
  kms_alias                    = "${module.conventions.kms_alias_prefix}/tfstate"
  deletion_window_in_days      = 30
  admin_principal_arn_patterns = var.admin_principal_arn_patterns
  plan_role_arn                = module.terraform_roles.plan_role_arn
}

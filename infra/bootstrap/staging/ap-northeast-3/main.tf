# Bootstrap for the staging account in Osaka (ADR-0005, T-73): this Region's state bucket and the Osaka replica of the
# tfstate key. Osaka's stacks keep their state and locks here, so planning or applying them, a failover included,
# needs nothing from Tokyo. The account's roles are global and belong to the Tokyo bootstrap stack, which is applied
# first; this stack grants them access through its own bucket and key policies and changes no IAM.
#
# Applied by the maintainer with the time-boxed Admin permission set, starting from local state, never by CI
# (infra/README.md, "Bootstrap an account"); in a Tokyo outage, with the account's emergency user.

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
    key          = "bootstrap/staging/ap-northeast-3/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "bootstrap/staging/ap-northeast-3"
  component   = "bootstrap"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# A Tokyo outage takes Identity Center, and with it Admin, so the account's emergency user (authn-authz 8.4), created
# by the Tokyo stack, is a bootstrap admin here too: by its exact ARN, never a pattern. Only Osaka names it, because
# Tokyo's state is out of reach in that outage anyway.
locals {
  admin_principal_arn_patterns = [module.conventions.sso_role_arn_patterns.admin, module.conventions.emergency_user.arn]
}

module "state" {
  source = "../../../modules/tfstate-backend"

  account_id                         = var.account_id
  bucket_name                        = module.conventions.state_bucket_name
  kms_alias                          = "${module.conventions.kms_alias_prefix}/tfstate"
  primary_key_arn                    = var.tfstate_primary_key_arn
  deletion_window_in_days            = 7
  admin_principal_arn_patterns       = local.admin_principal_arn_patterns
  break_glass_principal_arn_patterns = [module.conventions.sso_role_arn_patterns.break_glass]
  plan_role_arn                      = module.conventions.bootstrap_role_arns.terraform_plan
  deploy_role_arn                    = module.conventions.bootstrap_role_arns.terraform_deploy
  key_admin_role_arn                 = module.conventions.bootstrap_role_arns.key_admin
}

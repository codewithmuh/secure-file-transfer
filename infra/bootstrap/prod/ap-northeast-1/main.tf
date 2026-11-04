# Bootstrap for the prod account in Tokyo (ADR-0005, encryption 4.4): this Region's state bucket and tfstate key, the
# GitHub OIDC provider, the Terraform plan and deploy roles, and the key-admin role. The roles are global, so they live
# here; Osaka's bootstrap stack only adds its own bucket and key.
#
# Applied by the maintainer with the time-boxed Admin permission set, starting from local state, never by CI
# (infra/README.md, "Bootstrap an account").

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
    key          = "bootstrap/prod/ap-northeast-1/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "bootstrap/prod/ap-northeast-1"
  component   = "bootstrap"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

locals {
  admin_principal_arn_patterns       = [module.conventions.sso_role_arn_patterns.admin]
  break_glass_principal_arn_patterns = [module.conventions.sso_role_arn_patterns.break_glass]
}

module "terraform_roles" {
  source = "../../../modules/terraform-oidc-roles"

  account_id         = var.account_id
  github_repository  = module.conventions.github_repository
  github_environment = "prod"
  iam_path           = module.conventions.bootstrap_iam_path
  plan_role_name     = module.conventions.bootstrap_role_names.terraform_plan
  deploy_role_name   = module.conventions.bootstrap_role_names.terraform_deploy
}

module "key_admin" {
  source = "../../../modules/key-admin-role"

  account_id                         = var.account_id
  role_name                          = module.conventions.bootstrap_role_names.key_admin
  iam_path                           = module.conventions.bootstrap_iam_path
  break_glass_principal_arn_patterns = local.break_glass_principal_arn_patterns
}

module "state" {
  source = "../../../modules/tfstate-backend"

  account_id                         = var.account_id
  bucket_name                        = module.conventions.state_bucket_name
  kms_alias                          = "${module.conventions.kms_alias_prefix}/tfstate"
  deletion_window_in_days            = 30
  admin_principal_arn_patterns       = local.admin_principal_arn_patterns
  break_glass_principal_arn_patterns = local.break_glass_principal_arn_patterns
  plan_role_arn                      = module.terraform_roles.plan_role_arn
  deploy_role_arn                    = module.terraform_roles.deploy_role_arn
  key_admin_role_arn                 = module.key_admin.role_arn
}

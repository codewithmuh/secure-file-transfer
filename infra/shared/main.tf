# The shared account's stack: the container registry and its key (ADR-0007), the public DNS zone with DNSSEC and the
# environments' DNS roles (ADR-0021), and the organization's log archive with the organization trail (ADR-0006). It
# lives from the bootstrap until the last environment is torn down (capacity 5.4). Built by #105.
#
# One root for three Regions, one of the two deliberate exceptions (infra/README.md): Tokyo for everything that holds
# data; ap-northeast-3 for the registry key's replica and ECR's replication template, once staging exists
# (replicate_to_osaka); us-east-1 for the zone's DNSSEC signing key, which Route 53 requires there (NFR-21). None of
# them is in a failover path.
#
# The account IDs and the domain come in as variables (TF_VAR_*), never committed. The web bundle's versioned store
# (ADR-0008) is not here yet: it arrives with the web release workflow that writes it.

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
    key          = "shared/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../modules/conventions"

  environment = "shared"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "shared"
  component   = "shared"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

provider "aws" {
  alias               = "osaka"
  region              = "ap-northeast-3"
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = merge(module.conventions.tags, { "region" = "ap-northeast-3" })
  }
}

provider "aws" {
  alias               = "us_east_1"
  region              = "us-east-1"
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = merge(module.conventions.tags, { "region" = "us-east-1" })
  }
}

locals {
  bootstrap_role_arns = module.conventions.bootstrap_role_arns
  break_glass         = [module.conventions.sso_role_arn_patterns.break_glass]

  # Roles this stack creates live under their own path, which the deploy role may change; /sft-bootstrap/ is Admin's
  # alone (SCP 4).
  iam_path = "/sft-shared/"

  # The account's GitHub OIDC provider, made by its bootstrap stack.
  github_oidc_provider_arn = "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com"
}

module "registry" {
  source = "../modules/registry"

  providers = {
    aws       = aws
    aws.osaka = aws.osaka
  }

  account_id          = var.account_id
  member_account_ids  = var.member_account_ids
  mirror_repositories = var.mirror_repositories
  replicate_to_osaka  = var.replicate_to_osaka
  kms_alias_prefix    = module.conventions.kms_alias_prefix

  deploy_role_arn                    = local.bootstrap_role_arns.terraform_deploy
  plan_role_arn                      = local.bootstrap_role_arns.terraform_plan
  key_admin_role_arn                 = local.bootstrap_role_arns.key_admin
  break_glass_principal_arn_patterns = local.break_glass

  github_oidc_provider_arn = local.github_oidc_provider_arn
  github_repository        = module.conventions.github_repository
  push_role_name           = "${module.conventions.global_name_prefix}-image-push"
  iam_path                 = local.iam_path
}

module "dns_zone" {
  source = "../modules/dns-zone"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  account_id         = var.account_id
  domain             = var.domain
  member_account_ids = var.member_account_ids
  kms_alias_prefix   = module.conventions.kms_alias_prefix
  bootstrap_iam_path = module.conventions.bootstrap_iam_path
  iam_path           = local.iam_path

  deploy_role_arn                    = local.bootstrap_role_arns.terraform_deploy
  plan_role_arn                      = local.bootstrap_role_arns.terraform_plan
  key_admin_role_arn                 = local.bootstrap_role_arns.key_admin
  break_glass_principal_arn_patterns = local.break_glass
}

module "log_archive" {
  source = "../modules/log-archive"

  account_id            = var.account_id
  management_account_id = var.management_account_id
  member_account_ids    = var.member_account_ids
  bucket_name           = "${module.conventions.name_prefix}-log-archive-${var.account_id}"
  kms_alias_prefix      = module.conventions.kms_alias_prefix

  deploy_role_arn                    = local.bootstrap_role_arns.terraform_deploy
  plan_role_arn                      = local.bootstrap_role_arns.terraform_plan
  key_admin_role_arn                 = local.bootstrap_role_arns.key_admin
  admin_principal_arn_patterns       = [module.conventions.sso_role_arn_patterns.admin]
  break_glass_principal_arn_patterns = local.break_glass
}

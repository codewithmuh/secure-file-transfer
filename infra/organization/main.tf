# AWS Organizations, the OUs and member accounts, IAM Identity Center and its permission sets, the SCPs and the budgets,
# in the management account (ADR-0006, NFR-20, NFR-21). Applied by the maintainer with MFA, never by CI; CI only checks
# it and plans it read-only (ADR-0006).
#
# Skeleton from #54: providers, backend and conventions only. #55 fills it.

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

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

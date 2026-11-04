# The shared account's stack: the container registry and its key (ADR-0007), the web bundle artifacts (ADR-0008), the
# public DNS zone (ADR-0021) and the organization's log archive (ADR-0006). It lives from the bootstrap until the last
# environment is torn down (capacity 5.4).
#
# Skeleton from #54: providers, backend and conventions only. An M4 issue fills it. That issue also adds a provider
# alias for ap-northeast-3: the registry key's replica and ECR's replica, once staging exists (capacity 5.4). That issue
# also adds a provider alias for us-east-1: the zone's DNSSEC signing key, which Route 53 requires there (NFR-21).

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

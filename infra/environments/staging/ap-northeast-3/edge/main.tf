# staging in Osaka, edge layer. What the internet reaches first: the load balancer, its WAF web ACL and the
# environment's records in the shared DNS zone (ADR-0021, abuse 2 and 3). Its load balancer and WAF stand by for a
# failover (architecture 3.2).
#
# Skeleton from #54: providers, backend and conventions only. An M4 issue fills it.

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
    key          = "environments/staging/ap-northeast-3/edge/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-3/edge"
  component   = "edge"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

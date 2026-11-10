# prod in Osaka, edge layer (#105). What the internet reaches first: the API's load balancer with its web ACL and
# certificate, the sign-in web ACL, this Region's own API record in the shared zone and its health check (ADR-0021,
# abuse 2 and 3). The load balancer and web ACLs stand by for a failover (architecture 3.2), which points the API's
# name here through the Tokyo stack's api_alias_target (T-78). The web bucket here is the distribution's failover
# origin (ADR-0008).
#
# Applied after the Tokyo stack: web_distribution_arn is its output, the web bucket's only reader.
#
# Managed rules and the sign-in rate rules start in Count (abuse 3.2, rollout); each moves to Block after two weeks.

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
    key          = "environments/prod/ap-northeast-3/edge/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-3/edge"
  component   = "edge"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# The shared zone, through this environment's DNS role in the shared account (ADR-0021): the read role for plans,
# the write role for applies, which may change only this environment's names.
provider "aws" {
  alias               = "dns"
  region              = module.conventions.region
  allowed_account_ids = [var.shared_account_id]

  assume_role {
    role_arn     = "arn:aws:iam::${var.shared_account_id}:role/sft-shared/sft-shared-dns-prod-${var.terraform_role}"
    session_name = "prod-edge"
  }

  default_tags {
    tags = module.conventions.tags
  }
}

module "edge" {
  source = "../../../../modules/edge"

  providers = {
    aws     = aws
    aws.dns = aws.dns
  }

  environment      = "prod"
  account_id       = var.account_id
  name_prefix      = module.conventions.name_prefix
  region_short     = module.conventions.region_short
  kms_alias_prefix = module.conventions.kms_alias_prefix
  domain           = var.domain

  primary_region       = false
  web_distribution_arn = var.web_distribution_arn

  managed_rules_in_count = true
  deletion_protection    = !var.teardown
}

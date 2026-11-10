# staging in Tokyo, edge layer (#105). What the internet reaches first: the API's load balancer with its web ACL and
# certificate, the sign-in web ACL, the environment's records in the shared zone and this Region's health check
# (ADR-0021, abuse 2 and 3); and the CloudFront distribution that serves the web app, with its certificate and web
# ACL in us-east-1 (ADR-0008, NFR-21).
#
# The distribution's failover origin is Osaka's web bucket, which environments/staging/ap-northeast-3/edge creates
# after this stack, from this stack's web_distribution_arn output. Its name is fixed, so CloudFront can point at it
# before it exists.
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
    key          = "environments/staging/ap-northeast-1/edge/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-1/edge"
  component   = "edge"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
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

# The shared zone, through this environment's DNS role in the shared account (ADR-0021): the read role for plans,
# the write role for applies, which may change only this environment's names.
provider "aws" {
  alias               = "dns"
  region              = module.conventions.region
  allowed_account_ids = [var.shared_account_id]

  assume_role {
    role_arn     = "arn:aws:iam::${var.shared_account_id}:role/sft-shared/sft-shared-dns-staging-${var.terraform_role}"
    session_name = "staging-edge"
  }

  default_tags {
    tags = module.conventions.tags
  }
}

locals {
  # The files buckets the browser uploads parts to (ADR-0012, #102), for the web app's CSP.
  upload_origins = [
    "https://${module.conventions.name_prefix}-files-${var.account_id}.s3.ap-northeast-1.amazonaws.com",
    "https://${module.conventions.name_prefix}-large-files-${var.account_id}.s3.ap-northeast-1.amazonaws.com",
    "https://${module.conventions.global_name_prefix}-${module.conventions.region_shorts["ap-northeast-3"]}-files-${var.account_id}.s3.ap-northeast-3.amazonaws.com",
    "https://${module.conventions.global_name_prefix}-${module.conventions.region_shorts["ap-northeast-3"]}-large-files-${var.account_id}.s3.ap-northeast-3.amazonaws.com",
  ]
}

module "edge" {
  source = "../../../../modules/edge"

  providers = {
    aws     = aws
    aws.dns = aws.dns
  }

  environment      = "staging"
  account_id       = var.account_id
  name_prefix      = module.conventions.name_prefix
  region_short     = module.conventions.region_short
  kms_alias_prefix = module.conventions.kms_alias_prefix
  domain           = var.domain

  primary_region       = true
  api_alias_target     = var.api_alias_target
  web_distribution_arn = module.web_cdn.distribution_arn

  managed_rules_in_count = true
  deletion_protection    = false
}

module "web_cdn" {
  source = "../../../../modules/web-cdn"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
    aws.dns       = aws.dns
  }

  name_prefix    = module.conventions.name_prefix
  service_domain = module.edge.service_domain
  zone_id        = module.edge.zone_id
  log_bucket_arn = module.edge.waf_log_bucket_arn
  upload_origins = local.upload_origins

  primary_bucket = {
    region_short         = module.conventions.region_short
    regional_domain_name = module.edge.web_bucket.regional_domain_name
  }

  failover_bucket = {
    region_short         = module.conventions.region_shorts["ap-northeast-3"]
    regional_domain_name = "${module.conventions.global_name_prefix}-${module.conventions.region_shorts["ap-northeast-3"]}-web-${var.account_id}.s3.ap-northeast-3.amazonaws.com"
  }

  managed_rules_in_count = true
}

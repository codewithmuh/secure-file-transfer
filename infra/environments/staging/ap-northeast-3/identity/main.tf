# staging in Osaka, identity layer (#185): this Region's SES setup (modules/ses, ADR-0015), its member user pool
# (modules/user-pool, ADR-0016) and its application secrets, without values (modules/app-secrets, encryption 6.4).
# After the data and edge layers, which it reads: the ses-events queue and the sign-in web ACL. cluster-bootstrap
# reads this layer's outputs for the chart (user pool, login domain, configuration set).
#
# Osaka's pool is the standby: same code, no users (ADR-0016). Its secrets are only its own idp-client.

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
    key          = "environments/staging/ap-northeast-3/identity/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-3/identity"
  component   = "identity"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# The shared zone, through this environment's DNS role in the shared account (ADR-0021): the read role for plans,
# the write role for applies, which may change only this environment's names (mail and *.mail among them).
provider "aws" {
  alias               = "dns"
  region              = module.conventions.region
  allowed_account_ids = [var.shared_account_id]

  assume_role {
    role_arn     = "arn:aws:iam::${var.shared_account_id}:role/sft-shared/sft-shared-dns-staging-${var.terraform_role}"
    session_name = "staging-identity"
  }

  default_tags {
    tags = module.conventions.tags
  }
}

data "terraform_remote_state" "data" {
  backend = "s3"
  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/staging/ap-northeast-3/data/terraform.tfstate"
    region = module.conventions.region
  }
}

data "terraform_remote_state" "edge" {
  backend = "s3"
  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/staging/ap-northeast-3/edge/terraform.tfstate"
    region = module.conventions.region
  }
}

module "ses" {
  source = "../../../../modules/ses"

  providers = {
    aws     = aws
    aws.dns = aws.dns
  }

  environment          = "staging"
  account_id           = var.account_id
  region               = module.conventions.region
  region_short         = module.conventions.region_short
  name_prefix          = module.conventions.name_prefix
  kms_alias_prefix     = module.conventions.kms_alias_prefix
  domain               = var.domain
  primary_region       = false
  events_queue_arn     = data.terraform_remote_state.data.outputs.queue_arns["ses-events"]
  dmarc_report_address = var.dmarc_report_address
}

module "user_pool" {
  source = "../../../../modules/user-pool"

  environment           = "staging"
  account_id            = var.account_id
  region                = module.conventions.region
  region_short          = module.conventions.region_short
  name_prefix           = module.conventions.name_prefix
  domain                = var.domain
  ses_identity_arn      = module.ses.identity_arn
  from_address          = module.ses.from_address
  ses_configuration_set = module.ses.configuration_set
  sign_in_web_acl_arn   = data.terraform_remote_state.edge.outputs.sign_in_web_acl_arn
  deletion_protection   = false

  depends_on = [module.ses]
}

module "app_secrets" {
  source = "../../../../modules/app-secrets"

  environment             = "staging"
  region                  = module.conventions.region
  primary_region          = false
  kms_alias_prefix        = module.conventions.kms_alias_prefix
  recovery_window_in_days = 7
}

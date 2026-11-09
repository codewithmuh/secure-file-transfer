# prod in Tokyo, alarms layer (#246). The AWS-side alarms of ADR-0009 and their topics (modules/alarms): the
# watchdog's heartbeat, Aurora, the queues, the load balancer, the NAT gateways, KMS, SES and the sign-in triggers.
# Also S3 replication to Osaka, and in us-east-1 the Route 53 health check alarms of both Regions, so this stack goes
# after Osaka's edge stack, whose health check it reads.
#
# Applied last, after every other layer of this Region, whose state it reads. TF_VAR_alert_emails names who the
# alerts reach; it is supplied at apply time and never committed.

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
    key          = "environments/prod/ap-northeast-1/alarms/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-1/alarms"
  component   = "alarms"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# Route 53 publishes health check metrics only in us-east-1 (NFR-21's exception).
provider "aws" {
  alias               = "us_east_1"
  region              = "us-east-1"
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = merge(module.conventions.tags, { "region" = "us-east-1" })
  }
}

data "terraform_remote_state" "network" {
  backend = "s3"

  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/prod/ap-northeast-1/network/terraform.tfstate"
    region = module.conventions.region
  }
}

data "terraform_remote_state" "data" {
  backend = "s3"

  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/prod/ap-northeast-1/data/terraform.tfstate"
    region = module.conventions.region
  }
}

data "terraform_remote_state" "edge" {
  backend = "s3"

  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/prod/ap-northeast-1/edge/terraform.tfstate"
    region = module.conventions.region
  }
}

# Osaka's edge layer, in Osaka's state bucket: its health check, which this stack alarms on from us-east-1.
data "terraform_remote_state" "edge_osaka" {
  backend = "s3"

  config = {
    bucket = "sft-prod-apne3-tfstate-${var.account_id}"
    key    = "environments/prod/ap-northeast-3/edge/terraform.tfstate"
    region = "ap-northeast-3"
  }
}

locals {
  network = data.terraform_remote_state.network.outputs
  data    = data.terraform_remote_state.data.outputs
  edge    = data.terraform_remote_state.edge.outputs
}

module "alarms" {
  source = "../../../../modules/alarms"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment      = "prod"
  account_id       = var.account_id
  region           = module.conventions.region
  name_prefix      = module.conventions.name_prefix
  kms_alias_prefix = module.conventions.kms_alias_prefix
  platform_key_arn = local.data.kms_key_arns["platform"]
  deploy_role_arn  = module.conventions.bootstrap_role_arns.terraform_deploy
  alert_emails     = var.alert_emails

  # The synthetic probe's alarm (#248), once probe.enabled is true in this cluster's values file.
  probe_enabled = var.probe_enabled

  database = {
    cluster_identifier          = local.data.aurora_cluster_identifier
    role                        = "primary"
    freeable_memory_alarm_bytes = 1610612736 # 1536 MiB, about a tenth of db.r8g.large, 16 GiB
  }

  load_balancer_arn    = local.edge.load_balancer.arn
  api_target_group_arn = local.edge.api_target_group_arn
  vpc_id               = local.network.vpc_id

  # RTC replication to Osaka (modules/files-buckets): Osaka's names are Tokyo's with the Region swapped.
  replicated_buckets = {
    for kind, name in local.data.files_bucket_names : kind => {
      source      = name
      destination = replace(name, "-apne1-", "-apne3-")
    }
  }

  region_health = {
    health_checks = {
      "ap-northeast-1" = local.edge.health_check_id
      "ap-northeast-3" = data.terraform_remote_state.edge_osaka.outputs.health_check_id
    }
    plan_role_arn                      = module.conventions.bootstrap_role_arns.terraform_plan
    key_admin_role_arn                 = module.conventions.bootstrap_role_arns.key_admin
    break_glass_principal_arn_patterns = [module.conventions.sso_role_arn_patterns.break_glass]
    key_deletion_window_days           = 30 # prod's keys wait 30 days (encryption 8.3)
  }
}

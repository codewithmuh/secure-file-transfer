# staging in Osaka, alarms layer (#246). The AWS-side alarms of ADR-0009 and their topics (modules/alarms): the
# watchdog's heartbeat, Aurora, the queues, the load balancer, the NAT gateways, KMS, SES and the sign-in triggers.
# The pilot light (architecture 3.2): the heartbeat and API target alarms exist but don't notify until the failover
# runbook applies this stack with TF_VAR_heartbeat_enabled=true and TF_VAR_pilot_light=false. Tokyo's stack watches
# this Region's health check.
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
    key          = "environments/staging/ap-northeast-3/alarms/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-3/alarms"
  component   = "alarms"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# Route 53 publishes health check metrics only in us-east-1 (NFR-21's exception). Nothing is made there from Osaka.
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
    key    = "environments/staging/ap-northeast-3/network/terraform.tfstate"
    region = module.conventions.region
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

  conventions = module.conventions

  environment      = "staging"
  account_id       = var.account_id
  region           = module.conventions.region
  name_prefix      = module.conventions.name_prefix
  kms_alias_prefix = module.conventions.kms_alias_prefix
  platform_key_arn = local.data.kms_key_arns["platform"]
  deploy_role_arn  = module.conventions.bootstrap_role_arns.terraform_deploy
  alert_emails     = var.alert_emails

  # The synthetic probe's alarm (#248), once probe.enabled is true in this cluster's values file.
  probe_enabled = var.probe_enabled

  heartbeat_enabled = var.heartbeat_enabled
  pilot_light       = var.pilot_light

  database = {
    cluster_identifier          = local.data.aurora_cluster_identifier
    role                        = var.database_role
    freeable_memory_alarm_bytes = 1610612736 # 1536 MiB, about a tenth of the writer's after a failover
  }

  load_balancer_arn    = local.edge.load_balancer.arn
  api_target_group_arn = local.edge.api_target_group_arn
  vpc_id               = local.network.vpc_id
}

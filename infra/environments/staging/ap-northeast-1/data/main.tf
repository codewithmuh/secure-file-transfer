# staging in Tokyo, data layer. Stateful services: Aurora PostgreSQL, the files buckets, the queues, the rate-limit
# store and the environment's KMS keys (ADR-0011 to ADR-0014, ADR-0017). dev and staging also keep their audit archive
# here; prod keeps it in the retained stack (encryption 8.4).
#
# #101 fills this file, variables.tf and outputs.tf: Aurora, the counter store and the queues. #102 adds the keys and
# buckets in their own files.
#
# The primary of staging's global database, with a db.r8g.large writer and no reader (capacity 5.2), the counter store
# and the queues.

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
    key          = "environments/staging/ap-northeast-1/data/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-1/data"
  component   = "data"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# The network stack of this environment and Region (infra/modules/network/outputs.tf): its subnets and security
# groups. Its state is in the same bucket, under its directory's key (infra/README.md, "State").
data "terraform_remote_state" "network" {
  backend = "s3"

  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/staging/ap-northeast-1/network/terraform.tfstate"
    region = module.conventions.region
  }
}

locals {
  # The environment's keys (encryption 4.1). Until #102 merges they come in as a variable; then this line becomes
  # module.kms.key_arns, the keys module in kms.tf.
  kms_key_arns = var.kms_key_arns

  network             = data.terraform_remote_state.network.outputs
  isolated_subnet_ids = [for az in local.network.availability_zone_ids : local.network.isolated_subnet_ids[az]]

  # The data stores admit the main and scan node groups and nothing else (ADR-0021); network policies narrow them to
  # the workloads that use each store.
  data_store_clients = {
    main_nodes = local.network.security_group_ids.main_nodes
    scan_nodes = local.network.security_group_ids.scan_nodes
  }

  # Workload roles, named like their PostgreSQL login roles, at path / (encryption 4.3). The cluster layer creates
  # them after this stack, so policies here match them by ARN, never by an existing principal.
  role_arn_prefix = "arn:aws:iam::${var.account_id}:role/${module.conventions.global_name_prefix}-"
}

module "aurora" {
  source = "../../../../modules/aurora"

  name_prefix               = module.conventions.name_prefix
  cluster_role              = "primary"
  global_cluster_identifier = "sft-staging-aurora"
  engine_version            = "17.10"

  instance_class                 = "db.r8g.large"
  instance_availability_zone_ids = [local.network.availability_zone_ids[0]]

  vpc_id                    = local.network.vpc_id
  subnet_ids                = local.isolated_subnet_ids
  client_security_group_ids = local.data_store_clients

  kms_key_arn      = local.kms_key_arns.database
  logs_kms_key_arn = local.kms_key_arns.logs

  backup_retention_days = 14
  deletion_protection   = !var.teardown
  skip_final_snapshot   = var.teardown

  master_password_version = var.master_password_version
  master_secret = {
    name        = "sft/staging/db/master"
    kms_key_arn = local.kms_key_arns.secrets
    # The Osaka copy of the secrets key: a multi-Region replica has the primary's key ID (encryption 4.2).
    replica_kms_key_arn     = var.replicate_master_secret ? replace(local.kms_key_arns.secrets, ":ap-northeast-1:", ":ap-northeast-3:") : null
    reader_role_arn         = "${local.role_arn_prefix}db-bootstrap"
    break_glass_arn_like    = module.conventions.sso_role_arn_patterns.break_glass
    writer_role_arn         = module.conventions.bootstrap_role_arns.terraform_deploy
    recovery_window_in_days = var.teardown ? 0 : 7
  }
}

module "valkey" {
  source = "../../../../modules/valkey"

  name_prefix      = module.conventions.name_prefix
  user_name_prefix = module.conventions.global_name_prefix

  vpc_id                    = local.network.vpc_id
  subnet_ids                = local.isolated_subnet_ids
  client_security_group_ids = local.data_store_clients

  kms_key_arn = local.kms_key_arns.platform
}

module "queues" {
  source = "../../../../modules/queues"

  name_prefix = module.conventions.name_prefix
  kms_key_arn = local.kms_key_arns.platform

  senders = {
    relay_role_arn           = "${local.role_arn_prefix}relay"
    signin_trigger_role_arn  = "${local.role_arn_prefix}signin-trigger"
    events_delivery_role_arn = "${local.role_arn_prefix}events-delivery"
    ses_events_topic_arn     = "arn:aws:sns:${module.conventions.region}:${var.account_id}:${module.conventions.name_prefix}-ses-events"
  }
}

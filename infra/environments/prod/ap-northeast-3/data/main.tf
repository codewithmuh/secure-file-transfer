# prod in Osaka, data layer. Stateful services: Aurora PostgreSQL, the files buckets, the queues, the rate-limit
# store and the environment's KMS keys (ADR-0011 to ADR-0014, ADR-0017). dev and staging also keep their audit archive
# here; prod keeps it in the retained stack (encryption 8.4).
# In Osaka these are the pilot light's replicas: the Aurora secondary, replica buckets and key replicas
# (architecture 3.2).
#
# #101 fills this file, variables.tf and outputs.tf: Aurora, the counter store and the queues. #102 adds the keys and
# buckets in their own files.
#
# The pilot light's data: the secondary of prod's global database on one db.r8g.large until a drill shows Serverless
# v2 is enough (ADR-0011, capacity 4.5), and an idle counter store and queues.

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
    key          = "environments/prod/ap-northeast-3/data/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-3/data"
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
    key    = "environments/prod/ap-northeast-3/network/terraform.tfstate"
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
  cluster_role              = "secondary"
  global_cluster_identifier = "sft-prod-aurora"
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

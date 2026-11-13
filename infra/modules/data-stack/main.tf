# The data layer of one environment and Region (#101): Aurora, the counter store and the queues, wired to the network
# stack's subnets and security groups. Every data root calls this module once and passes only what differs between
# them: the cluster's role and size, its backups, the master secret's recovery window, and the inputs of the two-pass
# fresh build. #102 adds the keys and buckets (storage.tf); flow-logs.tf the VPC flow log's bucket. So a change to the
# layer is made here once, not in five roots. Providers, the backend and the conventions module stay
# in the roots (infra/README.md, "Add a stack or a module").

locals {
  environment = trimprefix(var.conventions.global_name_prefix, "sft-")
  region      = var.conventions.region

  network             = data.terraform_remote_state.network.outputs
  isolated_subnet_ids = [for az in local.network.availability_zone_ids : local.network.isolated_subnet_ids[az]]

  # The data stores admit the main and scan node groups and nothing else (ADR-0021); network policies narrow them to
  # the workloads that use each store.
  data_store_clients = {
    main_nodes = local.network.security_group_ids.main_nodes
    scan_nodes = local.network.security_group_ids.scan_nodes
  }

  # Workload roles, named like their PostgreSQL login roles, at path / (encryption 4.3), come from the conventions
  # module's one list (#172). The cluster layer creates them after this stack, so policies here match them by ARN,
  # never by an existing principal.

  standalone = var.aurora.cluster_role == "standalone"

  # The global database: sft-<env>-aurora, then sft-<env>-aurora-<n> for the one a failback after a detach makes from
  # Osaka's cluster (#261). Both data roots take the same generation.
  global_cluster_identifier = (
    var.aurora.global_generation == 1
    ? "${var.conventions.global_name_prefix}-aurora"
    : "${var.conventions.global_name_prefix}-aurora-${var.aurora.global_generation}"
  )
}

# The network stack of this environment and Region (infra/modules/network/outputs.tf). Its state is in the same
# bucket, under its directory's key (infra/README.md, "State").
data "terraform_remote_state" "network" {
  backend = "s3"

  config = {
    bucket = var.conventions.state_bucket_name
    key    = "environments/${local.environment}/${local.region}/network/terraform.tfstate"
    region = local.region
  }
}

module "aurora" {
  source = "../aurora"

  name_prefix               = var.conventions.name_prefix
  cluster_role              = var.aurora.cluster_role
  global_cluster_identifier = local.standalone ? null : local.global_cluster_identifier
  engine_version            = var.aurora.engine_version

  instance_class                 = var.aurora.instance_class
  serverless_capacity            = var.aurora.serverless_capacity
  instance_availability_zone_ids = slice(local.network.availability_zone_ids, 0, var.aurora.instance_count)

  vpc_id                    = local.network.vpc_id
  subnet_ids                = local.isolated_subnet_ids
  client_security_group_ids = local.data_store_clients

  kms_key_arn      = local.kms_key_arns["database"]
  logs_kms_key_arn = local.kms_key_arns["logs"]

  backup_retention_days = var.aurora.backup_retention_days
  deletion_protection   = !var.teardown
  skip_final_snapshot   = var.teardown

  # Osaka's secondary takes its master user from the primary, so it has no password or secret of its own. Tokyo keeps
  # the secret whatever its cluster's role, so a failback that makes Tokyo a secondary keeps it and its replica (#261).
  master_password_version = var.master_password_version
  master_secret = local.region == "ap-northeast-3" ? null : {
    name                    = "sft/${local.environment}/db/master"
    kms_key_arn             = local.kms_key_arns["secrets"]
    replica_kms_key_arn     = local.master_secret_replica_kms_key_arn
    reader_role_arn         = var.conventions.workload_role_arns["db-bootstrap"]
    break_glass_arn_like    = var.conventions.sso_role_arn_patterns.break_glass
    writer_role_arn         = var.conventions.bootstrap_role_arns.terraform_deploy
    recovery_window_in_days = var.teardown ? 0 : var.aurora.master_secret_recovery_window_days
  }
}

module "valkey" {
  source = "../valkey"

  name_prefix      = var.conventions.name_prefix
  user_name_prefix = var.conventions.global_name_prefix

  vpc_id                    = local.network.vpc_id
  subnet_ids                = local.isolated_subnet_ids
  client_security_group_ids = local.data_store_clients

  kms_key_arn = local.kms_key_arns["platform"]
}

module "queues" {
  source = "../queues"

  name_prefix = var.conventions.name_prefix
  kms_key_arn = local.kms_key_arns["platform"]

  senders = {
    relay_role_arn           = var.conventions.workload_role_arns["relay"]
    signin_trigger_role_arn  = var.conventions.workload_role_arns["signin-trigger"]
    events_delivery_role_arn = local.events_delivery_role_arn
    ses_events_topic_arn     = "arn:aws:sns:${local.region}:${var.account_id}:${var.conventions.name_prefix}-ses-events"
  }
}

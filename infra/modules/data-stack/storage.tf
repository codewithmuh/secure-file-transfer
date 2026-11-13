# Storage and keys (#102, ADR-0012, ADR-0017, ADR-0019): the environment's KMS keys, the files and large-files
# buckets, the audit archive in dev and staging (prod keeps it in the retained stack, encryption 8.4), EventBridge's
# delivery role and the account's EBS default key. Like the rest of this module, every data root gets them from here,
# and what differs between roots follows from the environment and Region: Tokyo makes the key primaries and the IAM
# roles, Osaka the key replicas and the replica buckets, and prod has the longer deletion wait and no teardown rights
# until its teardown apply.

locals {
  tokyo = local.region == "ap-northeast-1"
  prod  = local.environment == "prod"

  # dev runs in Tokyo only (capacity 5.3); staging and prod have the Osaka pilot light (architecture 3.2).
  with_osaka = local.environment != "dev"

  # prod's audit key and archive belong to the retained stack, which outlives teardown (encryption 8.4).
  archive_here = !local.prod
  key_classes = setsubtract(
    ["files", "fields", "database", "audit", "logs", "secrets", "platform"],
    local.archive_here ? [] : ["audit"],
  )

  # dev and staging tear down; prod never does (NFR-19, encryption 8.3).
  teardown_allowed = !local.prod

  # Tokyo replicates to Osaka once Osaka's buckets and key replicas exist (infra/README.md, "Apply order").
  replicate_to_osaka = local.tokyo && local.with_osaka && var.osaka_ready

  admin_patterns       = [var.conventions.sso_role_arn_patterns.admin]
  break_glass_patterns = [var.conventions.sso_role_arn_patterns.break_glass]

  # The keys the stores in main.tf use. In Osaka, the replicas.
  kms_key_arns = module.kms.key_arns

  # The master secret's Osaka replica takes Osaka's replica of the secrets key, which keeps the Tokyo key's ID
  # (encryption 4.2). Tokyo in staging and prod only, and only once that replica exists.
  master_secret_replica_kms_key_arn = (
    local.replicate_to_osaka && !local.standalone ? module.kms.osaka_key_arns["secrets"] : null
  )

  # sft-<env>-events-delivery. The queues module admits it as the only sender to the queues it delivers to, and the
  # role may send to exactly those queues (encryption 4.4, modules/queues).
  events_delivery_role_arn = var.conventions.workload_role_arns["events-delivery"]
}

# The service-linked roles that create EBS volumes under the platform and files keys: Auto Scaling for the system node
# group, EC2 Fleet for Karpenter's launches. Both keys' policies name them as principals (encryption 4.4), and KMS
# refuses a policy that names a role that doesn't exist, so they are made here, before the keys, rather than by AWS
# on the cluster layer's first launch. IAM is global, so Tokyo's stack makes them; Osaka's runs after it. An account
# that already has one needs `terraform import` of it before the first apply (infra/README.md, "Apply order").
resource "aws_iam_service_linked_role" "volumes" {
  for_each = local.tokyo ? {
    autoscaling = "autoscaling.amazonaws.com"
    ec2_fleet   = "ec2fleet.amazonaws.com"
  } : {}

  aws_service_name = each.value
}

module "kms" {
  source = "../kms-keys"

  environment      = local.environment
  account_id       = var.account_id
  conventions      = var.conventions
  classes          = local.key_classes
  primary_key_arns = var.primary_key_arns
  osaka_replicas   = local.tokyo && local.with_osaka

  deletion_window_in_days            = local.prod ? 30 : 7
  deploy_role_arn                    = var.conventions.bootstrap_role_arns.terraform_deploy
  plan_role_arn                      = var.conventions.bootstrap_role_arns.terraform_plan
  key_admin_role_arn                 = var.conventions.bootstrap_role_arns.key_admin
  break_glass_principal_arn_patterns = local.break_glass_patterns

  # From the resources in Tokyo, so the roles exist before the key policies name them; built from the names in Osaka.
  volume_service_linked_role_arns = local.tokyo ? {
    autoscaling = aws_iam_service_linked_role.volumes["autoscaling"].arn
    ec2_fleet   = aws_iam_service_linked_role.volumes["ec2_fleet"].arn
  } : null
}

# EBS encryption by default under the platform key, for the account in this Region (encryption 3.1): the system
# nodes' and the main pool's root volumes and the observability volumes name no key of their own (modules/eks-cluster;
# the scan pool's name the files key). SCP 3 keeps it on for everyone but the apply roles.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  key_arn = module.kms.key_arns["platform"]
}

# IAM is global, so Tokyo's stack makes the role for both Regions.
module "events_delivery" {
  source = "../events-delivery-role"
  count  = local.tokyo ? 1 : 0

  account_id  = var.account_id
  conventions = var.conventions
  regions     = local.with_osaka ? ["ap-northeast-1", "ap-northeast-3"] : ["ap-northeast-1"]

  permissions_boundary_arn = "arn:aws:iam::${var.account_id}:policy${var.conventions.bootstrap_iam_path}${var.conventions.global_name_prefix}-workload-boundary"
  # The queues that name it as their one sender (modules/queues), and Karpenter's interruption queue, which the
  # cluster layer makes in each Region with the same rule (modules/eks-cluster, #103).
  queue_names = concat(
    module.queues.queue_names_by_sender_role[local.events_delivery_role_arn],
    ["karpenter-interruption"],
  )
  platform_key_arns = compact([
    module.kms.key_arns["platform"],
    lookup(module.kms.osaka_key_arns, "platform", null),
  ])
}

module "files_buckets" {
  source = "../files-buckets"

  environment = local.environment
  account_id  = var.account_id
  conventions = var.conventions
  kms_key_arn = module.kms.key_arns["files"]

  with_osaka         = local.with_osaka
  create_iam_roles   = local.tokyo
  osaka_kms_key_arn  = local.tokyo ? lookup(module.kms.osaka_key_arns, "files", null) : null
  replicate_to_osaka = local.replicate_to_osaka
  replicate_to_tokyo = !local.tokyo && var.replicate_to_tokyo
  # prod's files buckets too, from its teardown apply on (#263, #42 gap 11): never while prod runs.
  teardown_allowed = local.teardown_allowed || var.teardown

  # On in Tokyo. In Osaka no plan in the pilot light; the failover runbook's apply creates it (ADR-0019).
  malware_protection_enabled = local.tokyo || var.osaka_malware_protection_enabled

  deploy_role_arn                    = var.conventions.bootstrap_role_arns.terraform_deploy
  admin_principal_arn_patterns       = local.admin_patterns
  break_glass_principal_arn_patterns = local.break_glass_patterns
}

module "audit_archive" {
  source = "../audit-archive"
  count  = local.archive_here ? 1 : 0

  account_id  = var.account_id
  conventions = var.conventions
  kms_key_arn = module.kms.key_arns["audit"]

  # Governance mode for a day, so the environment can be torn down (encryption 3.1, NFR-15).
  object_lock_mode = "GOVERNANCE"
  object_lock_days = 1
  teardown_allowed = local.teardown_allowed

  with_osaka            = local.with_osaka
  osaka_kms_key_arn     = local.tokyo ? lookup(module.kms.osaka_key_arns, "audit", null) : null
  replication_role_name = local.tokyo ? module.files_buckets.replication_role_name : null
  replicate_to_osaka    = local.replicate_to_osaka

  deploy_role_arn                    = var.conventions.bootstrap_role_arns.terraform_deploy
  admin_principal_arn_patterns       = local.admin_patterns
  break_glass_principal_arn_patterns = local.break_glass_patterns
}

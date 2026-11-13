# The prod audit archive and its key, which outlive teardown (#102, NFR-19, encryption 8.4, ADR-0012, ADR-0017).
#
# - The audit key is a multi-Region primary in Tokyo with a replica in Osaka, both with prevent_destroy and the
#   30-day deletion wait. Only this stack's own deploy role may disable or delete it; Admin also administers it,
#   because this stack's first apply runs with Admin from local state (ADR-0005). While prod runs the key-admin role
#   may repair its policy; teardown's first step removes it (8.4).
# - The archive buckets, Object Lock in compliance mode for 365 days, prevent_destroy, replicate Tokyo to Osaka through
#   this stack's own replication role. The Osaka bucket is made first, because S3 needs the destination to exist.
# - SCP 5 lets only this stack's deploy role and Admin change the buckets' guards.
#
# The deploy role, sft-prod-retained-terraform-deploy under /sft-bootstrap/, is made in deploy-role.tf; the key and
# bucket policies match it by ARN, so they don't need it to exist first.

locals {
  retained_deploy_role_arn = "arn:aws:iam::${var.account_id}:role${module.conventions.bootstrap_iam_path}sft-prod-retained-terraform-deploy"
  retained_replication     = "sft-prod-retained-s3-replication"
  admin_patterns           = [module.conventions.sso_role_arn_patterns.admin]
  break_glass_patterns     = [module.conventions.sso_role_arn_patterns.break_glass]

  # The key-admin role may repair the audit key's policy while prod runs; the teardown apply takes it out, because the
  # bootstrap stack's destroy removes the role and KMS refuses a policy that names a role that no longer exists (8.4).
  key_admin_role_arn = var.teardown ? null : module.conventions.bootstrap_role_arns.key_admin
}

module "audit_key" {
  source = "../../../modules/kms-keys"

  conventions = module.conventions

  environment    = "prod"
  account_id     = var.account_id
  classes        = ["audit"]
  osaka_replicas = true

  deletion_window_in_days            = 30
  prevent_destroy                    = true
  retained_stack                     = true
  deploy_role_arn                    = local.retained_deploy_role_arn
  extra_administrator_arn_patterns   = local.admin_patterns
  plan_role_arn                      = module.conventions.bootstrap_role_arns.terraform_plan
  key_admin_role_arn                 = local.key_admin_role_arn
  break_glass_principal_arn_patterns = local.break_glass_patterns
  replication_role_name              = local.retained_replication

  # From the teardown apply on: the environment's workload roles leave the key policy, and rotation stops (8.4, #263).
  environment_retired = var.teardown
}

module "audit_key_osaka" {
  source = "../../../modules/kms-keys"

  providers = {
    aws = aws.osaka
  }

  conventions = module.conventions

  environment      = "prod"
  account_id       = var.account_id
  classes          = ["audit"]
  primary_key_arns = module.audit_key.key_arns

  deletion_window_in_days            = 30
  prevent_destroy                    = true
  retained_stack                     = true
  deploy_role_arn                    = local.retained_deploy_role_arn
  extra_administrator_arn_patterns   = local.admin_patterns
  plan_role_arn                      = module.conventions.bootstrap_role_arns.terraform_plan
  key_admin_role_arn                 = local.key_admin_role_arn
  break_glass_principal_arn_patterns = local.break_glass_patterns
  replication_role_name              = local.retained_replication

  # From the teardown apply on: the environment's workload roles leave the key policy, and rotation stops (8.4, #263).
  environment_retired = var.teardown
}

module "audit_archive_osaka" {
  source = "../../../modules/audit-archive"

  providers = {
    aws = aws.osaka
  }

  conventions = module.conventions

  account_id  = var.account_id
  kms_key_arn = module.audit_key_osaka.key_arns["audit"]

  object_lock_mode      = "COMPLIANCE"
  object_lock_days      = 365
  teardown_allowed      = false
  prevent_destroy       = true
  with_osaka            = true
  replication_role_name = local.retained_replication

  deploy_role_arn                    = local.retained_deploy_role_arn
  admin_principal_arn_patterns       = local.admin_patterns
  break_glass_principal_arn_patterns = local.break_glass_patterns

  # From the teardown apply on: the environment's workload roles leave the bucket policy (8.4, #263).
  environment_retired = var.teardown
}

module "audit_archive" {
  source = "../../../modules/audit-archive"

  conventions = module.conventions

  account_id  = var.account_id
  kms_key_arn = module.audit_key.key_arns["audit"]

  object_lock_mode = "COMPLIANCE"
  object_lock_days = 365
  teardown_allowed = false
  prevent_destroy  = true

  with_osaka              = true
  osaka_kms_key_arn       = module.audit_key_osaka.key_arns["audit"]
  replicate_to_osaka      = true
  create_replication_role = true
  replication_role_name   = local.retained_replication

  deploy_role_arn                    = local.retained_deploy_role_arn
  admin_principal_arn_patterns       = local.admin_patterns
  break_glass_principal_arn_patterns = local.break_glass_patterns

  # From the teardown apply on: the environment's workload roles leave the bucket policy (8.4, #263).
  environment_retired = var.teardown

  depends_on = [module.audit_archive_osaka]
}

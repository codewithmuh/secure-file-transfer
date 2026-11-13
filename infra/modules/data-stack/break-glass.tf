# The break-glass database role and its alert (FR-35, authn-authz 8.3, #232; modules/break-glass-role). It names this
# Region's cluster, so it lives with Aurora. Tokyo creates the role, IAM being global; each Region adds the connect
# policy for its own cluster and the rule and topic that page on every assumption there.

module "break_glass_role" {
  source = "../break-glass-role"

  environment = local.environment
  account_id  = var.account_id
  conventions = var.conventions
  region      = local.region
  regions     = local.with_osaka ? ["ap-northeast-1", "ap-northeast-3"] : ["ap-northeast-1"]
  create_role = local.tokyo

  break_glass_principal_arn_patterns = local.break_glass_patterns
  cluster_resource_id                = module.aurora.cluster_resource_id

  platform_key_arn         = module.kms.key_arns["platform"]
  events_delivery_role_arn = local.events_delivery_role_arn
  deploy_role_arn          = var.conventions.bootstrap_role_arns.terraform_deploy
}

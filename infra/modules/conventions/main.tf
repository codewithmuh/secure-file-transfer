# Naming and tagging conventions (infra/README.md). Every root calls this module once and passes its tags to the AWS
# provider's default_tags, so every stack, Tokyo and Osaka alike, names and tags resources with the same code (T-79).
# It creates nothing and calls no AWS API.

locals {
  # Short Region codes in names, for every Region the service runs in (NFR-21). This is the one definition: modules
  # read it from their caller's conventions (region_shorts), never from a copy of their own (#172).
  region_shorts = {
    "ap-northeast-1" = "apne1"
    "ap-northeast-3" = "apne3"
  }
  region_short = local.region_shorts[var.region]

  # Regional resources: sft-<env>-<region-short>-<thing>. Global resources (IAM): sft-<env>-<thing>.
  name_prefix        = "sft-${var.environment}-${local.region_short}"
  global_name_prefix = "sft-${var.environment}"

  github_repository = "codewithmuh/secure-file-transfer"

  # An environment's workload roles: sft-<env>-<name> at path "/", by the layer that makes each (encryption 4.3,
  # authn-authz). The key, bucket and queue policies name them before they exist, matched by aws:PrincipalArn, so a
  # role renamed or added in one copy and missed in another would silently drop a grant. This is the one list: the
  # cluster layer makes its roles from it, the deploy role may create exactly those, and the policies name them from
  # it (#172).
  workload_roles = {
    # modules/eks-cluster, Tokyo's cluster stack.
    cluster = [
      "eks-cluster", "system-node", "karpenter-node", "karpenter", "vpc-cni", "ebs-csi", "lb-controller",
      "external-secrets", "kyverno", "api", "relay", "scan", "notify", "jobs", "archive", "migrate", "operator",
      "external-secrets-platform", "external-secrets-app", "key-rotation", "synthetic-probe", "recovery",
    ]
    # modules/files-buckets and modules/events-delivery-role, Tokyo's data stack.
    data = ["s3-replication", "s3-batch-replication", "malware-protection", "events-delivery"]
    # Tokyo's identity stack: modules/signin-triggers, and in staging modules/probe-mailbox's load test role (#259).
    identity = ["signin-trigger", "loadtest"]
    # modules/observability, Tokyo's cluster-bootstrap stack.
    cluster_bootstrap = ["loki", "tempo", "alertmanager", "cloudwatch-exporter"]
    # Named by the key policies for the job that will use it (encryption 4.3); no layer makes it yet.
    planned = ["db-bootstrap"]
  }
  workload_role_names = {
    for name in flatten(values(local.workload_roles)) : name => "${local.global_name_prefix}-${name}"
  }

  # Roles the bootstrap stacks create. Only the Admin permission set may change roles under this path (ADR-0006, T-71).
  bootstrap_iam_path = "/sft-bootstrap/"
  bootstrap_role_names = {
    terraform_plan   = "${local.global_name_prefix}-terraform-plan"
    terraform_deploy = "${local.global_name_prefix}-terraform-deploy"
    key_admin        = "${local.global_name_prefix}-keyadmin"
  }

  # The account's emergency IAM user, for when Identity Center can't be reached (authn-authz 8.4). Bucket and key
  # policies and the SCPs name it exactly, never by a pattern, so no other user can match it; only Admin may create
  # or change IAM users (SCP 4).
  emergency_user = {
    name = "${local.global_name_prefix}-emergency"
    path = "/sft-emergency/"
  }

  # IAM Identity Center creates one role per permission set in each account, named AWSReservedSSO_<set>_<suffix>,
  # under /aws-reserved/sso.amazonaws.com/ (with the Identity Center Region in the path outside us-east-1).
  sso_role_arn_prefix = "arn:aws:iam::${var.account_id}:role/aws-reserved/sso.amazonaws.com/"

  tags = merge(
    {
      "project"     = "secure-file-transfer"
      "environment" = var.environment
      "region"      = var.region
      "stack"       = var.stack
      "component"   = var.component
      "managed-by"  = "terraform"
      "repository"  = local.github_repository
    },
    var.extra_tags,
  )
}

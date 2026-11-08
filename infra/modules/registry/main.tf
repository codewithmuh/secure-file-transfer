# The container registry in the shared account (ADR-0007, encryption 3.1 and 4.4, capacity 5.4): the registry key,
# the repositories, their pull policy for the environments' node roles, the lifecycle rules, the push role for the
# build workflow and, once staging exists, replication to Osaka.
#
# - Tags are immutable, except cosign's fallback tags (sha256-<digest>.sig and .att), which a re-sign rewrites.
#   Builds are tagged with their Git SHA and deployed by digest.
# - Every repository is encrypted with the registry key. A repository's encryption can't change after creation, so
#   it never uses an environment's key, which goes away with that environment.
# - Node roles in dev, staging and prod pull, Kyverno's roles read signatures, and both use the key only through ECR.
#   Nothing else in another account may.
# - Basic scanning on push. Our own gate is Trivy in the build and the scheduled re-scan (NFR-13); ECR's findings are
#   a second opinion that costs nothing.

data "aws_region" "current" {}

locals {
  region       = data.aws_region.current.region
  account_root = "arn:aws:iam::${var.account_id}:root"
  ecr_service  = "ecr.${local.region}.amazonaws.com"
  osaka        = "ap-northeast-3"

  # The node roles the cluster stacks create (#103): the system node group's and Karpenter's, one each per account,
  # used by Tokyo's and Osaka's clusters alike.
  node_role_arns = flatten([
    for env, account in var.member_account_ids : [
      "arn:aws:iam::${account}:role/sft-${env}-system-node",
      "arn:aws:iam::${account}:role/sft-${env}-karpenter-node",
    ]
  ])
  member_account_roots = [for account in values(var.member_account_ids) : "arn:aws:iam::${account}:root"]

  # Kyverno's role in each cluster (#103, #104), which reads signatures and attestations to admit an image.
  kyverno_role_arns = [for env, account in var.member_account_ids : "arn:aws:iam::${account}:role/sft-${env}-kyverno"]

  # The Cognito sign-in triggers' role and functions in each account (#238): Lambda pulls sft/app for them.
  signin_trigger_role_arns = [for env, account in var.member_account_ids : "arn:aws:iam::${account}:role/sft-${env}-signin-trigger"]
  signin_trigger_functions = [for env, account in var.member_account_ids : "arn:aws:lambda:*:${account}:function:sft-${env}-*-signin-trigger"]

  repositories = merge(
    { (var.app_repository) = { lifecycle = true } },
    { for name in var.mirror_repositories : "mirror/${name}" => { lifecycle = false } },
  )

  pull_actions = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
}

# --- Registry key ------------------------------------------------------------------------------------------------

# Who uses the key besides Terraform: ECR, for the repositories' grants; the node roles, to decrypt pulls; the push
# role, to encrypt pushes. All of them only through ECR.
data "aws_iam_policy_document" "key_use" {
  for_each = toset(compact([local.region, var.replicate_to_osaka ? local.osaka : ""]))

  statement {
    sid       = "DeployRoleLetsEcrUseTheKey"
    actions   = ["kms:CreateGrant", "kms:RetireGrant", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.deploy_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ecr.${each.key}.amazonaws.com"]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  statement {
    sid       = "PushRoleUsesTheKeyThroughEcr"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.push.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ecr.${each.key}.amazonaws.com"]
    }
  }

  dynamic "statement" {
    for_each = length(local.node_role_arns) == 0 ? [] : [1]

    content {
      sid       = "NodeAndKyvernoRolesDecryptThroughEcr"
      actions   = ["kms:Decrypt"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = local.member_account_roots
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = concat(local.node_role_arns, local.kyverno_role_arns, local.signin_trigger_role_arns)
      }

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["ecr.${each.key}.amazonaws.com"]
      }
    }
  }
}

module "key_policy" {
  source   = "../key-policy"
  for_each = data.aws_iam_policy_document.key_use

  account_id                         = var.account_id
  deploy_role_arn                    = var.deploy_role_arn
  plan_role_arn                      = var.plan_role_arn
  key_admin_role_arn                 = var.key_admin_role_arn
  break_glass_principal_arn_patterns = var.break_glass_principal_arn_patterns
  additional_policy_documents        = [each.value.json]
}

resource "aws_kms_key" "registry" {
  description             = "Container images in the shared registry (ADR-0007)"
  multi_region            = true
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = module.key_policy[local.region].json
}

resource "aws_kms_alias" "registry" {
  name          = "${var.kms_alias_prefix}/registry"
  target_key_id = aws_kms_key.registry.key_id
}

resource "aws_kms_replica_key" "registry_osaka" {
  count    = var.replicate_to_osaka ? 1 : 0
  provider = aws.osaka

  description             = "Container images in the shared registry, Osaka replicas (ADR-0007)"
  primary_key_arn         = aws_kms_key.registry.arn
  deletion_window_in_days = 30
  policy                  = module.key_policy[local.osaka].json
}

resource "aws_kms_alias" "registry_osaka" {
  count    = var.replicate_to_osaka ? 1 : 0
  provider = aws.osaka

  name          = "${var.kms_alias_prefix}/registry"
  target_key_id = aws_kms_replica_key.registry_osaka[0].key_id
}

# --- Repositories ------------------------------------------------------------------------------------------------

resource "aws_ecr_repository" "this" {
  for_each = local.repositories

  name                 = each.key
  image_tag_mutability = "IMMUTABLE_WITH_EXCLUSION"

  # cosign stores signatures and attestations as OCI referrers, but may fall back to sha256-<digest>.sig and .att
  # tags, which a re-sign must be able to replace (#107).
  image_tag_mutability_exclusion_filter {
    filter      = "sha256-*"
    filter_type = "WILDCARD"
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.registry.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_registry_scanning_configuration" "this" {
  scan_type = "BASIC"

  rule {
    scan_frequency = "SCAN_ON_PUSH"

    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}

# Pulls from the environments' node roles, and signature reads from their Kyverno roles, only. The principals are the member accounts, narrowed to the node roles by
# ARN, because ECR refuses a policy that names a role that doesn't exist yet, and the clusters come after this stack.
data "aws_iam_policy_document" "pull" {
  count = length(local.node_role_arns) == 0 ? 0 : 1

  statement {
    sid     = "NodeRolesPull"
    actions = local.pull_actions

    principals {
      type        = "AWS"
      identifiers = local.member_account_roots
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.node_role_arns
    }
  }

  statement {
    sid     = "KyvernoReadsSignatures"
    actions = concat(local.pull_actions, ["ecr:DescribeImages", "ecr:ListImages"])

    principals {
      type        = "AWS"
      identifiers = local.member_account_roots
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.kyverno_role_arns
    }
  }

  # The sign-in triggers' Lambda functions (#238) run sft/app from this registry: Lambda pulls the image for a
  # function of ours in a member account, and the account pulls for its trigger role. Cross-account container
  # images need both statements; running it is pending the AWS run.
  statement {
    sid     = "SignInTriggerFunctionsPull"
    actions = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = local.signin_trigger_functions
    }
  }

  statement {
    sid     = "SignInTriggerRolesPull"
    actions = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]

    principals {
      type        = "AWS"
      identifiers = local.member_account_roots
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.signin_trigger_role_arns
    }
  }
}

resource "aws_ecr_repository_policy" "pull" {
  for_each = length(local.node_role_arns) == 0 ? {} : aws_ecr_repository.this

  repository = each.value.name
  policy     = data.aws_iam_policy_document.pull[0].json
}

# ADR-0007: the promotion job tags every digest it deploys deployed-<git-sha>. ECR applies rules by priority, and an
# image a higher rule selects can never be expired by a lower one, so:
#
# 1. Every deployed-* image is selected by a count no repository reaches, so it never expires.
# 2. So is every sha256-* tag: cosign's fallback signatures and attestations (sha256-<digest>.sig and .att), which a
#    deployed image needs as long as it is kept. They are small; one per build is never deleted, an accepted cost.
# 3. Tagged builds beyond the newest 30 expire (A40): built and tagged with their Git SHA, never deployed.
#
# Nothing selects untagged images. cosign v3 stores signatures as untagged OCI referrers, and ECR documents only that
# it expires a referrer within 24 hours of its subject (the user guide's "Lifecycle policy evaluation rules"), not
# that an untagged rule skips referrers of kept images; an untagged or tagStatus any rule could expire a deployed
# image's signature, and Kyverno would then refuse it. The SBOM and provenance are children of the image index, kept
# with it. So a build that failed its scan, pushed by digest and never tagged, stays until someone deletes it by hand
# (rare: one per failed build). Mirror repositories have no rule: they keep every digest that Git pins.
resource "aws_ecr_lifecycle_policy" "app" {
  for_each = { for name, repository in local.repositories : name => repository if repository.lifecycle }

  repository = aws_ecr_repository.this[each.key].name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep every image an environment has deployed"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["deployed-"]
          countType     = "imageCountMoreThan"
          countNumber   = 1000000
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep cosign fallback signatures and attestations"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["sha256-"]
          countType     = "imageCountMoreThan"
          countNumber   = 1000000
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 3
        description  = "Expire tagged builds never deployed, beyond the newest 30"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "imageCountMoreThan"
          countNumber    = var.undeployed_images_kept
        }
        action = { type = "expire" }
      },
    ]
  })
}

# --- Osaka -------------------------------------------------------------------------------------------------------

# Every repository replicates to Osaka once staging exists, for the pilot light and its drills (architecture 3.2).
# Signatures and SBOMs live in the same repositories and replicate with the images.
resource "aws_ecr_replication_configuration" "osaka" {
  count = var.replicate_to_osaka ? 1 : 0

  replication_configuration {
    rule {
      destination {
        region      = local.osaka
        registry_id = var.account_id
      }
    }
  }
}

# Replicas are created by ECR in Osaka; this template gives them the Osaka copy of the registry key, the same
# immutability and the same pull policy.
resource "aws_ecr_repository_creation_template" "osaka" {
  count    = var.replicate_to_osaka ? 1 : 0
  provider = aws.osaka

  prefix               = "ROOT"
  description          = "Replicas of the Tokyo repositories (ADR-0007)"
  applied_for          = ["REPLICATION"]
  image_tag_mutability = "IMMUTABLE_WITH_EXCLUSION"

  image_tag_mutability_exclusion_filter {
    filter      = "sha256-*"
    filter_type = "WILDCARD"
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_replica_key.registry_osaka[0].arn
  }

  repository_policy = one(data.aws_iam_policy_document.pull[*].json)
}

# --- Push role ---------------------------------------------------------------------------------------------------

# The build and promotion workflows (#107) push sft/* images and add deployed-* tags through this role. It trusts only
# jobs in the registry GitHub environment, which accepts deployments from main only, so neither a pull request nor a
# job on main without that environment can push (T-71). Third-party mirrors get their own role, limited to mirror/*,
# when the mirror workflow arrives, so a compromised build can't rewrite a mirrored image.
data "aws_iam_policy_document" "push_trust" {
  statement {
    sid     = "RegistryEnvironmentOfThisRepository"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:${var.push_github_environment}"]
    }
  }
}

resource "aws_iam_role" "push" {
  name                 = var.push_role_name
  path                 = var.iam_path
  description          = "Pushes sft/* images from the ${var.push_github_environment} environment of ${var.github_repository}."
  assume_role_policy   = data.aws_iam_policy_document.push_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "push" {
  statement {
    sid       = "SignIn"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "PushAndTagOurImagesOnly"
    actions = concat(local.pull_actions, [
      "ecr:CompleteLayerUpload", "ecr:DescribeImages", "ecr:InitiateLayerUpload", "ecr:PutImage",
      "ecr:UploadLayerPart",
    ])
    resources = ["arn:aws:ecr:${local.region}:${var.account_id}:repository/${split("/", var.app_repository)[0]}/*"]
  }

  statement {
    sid       = "UseTheRegistryKeyThroughEcr"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.registry.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.ecr_service]
    }
  }
}

resource "aws_iam_role_policy" "push" {
  name   = "push"
  role   = aws_iam_role.push.id
  policy = data.aws_iam_policy_document.push.json
}

# ---------------------------------------------------------------------------------------------------------------------
# Data layer, stores (#101): what modules/aurora, modules/valkey and modules/queues need in the data stacks. The data
# layer exists exactly where the network does, so these use var.network_regions. The plan role reads; the deploy role
# also creates, changes and deletes. The keys and buckets (#102) need permissions of their own, in a file of their own.
#
# Managed policies under /sft-bootstrap/, not inline ones: the inline policies of a role share 10,240 characters,
# which the network layer already uses most of (infra/README.md, "Layer permissions"). SCP 4 lets only Admin change
# what is under that path, so these change only through an Admin apply of the account's bootstrap stack.
#
# Scoped like the network layer: Describe and List calls take no resource, so they are limited by Region; everything
# else names resources in this account and these Regions whose names start with sft-; deletes also need the
# managed-by and project tags that every provider adds. The data layer's security groups use the network layer's EC2
# permissions, which cover security groups in this account. The deploy role uses the environment's keys only through
# these services (kms:ViaService); the keys and their policies come with #102.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  data_arns = {
    rds = flatten([
      for region in var.network_regions : [
        for type in ["cluster", "db", "subgrp", "cluster-pg", "cluster-snapshot"] :
        "arn:aws:rds:${region}:${var.account_id}:${type}:sft-*"
      ]
    ])
    # Global clusters have no Region in their ARN.
    rds_global = ["arn:aws:rds::${var.account_id}:global-cluster:sft-*"]
    # An Aurora instance is created with the default instance parameter and option groups.
    rds_defaults = flatten([
      for region in var.network_regions : [
        "arn:aws:rds:${region}:${var.account_id}:pg:default.*",
        "arn:aws:rds:${region}:${var.account_id}:og:default:*",
      ]
    ])
    elasticache = flatten([
      for region in var.network_regions : [
        for type in ["serverlesscache", "user", "usergroup"] :
        "arn:aws:elasticache:${region}:${var.account_id}:${type}:sft-*"
      ]
    ])
    sqs = [for region in var.network_regions : "arn:aws:sqs:${region}:${var.account_id}:sft-*"]
    # sft/<env>/db/master and its replica; Secrets Manager adds a random suffix to the name.
    secrets  = [for region in var.network_regions : "arn:aws:secretsmanager:${region}:${var.account_id}:secret:sft/*/db/*"]
    logs     = [for region in var.network_regions : "arn:aws:logs:${region}:${var.account_id}:log-group:/aws/rds/cluster/sft-*"]
    kms_keys = [for region in var.network_regions : "arn:aws:kms:${region}:${var.account_id}:key/*"]
  }

  data_kms_via_services = flatten([
    for region in var.network_regions : [
      for service in ["rds", "elasticache", "secretsmanager", "sqs"] : "${service}.${region}.amazonaws.com"
    ]
  ])

  data_delete_tag_conditions = {
    "aws:ResourceTag/managed-by" = "terraform"
    "aws:ResourceTag/project"    = "secure-file-transfer"
  }
}

data "aws_iam_policy_document" "data_read" {
  count = local.network_enabled ? 1 : 0

  statement {
    sid = "DataDescribe"
    actions = [
      "elasticache:DescribeServerlessCaches",
      "elasticache:DescribeUserGroups",
      "elasticache:DescribeUsers",
      "logs:DescribeLogGroups",
      "rds:DescribeDBClusterParameterGroups",
      "rds:DescribeDBClusterParameters",
      "rds:DescribeDBClusters",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSubnetGroups",
      "rds:DescribeGlobalClusters",
      # The ephemeral master password opens during plans too (modules/aurora).
      "secretsmanager:GetRandomPassword",
      "sqs:ListQueues",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid       = "DataReadTags"
    actions   = ["elasticache:ListTagsForResource", "rds:ListTagsForResource"]
    resources = concat(local.data_arns.rds, local.data_arns.rds_global, local.data_arns.elasticache)
  }

  statement {
    sid       = "QueuesRead"
    actions   = ["sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ListQueueTags"]
    resources = local.data_arns.sqs
  }

  # Never GetSecretValue: with write-only values the provider reads the version list, not the value (encryption 6.4).
  statement {
    sid       = "MasterSecretMetadata"
    actions   = ["secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy", "secretsmanager:ListSecretVersionIds"]
    resources = local.data_arns.secrets
  }

  statement {
    sid       = "DatabaseLogGroupRead"
    actions   = ["logs:GetDataProtectionPolicy", "logs:ListTagsForResource"]
    resources = local.data_arns.logs
  }
}

data "aws_iam_policy_document" "data_deploy" {
  count = local.network_enabled ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.data_read[0].json]

  statement {
    sid = "DatabaseCreateAndChange"
    actions = [
      "rds:AddTagsToResource",
      "rds:CreateDBCluster",
      "rds:CreateDBClusterParameterGroup",
      "rds:CreateDBInstance",
      "rds:CreateDBSubnetGroup",
      "rds:CreateGlobalCluster",
      "rds:ModifyDBCluster",
      "rds:ModifyDBClusterParameterGroup",
      "rds:ModifyDBInstance",
      "rds:ModifyDBSubnetGroup",
      "rds:ModifyGlobalCluster",
      "rds:RemoveTagsFromResource",
    ]
    resources = concat(local.data_arns.rds, local.data_arns.rds_global)
  }

  statement {
    sid       = "DatabaseInstanceDefaults"
    actions   = ["rds:CreateDBInstance"]
    resources = local.data_arns.rds_defaults
  }

  # A final snapshot is taken on delete unless the teardown apply skipped it.
  statement {
    sid = "DatabaseDeleteOwn"
    actions = [
      "rds:CreateDBClusterSnapshot",
      "rds:DeleteDBCluster",
      "rds:DeleteDBClusterParameterGroup",
      "rds:DeleteDBInstance",
      "rds:DeleteDBSubnetGroup",
      "rds:DeleteGlobalCluster",
      "rds:RemoveFromGlobalCluster",
    ]
    resources = concat(local.data_arns.rds, local.data_arns.rds_global)

    dynamic "condition" {
      for_each = local.data_delete_tag_conditions

      content {
        test     = "StringEquals"
        variable = condition.key
        values   = [condition.value]
      }
    }
  }

  statement {
    sid = "CounterStoreCreateAndChange"
    actions = [
      "elasticache:AddTagsToResource",
      "elasticache:CreateServerlessCache",
      "elasticache:CreateUser",
      "elasticache:CreateUserGroup",
      "elasticache:ModifyServerlessCache",
      "elasticache:ModifyUser",
      "elasticache:ModifyUserGroup",
      "elasticache:RemoveTagsFromResource",
    ]
    resources = local.data_arns.elasticache
  }

  statement {
    sid       = "CounterStoreDeleteOwn"
    actions   = ["elasticache:DeleteServerlessCache", "elasticache:DeleteUser", "elasticache:DeleteUserGroup"]
    resources = local.data_arns.elasticache

    dynamic "condition" {
      for_each = local.data_delete_tag_conditions

      content {
        test     = "StringEquals"
        variable = condition.key
        values   = [condition.value]
      }
    }
  }

  # RDS and ElastiCache create their service-linked roles on first use in an account.
  statement {
    sid       = "DataServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::${var.account_id}:role/aws-service-role/*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["rds.amazonaws.com", "elasticache.amazonaws.com"]
    }
  }

  statement {
    sid       = "QueuesCreateAndChange"
    actions   = ["sqs:CreateQueue", "sqs:SetQueueAttributes", "sqs:TagQueue", "sqs:UntagQueue"]
    resources = local.data_arns.sqs
  }

  statement {
    sid       = "QueuesDeleteOwn"
    actions   = ["sqs:DeleteQueue"]
    resources = local.data_arns.sqs

    dynamic "condition" {
      for_each = local.data_delete_tag_conditions

      content {
        test     = "StringEquals"
        variable = condition.key
        values   = [condition.value]
      }
    }
  }

  # The master secret: created without a value, written only through write-only arguments, replicated to Osaka. The
  # secret's own policy refuses every write but this role's (modules/aurora).
  statement {
    sid = "MasterSecretWrite"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:DeleteResourcePolicy",
      "secretsmanager:DeleteSecret",
      "secretsmanager:PutResourcePolicy",
      "secretsmanager:PutSecretValue",
      "secretsmanager:RemoveRegionsFromReplication",
      "secretsmanager:ReplicateSecretToRegions",
      "secretsmanager:TagResource",
      "secretsmanager:UntagResource",
      "secretsmanager:UpdateSecret",
      "secretsmanager:ValidateResourcePolicy",
    ]
    resources = local.data_arns.secrets
  }

  statement {
    sid = "DatabaseLogGroupWrite"
    actions = [
      "logs:AssociateKmsKey",
      "logs:CreateLogGroup",
      "logs:DeleteDataProtectionPolicy",
      "logs:DeleteLogGroup",
      "logs:DeleteRetentionPolicy",
      "logs:DisassociateKmsKey",
      "logs:PutDataProtectionPolicy",
      "logs:PutRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource",
    ]
    resources = local.data_arns.logs
  }

  # The calls these services make with the deploy role's credentials when it creates an encrypted cluster, cache, queue
  # or secret: grants for the resource, and data keys. Through the services only, never directly.
  statement {
    sid = "UseKeysThroughDataServices"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
    ]
    resources = local.data_arns.kms_keys

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = local.data_kms_via_services
    }
  }

  statement {
    sid       = "GrantsOnlyForAwsResources"
    effect    = "Deny"
    actions   = ["kms:CreateGrant"]
    resources = local.data_arns.kms_keys

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "plan_data" {
  count = local.network_enabled ? 1 : 0

  name        = "${var.plan_role_name}-data"
  path        = var.iam_path
  description = "Terraform plans of the data layer's stores: read only (#101)."
  policy      = data.aws_iam_policy_document.data_read[0].json
}

resource "aws_iam_role_policy_attachment" "plan_data" {
  count = local.network_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.plan_data[0].arn
}

resource "aws_iam_policy" "deploy_data" {
  count = local.network_enabled && var.github_environment != null ? 1 : 0

  name        = "${var.deploy_role_name}-data"
  path        = var.iam_path
  description = "Terraform applies of the data layer's stores: Aurora, the counter store, the queues (#101)."
  policy      = data.aws_iam_policy_document.data_deploy[0].json
}

resource "aws_iam_role_policy_attachment" "deploy_data" {
  count = local.network_enabled && var.github_environment != null ? 1 : 0

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.deploy_data[0].arn
}

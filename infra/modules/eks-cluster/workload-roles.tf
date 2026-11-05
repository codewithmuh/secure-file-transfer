# One IAM role per workload (ADR-0004, architecture 3.1, encryption 4.3), each reached only through EKS Pod Identity
# by its own namespace and service account in one of this account's clusters, never IRSA (the STS endpoint refuses web
# identity, network module). Each role holds only what its workload does, in every Region with a cluster, so the same
# role works in Osaka after a failover. Bucket, queue and key policies in the data layer name the same roles (#101,
# #102), so each permission needs both sides.
#
# clamd, the DLP inspector and the signature mirror get no role and no service account token (architecture 3.1).
# The database bootstrap, recovery and key rotation jobs (encryption 4.3) get theirs with the issues that build them.

locals {
  # Namespaces and service accounts agreed with the Helm chart (#106) and cluster-bootstrap (#104).
  pod_identities = {
    api              = { namespace = "sft", service_accounts = ["api"], description = "API service" }
    relay            = { namespace = "sft", service_accounts = ["relay"], description = "Outbox relay" }
    scan             = { namespace = "sft", service_accounts = ["scan-worker"], description = "Scan worker" }
    notify           = { namespace = "sft", service_accounts = ["notifier"], description = "Notification worker" }
    jobs             = { namespace = "sft", service_accounts = ["jobs"], description = "Lifecycle jobs" }
    archive          = { namespace = "sft", service_accounts = ["audit-archive"], description = "Audit archive job" }
    migrate          = { namespace = "sft", service_accounts = ["migrate"], description = "Migrations job" }
    operator         = { namespace = "sft-operator", service_accounts = ["operator-api"], description = "Operator API" }
    karpenter        = { namespace = "karpenter", service_accounts = ["karpenter"], description = "Karpenter controller" }
    lb_controller    = { namespace = "kube-system", service_accounts = ["aws-load-balancer-controller"], description = "AWS Load Balancer Controller" }
    external_secrets = { namespace = "external-secrets", service_accounts = ["external-secrets"], description = "External Secrets" }
    kyverno          = { namespace = "kyverno", service_accounts = ["kyverno-admission-controller", "kyverno-reports-controller"], description = "Kyverno image verification" }
    # Associated through their EKS add-ons (main.tf), not below.
    vpc_cni = { namespace = "kube-system", service_accounts = ["aws-node"], description = "VPC CNI" }
    ebs_csi = { namespace = "kube-system", service_accounts = ["ebs-csi-controller-sa"], description = "EBS CSI driver" }
  }

  addon_roles = toset(["vpc_cni", "ebs_csi"])

  # AWS managed policies, only where AWS keeps them in step with its own component.
  pod_identity_managed_policies = {
    vpc_cni = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
    ebs_csi = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  }

  # One association per service account.
  pod_identity_associations = merge([
    for role, p in local.pod_identities : {
      for sa in p.service_accounts : "${role}/${sa}" => { role = role, namespace = p.namespace, service_account = sa }
    } if !contains(local.addon_roles, role)
  ]...)
}

# Pod Identity tags each session with the cluster, namespace and service account (session tags stay on), so only the
# named service accounts in this account's clusters can assume the role.
data "aws_iam_policy_document" "pod_identity_trust" {
  for_each = local.pod_identities

  statement {
    sid     = "PodIdentity"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/eks-cluster-arn"
      values   = local.cluster_arns
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = [each.value.namespace]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = each.value.service_accounts
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Resources the policies name: the data layer's, by the names agreed with #101 and #102, in every Region with a cluster
# ---------------------------------------------------------------------------------------------------------------------

locals {
  buckets = {
    for kind in ["files", "large-files", "audit-archive"] :
    kind => [for r, p in local.regional_prefixes : "arn:aws:s3:::${p}-${kind}-${var.account_id}"]
  }
  objects = { for kind, arns in local.buckets : kind => [for a in arns : "${a}/*"] }

  queues = {
    for q in ["scan-small", "scan-large", "notify", "signin-events", "ses-events", "guardduty-results", "ses-tenant-status"] :
    q => [for r, p in local.regional_prefixes : "arn:aws:sqs:${r}:${var.account_id}:${p}-${q}"]
  }

  # Secrets Manager adds six random characters to every secret's ARN.
  app_secrets = {
    for s in ["code-hmac", "email-hmac", "link-hmac", "csrf-hmac"] :
    s => [for r in var.cluster_regions : "arn:aws:secretsmanager:${r}:${var.account_id}:secret:sft/${var.environment}/app/${s}-??????"]
  }
  # Each Region's API reads only its own user pool's client (encryption 6.1, authn-authz 2.6).
  idp_client_secrets = [
    for r in var.cluster_regions : "arn:aws:secretsmanager:${r}:${var.account_id}:secret:sft/${var.environment}/app/idp-client/${r}-??????"
  ]
  platform_secrets = [
    for r in var.cluster_regions : "arn:aws:secretsmanager:${r}:${var.account_id}:secret:sft/${var.environment}/platform/*"
  ]

  valkey_caches = [for r, p in local.regional_prefixes : "arn:aws:elasticache:${r}:${var.account_id}:serverlesscache:${p}-valkey"]

  key_arns = [for r in var.cluster_regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]
  via      = { for s in ["s3", "sqs", "secretsmanager", "ecr"] : s => [for r in var.cluster_regions : "${s}.${r}.amazonaws.com"] }

  # Statements every database user needs: IAM authentication as its own PostgreSQL login role (encryption 6.3). The
  # account has no other Aurora clusters, so any cluster resource ID in the Regions with a cluster (#101).
  database = {
    for w in ["api", "relay", "scan", "notify", "jobs", "archive", "migrate", "operator"] : w => {
      Sid      = "ConnectAsOwnDatabaseRole"
      Effect   = "Allow"
      Action   = ["rds-db:connect"]
      Resource = [for r in var.cluster_regions : "arn:aws:rds-db:${r}:${var.account_id}:dbuser:*/sft_${w}"]
    }
  }

  # Valkey by IAM authentication, as its own user, for the four workloads that use it (ADR-0014; the sign-in triggers
  # are the edge layer's).
  valkey = {
    for w in ["api", "scan", "notify"] : w => {
      Sid    = "ConnectToValkeyAsOwnUser"
      Effect = "Allow"
      Action = ["elasticache:Connect"]
      Resource = concat(
        local.valkey_caches,
        [for r in var.cluster_regions : "arn:aws:elasticache:${r}:${var.account_id}:user:${var.global_name_prefix}-${w}"],
      )
    }
  }

  # A key by its alias, in any Region with a cluster.
  key_alias = { for k in ["files", "fields", "platform", "secrets", "audit"] : k => { "kms:ResourceAliases" = ["${var.kms_alias_prefix}/${k}"] } }

  consume_queue_actions = ["sqs:ChangeMessageVisibility", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ReceiveMessage"]
}

# ---------------------------------------------------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------------------------------------------------

locals {
  pod_identity_policies = {
    # Architecture 3.1: uploads into both files buckets, reads of scanned objects only, no delete and no tags; the
    # security-critical audit records straight to the archive in both Regions (5.2); fields key for names and DLP
    # details (encryption 3.2, 3.3).
    api = [
      {
        Sid      = "MultipartUploadsToFilesBuckets"
        Effect   = "Allow"
        Action   = ["s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:PutObject"]
        Resource = concat(local.objects["files"], local.objects["large-files"])
      },
      {
        Sid      = "ListOwnUploads"
        Effect   = "Allow"
        Action   = ["s3:ListBucketMultipartUploads"]
        Resource = concat(local.buckets["files"], local.buckets["large-files"])
      },
      {
        Sid      = "ObjectSizeAndVersion"
        Effect   = "Allow"
        Action   = ["s3:GetObjectAttributes", "s3:GetObjectVersionAttributes"]
        Resource = concat(local.objects["files"], local.objects["large-files"])
      },
      {
        # FR-16, FR-17: only clean or allowed-unscannable objects are ever readable by the API.
        Sid       = "ReadScannedObjectsOnly"
        Effect    = "Allow"
        Action    = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource  = concat(local.objects["files"], local.objects["large-files"])
        Condition = { StringEquals = { "s3:ExistingObjectTag/scan" = ["clean", "unscannable_allowed"] } }
      },
      {
        Sid      = "WriteSecurityCriticalAuditRecords"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = local.objects["audit-archive"]
      },
      {
        Sid      = "OwnSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = concat(local.app_secrets["code-hmac"], local.app_secrets["email-hmac"], local.app_secrets["csrf-hmac"], local.idp_client_secrets)
      },
      local.valkey["api"],
      local.database["api"],
      {
        Sid       = "FilesKeyThroughS3"
        Effect    = "Allow"
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["files"], StringEquals = { "kms:ViaService" = local.via["s3"], "kms:EncryptionContext:aws:s3:arn" = concat(local.buckets["files"], local.buckets["large-files"]) } }
      },
      {
        Sid      = "FieldsKeyForTenantDataKeys"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = local.key_arns
        Condition = {
          "ForAnyValue:StringEquals" = merge(local.key_alias["fields"], { "kms:EncryptionContextKeys" = ["tenant_id"] })
          StringEquals               = { "kms:EncryptionContext:purpose" = ["field-dek", "dlp-dek"] }
        }
      },
      {
        Sid       = "AuditKeyThroughS3"
        Effect    = "Allow"
        Action    = ["kms:GenerateDataKey"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["audit"], StringEquals = { "kms:ViaService" = local.via["s3"], "kms:EncryptionContext:aws:s3:arn" = local.buckets["audit-archive"] } }
      },
      {
        Sid       = "SecretsKeyForOwnSecrets"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["secrets"], StringEquals = { "kms:ViaService" = local.via["secretsmanager"] }, StringLike = { "kms:EncryptionContext:SecretARN" = concat(local.app_secrets["code-hmac"], local.app_secrets["email-hmac"], local.app_secrets["csrf-hmac"], local.idp_client_secrets) } }
      },
    ]

    # The only sender to the work queues (#101).
    relay = [
      {
        Sid      = "SendToWorkQueues"
        Effect   = "Allow"
        Action   = ["sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:SendMessage"]
        Resource = concat(local.queues["scan-small"], local.queues["scan-large"], local.queues["notify"])
      },
      local.database["relay"],
      {
        Sid       = "PlatformKeyThroughSqs"
        Effect    = "Allow"
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["platform"], StringEquals = { "kms:ViaService" = local.via["sqs"], "kms:EncryptionContext:aws:sqs:arn" = concat(local.queues["scan-small"], local.queues["scan-large"], local.queues["notify"]) } }
      },
    ]

    # Architecture 3.1: reads unscanned objects in the files bucket only (GuardDuty scans the large ones), writes the
    # scan tag in both pairs, never deletes; fields key for DLP data keys only (encryption 3.3).
    scan = [
      {
        Sid       = "ReadUnscannedSmallFiles"
        Effect    = "Allow"
        Action    = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource  = local.objects["files"]
        Condition = { Null = { "s3:ExistingObjectTag/scan" = "true" } }
      },
      {
        Sid      = "ScanTags"
        Effect   = "Allow"
        Action   = ["s3:GetObjectTagging", "s3:GetObjectVersionTagging", "s3:PutObjectTagging", "s3:PutObjectVersionTagging"]
        Resource = concat(local.objects["files"], local.objects["large-files"])
      },
      {
        Sid      = "ConsumeScanQueues"
        Effect   = "Allow"
        Action   = local.consume_queue_actions
        Resource = concat(local.queues["scan-small"], local.queues["scan-large"], local.queues["guardduty-results"])
      },
      local.valkey["scan"],
      local.database["scan"],
      {
        Sid       = "FilesKeyThroughS3ForSmallFiles"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["files"], StringEquals = { "kms:ViaService" = local.via["s3"], "kms:EncryptionContext:aws:s3:arn" = local.buckets["files"] } }
      },
      {
        Sid      = "FieldsKeyForDlpDataKeysOnly"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = local.key_arns
        Condition = {
          "ForAnyValue:StringEquals" = merge(local.key_alias["fields"], { "kms:EncryptionContextKeys" = ["tenant_id"] })
          StringEquals               = { "kms:EncryptionContext:purpose" = ["dlp-dek"] }
        }
      },
      {
        Sid       = "PlatformKeyThroughSqs"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["platform"], StringEquals = { "kms:ViaService" = local.via["sqs"], "kms:EncryptionContext:aws:sqs:arn" = concat(local.queues["scan-small"], local.queues["scan-large"], local.queues["guardduty-results"]) } }
      },
    ]

    # Sends email through SES's API and runs the Cognito admin calls for members (authn-authz 2.5): create, delete,
    # disable and sign out users; the only role with any Cognito permission.
    notify = [
      {
        Sid      = "ConsumeNotificationQueues"
        Effect   = "Allow"
        Action   = local.consume_queue_actions
        Resource = concat(local.queues["notify"], local.queues["signin-events"], local.queues["ses-events"], local.queues["ses-tenant-status"])
      },
      {
        Sid    = "SendEmail"
        Effect = "Allow"
        Action = ["ses:SendEmail", "ses:SendRawEmail"]
        Resource = flatten([
          for r in var.cluster_regions : [
            "arn:aws:ses:${r}:${var.account_id}:identity/*",
            "arn:aws:ses:${r}:${var.account_id}:configuration-set/*",
          ]
        ])
      },
      {
        Sid      = "CognitoMemberAdministration"
        Effect   = "Allow"
        Action   = ["cognito-idp:AdminCreateUser", "cognito-idp:AdminDeleteUser", "cognito-idp:AdminDisableUser", "cognito-idp:AdminGetUser", "cognito-idp:AdminUserGlobalSignOut"]
        Resource = [for r in var.cluster_regions : "arn:aws:cognito-idp:${r}:${var.account_id}:userpool/*"]
      },
      {
        Sid      = "OwnSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = concat(local.app_secrets["code-hmac"], local.app_secrets["email-hmac"], local.app_secrets["link-hmac"])
      },
      local.valkey["notify"],
      local.database["notify"],
      {
        Sid       = "PlatformKeyThroughSqs"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["platform"], StringEquals = { "kms:ViaService" = local.via["sqs"], "kms:EncryptionContext:aws:sqs:arn" = concat(local.queues["notify"], local.queues["signin-events"], local.queues["ses-events"], local.queues["ses-tenant-status"]) } }
      },
      {
        Sid       = "SecretsKeyForOwnSecrets"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["secrets"], StringEquals = { "kms:ViaService" = local.via["secretsmanager"] }, StringLike = { "kms:EncryptionContext:SecretARN" = concat(local.app_secrets["code-hmac"], local.app_secrets["email-hmac"], local.app_secrets["link-hmac"]) } }
      },
    ]

    # The only workload that deletes objects (architecture 4.5), in both files bucket pairs in both Regions. Deleting
    # needs no key, so it can't read what it deletes (encryption 4.3).
    jobs = [
      {
        Sid      = "ListFilesBuckets"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions"]
        Resource = concat(local.buckets["files"], local.buckets["large-files"])
      },
      {
        Sid      = "DeleteObjectsAndUploads"
        Effect   = "Allow"
        Action   = ["s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = concat(local.objects["files"], local.objects["large-files"])
      },
      local.database["jobs"],
    ]

    # Copies audit rows to the Object Lock archive (architecture 5.2); the bucket's default retention applies.
    archive = [
      {
        Sid      = "WriteAuditArchive"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = local.objects["audit-archive"]
      },
      local.database["archive"],
      {
        Sid       = "AuditKeyThroughS3"
        Effect    = "Allow"
        Action    = ["kms:GenerateDataKey"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["audit"], StringEquals = { "kms:ViaService" = local.via["s3"], "kms:EncryptionContext:aws:s3:arn" = local.buckets["audit-archive"] } }
      },
    ]

    migrate = [local.database["migrate"]]

    # Writes its security-critical audit records to the archive (encryption 4.3, decision 12); no Cognito, no files.
    operator = [
      {
        Sid      = "WriteSecurityCriticalAuditRecords"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = local.objects["audit-archive"]
      },
      local.database["operator"],
      {
        Sid       = "AuditKeyThroughS3"
        Effect    = "Allow"
        Action    = ["kms:GenerateDataKey"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["audit"], StringEquals = { "kms:ViaService" = local.via["s3"], "kms:EncryptionContext:aws:s3:arn" = local.buckets["audit-archive"] } }
      },
    ]

    karpenter = jsondecode(data.aws_iam_policy_document.karpenter.json).Statement

    # TargetGroupBinding only: the edge layer's Terraform owns the load balancer, its listeners, target groups and
    # security group rules, so the controller registers and deregisters pod IPs and creates nothing (#104, #105).
    lb_controller = [
      {
        Sid    = "Describe"
        Effect = "Allow"
        Action = [
          "ec2:DescribeAvailabilityZones", "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets", "ec2:DescribeVpcs",
          "elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
        ]
        Resource  = ["*"]
        Condition = { StringEquals = { "aws:RequestedRegion" = var.cluster_regions } }
      },
      {
        Sid      = "RegisterPodTargets"
        Effect   = "Allow"
        Action   = ["elasticloadbalancing:DeregisterTargets", "elasticloadbalancing:RegisterTargets"]
        Resource = [for r, p in local.regional_prefixes : "arn:aws:elasticloadbalancing:${r}:${var.account_id}:targetgroup/${p}-*/*"]
      },
    ]

    # Platform component secrets only, through Secrets Manager (encryption 6.1).
    external_secrets = [
      {
        Sid      = "PlatformSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = local.platform_secrets
      },
      {
        Sid       = "SecretsKeyForPlatformSecrets"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["secrets"], StringEquals = { "kms:ViaService" = local.via["secretsmanager"] }, StringLike = { "kms:EncryptionContext:SecretARN" = local.platform_secrets } }
      },
    ]

    # Reads signatures and attestations next to our images in the shared registry (ADR-0007): read only, our
    # organization's sft/ and mirror/ repositories only.
    kyverno = [
      {
        Sid      = "RegistryToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = ["*"]
      },
      {
        Sid    = "ReadSignatures"
        Effect = "Allow"
        Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer", "ecr:ListImages"]
        Resource = flatten([
          for r in var.cluster_regions : ["arn:aws:ecr:${r}:*:repository/sft/*", "arn:aws:ecr:${r}:*:repository/mirror/*"]
        ])
        Condition = { StringEquals = { "aws:ResourceOrgID" = [var.organization_id] } }
      },
      {
        Sid       = "RegistryKeyThroughEcr"
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = [for r in var.cluster_regions : "arn:aws:kms:${r}:*:key/*"]
        Condition = { StringEquals = { "aws:ResourceOrgID" = [var.organization_id], "kms:ViaService" = local.via["ecr"] } }
      },
    ]

    # The EBS CSI driver's volumes (observability) use the account's default key, the platform key (encryption 3.1).
    ebs_csi = [
      {
        Sid       = "PlatformKeyForVolumes"
        Effect    = "Allow"
        Action    = ["kms:CreateGrant", "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncryptFrom", "kms:ReEncryptTo"]
        Resource  = local.key_arns
        Condition = { "ForAnyValue:StringEquals" = local.key_alias["platform"], StringEquals = { "kms:ViaService" = [for r in var.cluster_regions : "ec2.${r}.amazonaws.com"] } }
      },
    ]
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Roles and associations
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "pod_identity" {
  for_each = var.create_iam ? local.pod_identities : {}

  name                 = local.role_names[each.key]
  description          = "${each.value.description} in ${var.global_name_prefix}, through EKS Pod Identity (${each.value.namespace})."
  assume_role_policy   = data.aws_iam_policy_document.pod_identity_trust[each.key].json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy" "pod_identity" {
  for_each = var.create_iam ? {
    for k, statements in local.pod_identity_policies : k => jsonencode({ Version = "2012-10-17", Statement = statements })
  } : {}

  name   = "workload"
  role   = aws_iam_role.pod_identity[each.key].name
  policy = each.value
}

resource "aws_iam_role_policy_attachment" "pod_identity" {
  for_each = var.create_iam ? local.pod_identity_managed_policies : {}

  role       = aws_iam_role.pod_identity[each.key].name
  policy_arn = each.value
}

resource "aws_eks_pod_identity_association" "this" {
  for_each = local.pod_identity_associations

  cluster_name    = aws_eks_cluster.this.name
  namespace       = each.value.namespace
  service_account = each.value.service_account
  role_arn        = local.role_arns[each.value.role]

  tags = {
    component = "eks"
  }

  depends_on = [aws_iam_role.pod_identity, aws_iam_role_policy.pod_identity]
}

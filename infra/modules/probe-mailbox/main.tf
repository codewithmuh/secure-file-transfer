# The synthetic probe's and the load test's mailbox in one Region (#259; the probe #248, the load test #249): SES
# receives mail for probe.<service domain> (and loadtest.<service domain> in staging) and writes each message, raw,
# to this Region's mailbox bucket under probe/ or loadtest/, where the probe and the load test's mailbox bridge read it
# once and delete it (services/api/src/sft/probe/mailbox.py, loadtest/mailbox_bridge.py).
#
# - Both Japanese Regions receive email (AWS General Reference, "Amazon SES endpoints and quotas", Email Receiving
#   endpoints: inbound-smtp.ap-northeast-1 and inbound-smtp.ap-northeast-3), so each Region has its own receipt rule
#   set and bucket. The MX record, written by Tokyo's stack, names Tokyo first and Osaka second: senders fall back to
#   Osaka when Tokyo's endpoint doesn't answer, so the probe keeps reading its mail in Osaka after a failover.
# - SES receives only for domains it has verified, so each mailbox domain is an SES identity with Easy DKIM in each
#   Region, like mail.<service domain> (modules/ses).
# - The bucket: SSE-KMS under the platform key, whose policy lets SES write and the two readers decrypt (modules/
#   kms-keys); a one-day expiry, because a message matters only to the run that waits for it; a policy that lets SES
#   write under the two prefixes for this account's rules only, the probe read and delete probe/ only, the load test
#   loadtest/ only, and only Terraform and Admin change the bucket.
# - In staging's Tokyo stack, the load test's role sft-staging-loadtest (OIDC, the loadtest-staging environment, main
#   only) and its secret sft/staging/loadtest/api-keys, without a value (docs/operations/performance.md).
#
# The probe stays off until the maintainer turns it on (probe.enabled in the values file, TF_VAR_probe_enabled for its
# alarm), after the AWS run's first deploy (docs/runbooks/synthetic-probe.md).

locals {
  zone_name      = "sft.${var.domain}"
  service_domain = var.environment == "prod" ? local.zone_name : "${var.environment}.${local.zone_name}"

  prefix      = "${var.conventions.global_name_prefix}-${var.conventions.region_shorts[var.region]}"
  bucket_name = "${local.prefix}-probe-mailbox-${var.account_id}"
  bucket_arn  = "arn:aws:s3:::${local.bucket_name}"
  rule_set    = "${local.prefix}-inbound"

  # Each mailbox: its domain, its prefix in the bucket, and who reads it.
  readers = {
    probe    = var.conventions.workload_role_arns["synthetic-probe"]
    loadtest = var.conventions.workload_role_arns["loadtest"]
  }
  mailboxes = {
    for m in var.mailboxes : m => {
      domain = "${m}.${local.service_domain}"
      prefix = "${m}/"
      reader = local.readers[m]
    }
  }

  # Easy DKIM's CNAME target: Osaka signs from its own domain (AWS General Reference, DKIM domains).
  dkim_domain = var.region == "ap-northeast-3" ? "dkim.ap-northeast-3.amazonses.com" : "dkim.amazonses.com"

  # The MX record's values: Tokyo first, then Osaka (lower is preferred).
  mx_values = [for i, r in var.mx_regions : "${10 * (i + 1)} inbound-smtp.${r}.amazonaws.com"]
}

data "aws_route53_zone" "this" {
  provider = aws.dns

  name         = local.zone_name
  private_zone = false
}

# --- The bucket -----------------------------------------------------------------------------------------------------

resource "aws_s3_bucket" "this" {
  bucket = local.bucket_name

  # Nothing here outlives a day; a teardown empties it.
  force_destroy = true

  tags = { component = "probe" }
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.platform_key_arn
    }
  }
}

# A message matters only to the run that waits for it: anything a reader didn't delete goes after a day.
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "one-day"
    status = "Enabled"

    filter {}

    expiration {
      days = 1
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "SesWritesTheMailboxes"
    actions   = ["s3:PutObject"]
    resources = [for m in values(local.mailboxes) : "${local.bucket_arn}/${m.prefix}*"]

    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ses:${var.region}:${var.account_id}:receipt-rule-set/${local.rule_set}:receipt-rule/*"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Only SES writes mail: nobody can plant a message for the probe to read.
  statement {
    sid       = "DenyWritesToEveryoneButSes"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalServiceName"
      values   = ["ses.amazonaws.com"]
    }
  }

  # Each reader reads and deletes its own prefix only; links and codes in the other's mail stay out of reach.
  dynamic "statement" {
    for_each = local.mailboxes

    content {
      sid       = "Deny${title(statement.key)}MailToEveryoneElse"
      effect    = "Deny"
      actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObject", "s3:DeleteObjectVersion"]
      resources = ["${local.bucket_arn}/${statement.value.prefix}*"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = concat([statement.value.reader, var.deploy_role_arn], var.admin_principal_arn_patterns)
      }
    }
  }

  statement {
    sid    = "DenyBucketSettingsToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketOwnershipControls",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration", "s3:PutInventoryConfiguration",
      "s3:PutBucketTagging",
    ]
    resources = [local.bucket_arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = concat([var.deploy_role_arn], var.admin_principal_arn_patterns)
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [aws_s3_bucket_public_access_block.this]
}

# --- SES receiving --------------------------------------------------------------------------------------------------

resource "aws_sesv2_email_identity" "mailbox" {
  for_each = local.mailboxes

  email_identity = each.value.domain

  dkim_signing_attributes {
    next_signing_key_length = "RSA_2048_BIT"
  }
}

resource "aws_route53_record" "dkim" {
  provider = aws.dns
  for_each = { for pair in setproduct(keys(local.mailboxes), [0, 1, 2]) : "${pair[0]}/${pair[1]}" => pair }

  zone_id = data.aws_route53_zone.this.zone_id
  name    = "${aws_sesv2_email_identity.mailbox[each.value[0]].dkim_signing_attributes[0].tokens[each.value[1]]}._domainkey.${local.mailboxes[each.value[0]].domain}"
  type    = "CNAME"
  ttl     = 1800
  records = ["${aws_sesv2_email_identity.mailbox[each.value[0]].dkim_signing_attributes[0].tokens[each.value[1]]}.${local.dkim_domain}"]
}

# The Region's one active rule set (SES allows one per Region and account).
resource "aws_ses_receipt_rule_set" "this" {
  rule_set_name = local.rule_set
}

resource "aws_ses_active_receipt_rule_set" "this" {
  rule_set_name = aws_ses_receipt_rule_set.this.rule_set_name
}

resource "aws_ses_receipt_rule" "this" {
  for_each = local.mailboxes

  name          = "${local.prefix}-${each.key}"
  rule_set_name = aws_ses_receipt_rule_set.this.rule_set_name
  recipients    = [each.value.domain]
  enabled       = true
  scan_enabled  = true
  tls_policy    = "Require"

  s3_action {
    bucket_name       = aws_s3_bucket.this.id
    object_key_prefix = each.value.prefix
    position          = 1
  }

  depends_on = [aws_s3_bucket_policy.this, aws_sesv2_email_identity.mailbox]
}

# Tokyo's stack writes each mailbox domain's MX: Tokyo first, Osaka second (staging and prod). Osaka's writes none.
resource "aws_route53_record" "mx" {
  provider = aws.dns
  for_each = length(var.mx_regions) > 0 ? local.mailboxes : {}

  zone_id = data.aws_route53_zone.this.zone_id
  name    = each.value.domain
  type    = "MX"
  ttl     = 300
  records = local.mx_values
}

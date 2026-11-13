# This Region's copy of the web bundle (ADR-0008): private, read only by the environment's CloudFront distribution
# through origin access control, written only by the release pipeline's role (modules/web-release, #283), which the
# bucket policy holds to. SSE-S3: the bundle is public content (encryption 3.1). Tokyo is the distribution's primary
# origin and Osaka its failover origin.

resource "aws_s3_bucket" "web" {
  count = var.web_bucket ? 1 : 0

  bucket        = local.web_bucket
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "web" {
  count = var.web_bucket ? 1 : 0

  bucket = aws_s3_bucket.web[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "web" {
  count = var.web_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.web[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versions let an operator see what a release replaced; rollback itself writes the previous index.html (NFR-18). A
# release never deletes: every older version's hashed files stay, so a rollback's index.html finds them.
resource "aws_s3_bucket_versioning" "web" {
  count = var.web_bucket ? 1 : 0

  bucket = aws_s3_bucket.web[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "web" {
  count = var.web_bucket ? 1 : 0

  bucket = aws_s3_bucket.web[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "web" {
  count = var.web_bucket ? 1 : 0

  bucket = aws_s3_bucket.web[0].id

  rule {
    id     = "expire-replaced-files"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.web]
}

data "aws_iam_policy_document" "web" {
  count = var.web_bucket ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::${local.web_bucket}", "arn:aws:s3:::${local.web_bucket}/*"]

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

  # The release role writes the bundle; the deploy role empties the bucket at teardown (force_destroy). Nobody else,
  # BreakGlass included, writes or deletes what browsers load (T-01, T-02).
  statement {
    sid       = "OnlyTheReleaseRoleWrites"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObject", "s3:PutObjectAcl", "s3:RestoreObject"]
    resources = ["arn:aws:s3:::${local.web_bucket}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = var.web_writer_arns
    }
  }

  # The environment's one distribution, by ARN. Osaka's stack gets it from Tokyo's output (web_distribution_arn).
  dynamic "statement" {
    for_each = var.web_distribution_arn == null ? [] : [var.web_distribution_arn]

    content {
      sid       = "CloudFrontReads"
      actions   = ["s3:GetObject"]
      resources = ["arn:aws:s3:::${local.web_bucket}/*"]

      principals {
        type        = "Service"
        identifiers = ["cloudfront.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "AWS:SourceArn"
        values   = [statement.value]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "web" {
  count = var.web_bucket ? 1 : 0

  bucket = aws_s3_bucket.web[0].id
  policy = data.aws_iam_policy_document.web[0].json

  depends_on = [aws_s3_bucket_public_access_block.web]
}

# The public zone sft.<domain> in the shared account, DNSSEC-signed, and the narrow roles through which each
# environment writes its own names into it (ADR-0021, T-01, capacity A32).
#
# - One zone for every environment, delegated once from the maintainer's domain. It delegates nothing: no NS record
#   can be written through the environment roles, so no delegation can ever point at a torn-down zone.
# - prod's names sit directly under the zone (app.sft.<domain>); dev's and staging's under their own label
#   (app.dev.sft.<domain>). Each environment's roles may change only its own names, of the listed record types.
# - Each environment gets two roles: a read role its plan role assumes, and a write role its deploy role assumes.
# - CAA lets only ACM issue certificates for any name in the zone, and no wildcard certificates.

locals {
  zone_name = "sft.${var.domain}"

  # Each environment's own domain: prod at the zone's apex, the others under their name.
  environment_domains = {
    for env in keys(var.member_account_ids) : env => env == "prod" ? local.zone_name : "${env}.${local.zone_name}"
  }

  # The names each environment may change: every listed label, and anything under it (ACM validation records,
  # SES's DKIM and DMARC records under mail). Route 53 matches the normalized name: lower case, no trailing dot.
  environment_record_names = {
    for env, domain in local.environment_domains : env => flatten([
      for label in var.record_labels : ["${label}.${domain}", "*.${label}.${domain}"]
    ])
  }

  zone_arn = aws_route53_zone.this.arn
}

resource "aws_route53_zone" "this" {
  name    = local.zone_name
  comment = "secure-file-transfer: every environment's records (ADR-0021). Managed by Terraform only."
}

resource "aws_route53_record" "caa" {
  zone_id = aws_route53_zone.this.zone_id
  name    = local.zone_name
  type    = "CAA"
  ttl     = 3600
  records = ["0 issue \"amazon.com\"", "0 issuewild \";\""]
}

# --- DNSSEC ------------------------------------------------------------------------------------------------------

# Route 53 requires the key-signing key's KMS key in us-east-1 (NFR-21's exception, ADR-0006). It protects no data:
# it signs the zone. Asymmetric keys can't rotate automatically; rotating the key-signing key is a runbook step.
data "aws_iam_policy_document" "dnssec_use" {
  statement {
    sid       = "Route53SignsThisAccountsZones"
    actions   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["dnssec-route53.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:route53:::hostedzone/*"]
    }
  }

  statement {
    sid       = "Route53CreatesItsGrant"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["dnssec-route53.amazonaws.com"]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

module "dnssec_key_policy" {
  source = "../key-policy"

  account_id                         = var.account_id
  deploy_role_arn                    = var.deploy_role_arn
  plan_role_arn                      = var.plan_role_arn
  key_admin_role_arn                 = var.key_admin_role_arn
  break_glass_principal_arn_patterns = var.break_glass_principal_arn_patterns
  additional_policy_documents        = [data.aws_iam_policy_document.dnssec_use.json]
}

resource "aws_kms_key" "dnssec" {
  provider = aws.us_east_1

  description              = "DNSSEC key-signing key for ${local.zone_name} (ADR-0021)"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  policy                   = module.dnssec_key_policy.json
}

resource "aws_kms_alias" "dnssec" {
  provider = aws.us_east_1

  name          = "${var.kms_alias_prefix}/dnssec"
  target_key_id = aws_kms_key.dnssec.key_id
}

resource "aws_route53_key_signing_key" "this" {
  hosted_zone_id             = aws_route53_zone.this.id
  key_management_service_arn = aws_kms_key.dnssec.arn
  name                       = "sft_ksk"
}

resource "aws_route53_hosted_zone_dnssec" "this" {
  hosted_zone_id = aws_route53_key_signing_key.this.hosted_zone_id
}

# --- Environment roles -------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "trust" {
  for_each = {
    for pair in setproduct(keys(var.member_account_ids), ["plan", "deploy"]) : "${pair[0]}-${pair[1]}" => {
      env    = pair[0]
      access = pair[1]
    }
  }

  statement {
    sid     = "EnvironmentTerraform${title(each.value.access)}Role"
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${var.member_account_ids[each.value.env]}:role${var.bootstrap_iam_path}sft-${each.value.env}-terraform-${each.value.access}",
      ]
    }
  }
}

data "aws_iam_policy_document" "read" {
  statement {
    sid       = "FindTheZone"
    actions   = ["route53:ListHostedZones", "route53:ListHostedZonesByName"]
    resources = ["*"]
  }

  statement {
    sid = "ReadTheZone"
    actions = [
      "route53:GetHostedZone", "route53:ListResourceRecordSets", "route53:ListTagsForResource",
      "route53:GetDNSSEC",
    ]
    resources = [local.zone_arn]
  }

  statement {
    sid       = "ReadChanges"
    actions   = ["route53:GetChange"]
    resources = ["arn:aws:route53:::change/*"]
  }
}

data "aws_iam_policy_document" "write" {
  for_each = local.environment_record_names

  source_policy_documents = [data.aws_iam_policy_document.read.json]

  statement {
    sid       = "ChangeOwnNamesOnly"
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = [local.zone_arn]

    condition {
      test     = "ForAllValues:StringLike"
      variable = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
      values   = each.value
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "route53:ChangeResourceRecordSetsRecordTypes"
      values   = var.record_types
    }
  }
}

resource "aws_iam_role" "environment" {
  for_each = data.aws_iam_policy_document.trust

  name                 = "sft-shared-dns-${each.key}"
  path                 = var.iam_path
  description          = "Lets ${split("-", each.key)[0]}'s Terraform ${split("-", each.key)[1]} role ${endswith(each.key, "-deploy") ? "change its own names in" : "read"} ${local.zone_name}."
  assume_role_policy   = each.value.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "environment" {
  for_each = aws_iam_role.environment

  name = "dns"
  role = each.value.id
  policy = (
    endswith(each.key, "-deploy")
    ? data.aws_iam_policy_document.write[trimsuffix(each.key, "-deploy")].json
    : data.aws_iam_policy_document.read.json
  )
}

# One Region's SES setup (ADR-0015, abuse 7.3 and 7.4, #185): the domain identity mail.<service domain> with Easy DKIM,
# this Region's custom MAIL FROM subdomain, the configuration set sft-<env>, and its events path: an SNS topic, under
# the platform key, that delivers into the ses-events queue the data layer made (modules/queues), which the
# notification worker reads (sft.service.ses_events).
#
# - DNS goes into the shared zone through the environment's DNS role (aws.dns), which may write only this
#   environment's names, mail and *.mail among them (modules/dns-zone). Each Region has its own DKIM tokens and its own
#   MAIL FROM subdomain (<region-short>.mail), because SES requires exactly one MX on it, pointing at one Region's
#   feedback endpoint. SPF on each; DMARC at p=reject once, from Tokyo.
# - The configuration set requires TLS to receiving servers, keeps reputation metrics, and turns the account-level
#   suppression list off for its sends: suppression is per tenant, in our own table (ADR-0015).
# - The identity policy lets Cognito send as the identity for this account's user pools in this Region only, with this
#   Region's configuration set (ADR-0016, developer email sending).
# - Production access, quotas and SES tenants are not Terraform's: the maintainer requests production access per Region
#   (ADR-0015), and the API creates SES tenants (createTenant).

locals {
  zone_name        = "sft.${var.domain}"
  service_domain   = var.environment == "prod" ? local.zone_name : "${var.environment}.${local.zone_name}"
  mail_domain      = "mail.${local.service_domain}"
  mail_from_domain = "${var.region_short}.${local.mail_domain}"
  configuration    = "sft-${var.environment}"
  topic_name       = "${var.name_prefix}-ses-events"
}

data "aws_route53_zone" "this" {
  provider = aws.dns

  name         = local.zone_name
  private_zone = false
}

data "aws_kms_alias" "platform" {
  name = "${var.kms_alias_prefix}/platform"
}

# ---------------------------------------------------------------------------------------------------------------------
# The configuration set and its events
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_sesv2_configuration_set" "this" {
  configuration_set_name = local.configuration

  delivery_options {
    tls_policy = "REQUIRE"
  }

  reputation_options {
    reputation_metrics_enabled = true
  }

  sending_options {
    sending_enabled = true
  }

  # Empty: the account-level suppression list never blocks these sends (ADR-0015).
  suppression_options {
    suppressed_reasons = []
  }
}

resource "aws_sns_topic" "events" {
  name              = local.topic_name
  kms_master_key_id = data.aws_kms_alias.platform.target_key_arn
}

data "aws_iam_policy_document" "topic" {
  statement {
    sid       = "SesPublishesThisConfigurationSetsEvents"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.events.arn]

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
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sesv2_configuration_set.this.arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish", "sns:Subscribe"]
    resources = [aws_sns_topic.events.arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "events" {
  arn    = aws_sns_topic.events.arn
  policy = data.aws_iam_policy_document.topic.json
}

# SNS's envelope stays on (no raw delivery): the worker reads the event from its Message.
resource "aws_sns_topic_subscription" "events" {
  topic_arn = aws_sns_topic.events.arn
  protocol  = "sqs"
  endpoint  = var.events_queue_arn
}

resource "aws_sesv2_configuration_set_event_destination" "events" {
  configuration_set_name = aws_sesv2_configuration_set.this.configuration_set_name
  event_destination_name = "ses-events"

  event_destination {
    enabled              = true
    matching_event_types = ["BOUNCE", "COMPLAINT", "DELIVERY", "REJECT", "DELIVERY_DELAY"]

    sns_destination {
      topic_arn = aws_sns_topic.events.arn
    }
  }

  depends_on = [aws_sns_topic_policy.events]
}

# ---------------------------------------------------------------------------------------------------------------------
# The identity, DKIM, MAIL FROM, SPF and DMARC
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_sesv2_email_identity" "mail" {
  email_identity         = local.mail_domain
  configuration_set_name = aws_sesv2_configuration_set.this.configuration_set_name

  dkim_signing_attributes {
    next_signing_key_length = "RSA_2048_BIT"
  }
}

resource "aws_route53_record" "dkim" {
  provider = aws.dns
  count    = 3

  zone_id = data.aws_route53_zone.this.zone_id
  name    = "${aws_sesv2_email_identity.mail.dkim_signing_attributes[0].tokens[count.index]}._domainkey.${local.mail_domain}"
  type    = "CNAME"
  ttl     = 1800
  records = ["${aws_sesv2_email_identity.mail.dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}

resource "aws_sesv2_email_identity_mail_from_attributes" "mail" {
  email_identity         = aws_sesv2_email_identity.mail.email_identity
  mail_from_domain       = local.mail_from_domain
  behavior_on_mx_failure = "REJECT_MESSAGE"
}

resource "aws_route53_record" "mail_from_mx" {
  provider = aws.dns

  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.mail_from_domain
  type    = "MX"
  ttl     = 1800
  records = ["10 feedback-smtp.${var.region}.amazonses.com"]
}

resource "aws_route53_record" "mail_from_spf" {
  provider = aws.dns

  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.mail_from_domain
  type    = "TXT"
  ttl     = 1800
  records = ["v=spf1 include:amazonses.com -all"]
}

# One DMARC record for the sending subdomain, written by Tokyo's stack; both Regions sign with their own DKIM keys.
resource "aws_route53_record" "dmarc" {
  provider = aws.dns
  count    = var.primary_region ? 1 : 0

  zone_id = data.aws_route53_zone.this.zone_id
  name    = "_dmarc.${local.mail_domain}"
  type    = "TXT"
  ttl     = 1800
  records = ["v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:${var.dmarc_report_address}"]
}

data "aws_iam_policy_document" "identity" {
  statement {
    sid       = "CognitoSendsForThisAccountsPoolsHere"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = [aws_sesv2_email_identity.mail.arn]

    principals {
      type        = "Service"
      identifiers = ["cognito-idp.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cognito-idp:${var.region}:${var.account_id}:userpool/*"]
    }
  }
}

resource "aws_sesv2_email_identity_policy" "cognito" {
  email_identity = aws_sesv2_email_identity.mail.email_identity
  policy_name    = "cognito-${var.region_short}"
  policy         = data.aws_iam_policy_document.identity.json
}

# The key-admin role, sft-<env>-keyadmin (ADR-0017, encryption 4.4 rule 6).
#
# Every key policy in the account names this role for kms:GetKeyPolicy and kms:PutKeyPolicy and nothing else, so a
# broken key policy can be put back even after a deploy role is deleted and re-created. Only the BreakGlass permission
# set may assume it, and every use pages (the alert rule comes with the environment's alerting). It needs no identity
# policy: the key policies grant what it may do.
#
# Created once with prevent_destroy. The last apply before a final teardown lifts it (encryption 8.4, step 2).

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "BreakGlassOnly"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.break_glass_principal_arn_patterns
    }
  }
}

resource "aws_iam_role" "key_admin" {
  name                 = var.role_name
  path                 = var.iam_path
  description          = "Repairs KMS key policies. Assumed only through BreakGlass; every use pages."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600

  lifecycle {
    prevent_destroy = true
  }
}

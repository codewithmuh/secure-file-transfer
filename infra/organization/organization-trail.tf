# The organization trail (ADR-0006, T-73, T-75): every account and Region, management events, and S3 data events on
# every Terraform state bucket, which are the state buckets' access log instead of S3 server access logs
# (.trivyignore.yaml, AVD-AWS-0089). It writes to the shared account's log archive, under its logs key, whose bucket and
# key policies admit this account's trail by its ARN (modules/log-archive).
#
# Created here, in the management account (#318). The shared account, CloudTrail's delegated administrator, created it
# first, but AWS makes the management account the owner of an organization trail whoever creates it, and the provider
# can't read a trail of another account: every shared plan failed. The import below adopts that trail.
#
# It needs the shared stack's archive: TF_VAR_log_archive = {bucket_name = ..., key_arn = ...}, from that stack's
# outputs. Every apply must name it, or the plan stops (below), so an apply for something else can't remove the trail
# by leaving it out. Before the shared stack exists (the organization's first apply, docs/runbooks/
# organization-and-bootstrap.md) and at the final teardown, TF_VAR_organization_trail_enabled=false says so instead.

locals {
  organization_trail_name = module.conventions.organization_trail_name
  organization_trail      = var.organization_trail_enabled && var.log_archive != null ? { organization = var.log_archive } : {}

  # Every Terraform state bucket: sft-<env>-<region-short>-tfstate-<account-id>, and the retained stack's own
  # (infra/README.md, "State"). Osaka has state buckets in staging and prod only.
  tfstate_bucket_prefixes = concat(
    [
      for pair in [
        ["management", "apne1"], ["shared", "apne1"], ["dev", "apne1"], ["staging", "apne1"], ["staging", "apne3"],
        ["prod", "apne1"], ["prod", "apne3"],
      ] : "arn:aws:s3:::sft-${pair[0]}-${pair[1]}-tfstate-"
    ],
    ["arn:aws:s3:::sft-prod-apne1-retained-tfstate-"],
  )
}

# Stops a plan that would remove the trail only because TF_VAR_log_archive was left out.
resource "terraform_data" "organization_trail_inputs" {
  lifecycle {
    precondition {
      condition     = !var.organization_trail_enabled || var.log_archive != null
      error_message = "Set TF_VAR_log_archive (the shared stack's log_archive_bucket_arn name and log_archive_key_arn), or TF_VAR_organization_trail_enabled=false before the shared stack exists or at the final teardown."
    }
  }
}

# The trail the shared account created before #318, adopted once with TF_VAR_adopt_organization_trail=true.
import {
  for_each = var.adopt_organization_trail ? local.organization_trail : {}
  to       = aws_cloudtrail.organization[each.key]
  id       = "arn:aws:cloudtrail:${module.conventions.region}:${var.account_id}:trail/${local.organization_trail_name}"
}

resource "aws_cloudtrail" "organization" {
  for_each = local.organization_trail

  name                          = local.organization_trail_name
  s3_bucket_name                = each.value.bucket_name
  kms_key_id                    = each.value.key_arn
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # The state buckets' access log (T-73): every read and write of a state or lock file, in every account.
  advanced_event_selector {
    name = "Terraform state objects"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = local.tfstate_bucket_prefixes
    }
  }

  depends_on = [aws_cloudtrail_organization_delegated_admin_account.shared]
}

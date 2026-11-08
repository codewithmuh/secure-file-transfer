# The application's secrets in one Region (encryption and keys 6.1, 6.4, #185), created without a value:
#
# - In Tokyo, the four keyrings sft/<env>/app/{csrf,email,code,link}-hmac, replicated to Osaka in staging and prod
#   (each replica under Osaka's secrets key), and Tokyo's idp-client/ap-northeast-1.
# - In Osaka, only its own pool's idp-client/ap-northeast-3: it lives only there, so it stays writable while Tokyo is
#   down (6.4, failover).
#
# Terraform never writes a value, so nothing secret reaches the plan or the state. The key rotation job
# (sft.workers.key_rotation) writes every first version, then rotates them (6.5); until it has run once the API and the
# notification worker don't start, because they find no keyring to read (and the API no client in External Secrets).

locals {
  keyrings = var.primary_region ? toset(["csrf-hmac", "email-hmac", "code-hmac", "link-hmac"]) : toset([])
}

data "aws_kms_alias" "secrets" {
  name = "${var.kms_alias_prefix}/secrets"
}

resource "aws_secretsmanager_secret" "keyring" {
  for_each = local.keyrings

  name                    = "sft/${var.environment}/app/${each.key}"
  description             = "The ${each.key} keyring (encryption and keys 6.1). Written only by the key rotation job."
  kms_key_id              = data.aws_kms_alias.secrets.target_key_arn
  recovery_window_in_days = var.recovery_window_in_days

  dynamic "replica" {
    for_each = var.replica_region == null ? [] : [var.replica_region]

    content {
      region     = replica.value
      kms_key_id = var.replica_kms_key_arn
    }
  }
}

resource "aws_secretsmanager_secret" "idp_client" {
  name                    = "sft/${var.environment}/app/idp-client/${var.region}"
  description             = "This Region's user pool app client, as JSON client_id and client_secret. Written only by the key rotation job."
  kms_key_id              = data.aws_kms_alias.secrets.target_key_arn
  recovery_window_in_days = var.recovery_window_in_days
}

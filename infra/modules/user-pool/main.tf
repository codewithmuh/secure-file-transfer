# One Region's member user pool (ADR-0016, authn and authz 2, #185): Tokyo's in every environment, Osaka's standby in
# staging and prod, from the same code and with no users.
#
# - Plus plan, threat protection enforced, admin-only sign-up; MFA required: TOTP, or a passkey with user verification.
#   No SMS, no email codes. Our user ID is the username and the address a verified alias (sft.runtime.cognito); the
#   schema adds custom:tenant_id (immutable) and custom:enrolment_id, which only the notification worker writes.
# - Cognito sends its own few emails through our SES identity in this Region, with its configuration set (ADR-0015,
#   developer email sending). Invitations are ours: the worker calls AdminCreateUser with MessageAction=SUPPRESS.
# - Managed login on a Cognito prefix domain, *.auth.<region>.amazoncognito.com, which the DNS Firewall already admits
#   (modules/network). The prefix carries a hash of the account, never its ID, so nobody can claim our names first.
# - One confidential app client: the authorization code grant with PKCE, one callback URL, token revocation on,
#   members may write no attribute. Cognito makes its first client secret, which lands in state; the key rotation job
#   replaces it before the API uses the client, so state only keeps a dead value (encryption and keys 6.4).
# - The edge's sign-in web ACL guards the pool's endpoints (abuse 3).
#
# The pre-authentication and audit triggers (ADR-0016, consequences) are not here yet: they arrive with their issue.

locals {
  zone_name      = "sft.${var.domain}"
  service_domain = var.environment == "prod" ? local.zone_name : "${var.environment}.${local.zone_name}"
  domain_prefix  = "sft-${var.environment}-${var.region_short}-${substr(sha256(var.account_id), 0, 10)}"
}

resource "aws_cognito_user_pool" "this" {
  name                = "${var.name_prefix}-members"
  user_pool_tier      = "PLUS"
  deletion_protection = var.deletion_protection ? "ACTIVE" : "INACTIVE"

  alias_attributes         = ["email"]
  auto_verified_attributes = []
  mfa_configuration        = "ON"

  username_configuration {
    case_sensitive = false
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 15
    require_lowercase                = false
    require_uppercase                = false
    require_numbers                  = false
    require_symbols                  = false
    temporary_password_validity_days = 3 # sft.service.user_pool.TEMPORARY_PASSWORD_DAYS
    password_history_size            = 5
  }

  software_token_mfa_configuration {
    enabled = true
  }

  web_authn_configuration {
    relying_party_id  = "${local.domain_prefix}.auth.${var.region}.amazoncognito.com"
    user_verification = "required"
  }

  sign_in_policy {
    allowed_first_auth_factors = ["PASSWORD", "WEB_AUTHN"]
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  email_configuration {
    email_sending_account  = "DEVELOPER"
    source_arn             = var.ses_identity_arn
    from_email_address     = var.from_address
    configuration_set      = var.ses_configuration_set
    reply_to_email_address = null
  }

  schema {
    name                     = "tenant_id"
    attribute_data_type      = "String"
    mutable                  = false
    developer_only_attribute = false
    required                 = false

    string_attribute_constraints {
      min_length = 36
      max_length = 36
    }
  }

  schema {
    name                     = "enrolment_id"
    attribute_data_type      = "String"
    mutable                  = true
    developer_only_attribute = false
    required                 = false

    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }

  lifecycle {
    # Cognito can't change a pool's schema after creation; an attribute added later is a new block, never an edit.
    ignore_changes = [schema]
  }
}

resource "aws_cognito_user_pool_domain" "this" {
  domain                = local.domain_prefix
  user_pool_id          = aws_cognito_user_pool.this.id
  managed_login_version = 2
}

resource "aws_cognito_user_pool_client" "api" {
  name         = "${var.name_prefix}-api"
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["https://api.${local.service_domain}/v1/auth/callback"]
  logout_urls                          = ["https://app.${local.service_domain}/"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]

  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"
  read_attributes               = ["email", "email_verified", "custom:tenant_id"]
  write_attributes              = []

  # One sign-in; our own session does the rest (ADR-0016): short tokens, refresh revoked at once by the API.
  access_token_validity  = 5
  id_token_validity      = 5
  refresh_token_validity = 60
  auth_session_validity  = 3

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "minutes"
  }
}

resource "aws_cognito_managed_login_branding" "api" {
  client_id    = aws_cognito_user_pool_client.api.id
  user_pool_id = aws_cognito_user_pool.this.id

  use_cognito_provided_values = true
}

resource "aws_wafv2_web_acl_association" "sign_in" {
  count = var.sign_in_web_acl_arn == null ? 0 : 1

  resource_arn = aws_cognito_user_pool.this.arn
  web_acl_arn  = var.sign_in_web_acl_arn
}

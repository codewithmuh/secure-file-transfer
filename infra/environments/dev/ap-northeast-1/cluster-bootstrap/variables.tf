variable "account_id" {
  description = "ID of the dev AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "shared_account_id" {
  description = "ID of the shared account, whose registry serves every image (TF_VAR_shared_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.shared_account_id))
    error_message = "shared_account_id must be a 12-digit AWS account ID."
  }
}

variable "cluster_api_tunnel_url" {
  description = "The cluster API through the Systems Manager tunnel, for example https://127.0.0.1:8443. Null to use the private endpoint directly."
  type        = string
  default     = null

  validation {
    condition     = var.cluster_api_tunnel_url == null ? true : can(regex("^https://(127\\.0\\.0\\.1|localhost):[0-9]+$", var.cluster_api_tunnel_url))
    error_message = "cluster_api_tunnel_url must be https://127.0.0.1:<port> or https://localhost:<port>."
  }
}

variable "identity_center_saml" {
  description = "Argo CD's Identity Center SAML application and the read-only group IDs (modules/cluster-bootstrap). Null until it exists."
  type = object({
    sso_url           = string
    ca_data           = string
    readonly_group_id = string
    operator_group_id = string
  })
  default = null
}

variable "github_app" {
  description = "The deployments-only GitHub App for Argo CD notifications (modules/cluster-bootstrap). Null for none."
  type = object({
    app_id          = string
    installation_id = string
  })
  default = null
}

variable "domain" {
  description = "The maintainer's domain; the shared zone is sft.<domain> (PRD open question 5). TF_VAR_domain, never committed."
  type        = string
}

variable "break_glass_reconciliation" {
  description = "The operator API's break-glass reconciliation (#275): this environment's trail role, the BreakGlass permission set and the identity store, from the organization stack's outputs (TF_VAR_break_glass_reconciliation, never committed). Null keeps it off."
  type = object({
    trail_role_arn     = string
    permission_set_arn = string
    identity_store_id  = string
  })
  default = null
}

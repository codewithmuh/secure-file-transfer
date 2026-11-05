variable "environment" {
  description = "The environment: dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "region" {
  description = "The cluster's Region, from the caller's conventions module: Tokyo or Osaka (NFR-21)."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "name_prefix" {
  description = "Prefix for names, from the caller's conventions module: sft-<env>-<region-short>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]$", var.name_prefix))
    error_message = "name_prefix must be sft-<dev|staging|prod>-<apne1|apne3>, the conventions module's name_prefix."
  }
}

variable "account_id" {
  description = "ID of this environment's account. Handed to the application's Applications, never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "shared_account_id" {
  description = "ID of the shared account, whose ECR registry (or its Osaka replica) serves every image (ADR-0007)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.shared_account_id))
    error_message = "shared_account_id must be a 12-digit AWS account ID."
  }
}

variable "pilot_light" {
  description = "Osaka's pilot light (ADR-0004): one replica of everything, and the main-pool controllers on the one system node."
  type        = bool
  default     = false
}

variable "high_availability" {
  description = "Prod's replica counts (capacity 4.3): two of Argo CD's repo and API servers, two Kyverno admission controllers, two Karpenter controllers."
  type        = bool
  default     = false

  validation {
    condition     = !(var.high_availability && var.pilot_light)
    error_message = "A pilot light runs one replica of everything, so high_availability must be false with it."
  }
}

variable "cluster" {
  description = <<-EOT
    What this module needs from the environment's cluster layer (#103), read from its state: the cluster's name,
    private endpoint and VPC; Karpenter's interruption queue; and Karpenter's EC2NodeClass and NodePool manifests,
    keyed by pool, as full objects (apiVersion, kind, metadata, spec).
  EOT
  type = object({
    name                           = string
    endpoint                       = string
    vpc_id                         = string
    karpenter_interruption_queue   = string
    karpenter_node_class_manifests = map(any)
    karpenter_node_pool_manifests  = map(any)
  })

  validation {
    condition     = startswith(var.cluster.endpoint, "https://")
    error_message = "cluster.endpoint must be the cluster API's https:// URL."
  }
}

variable "database_host" {
  description = "The Aurora writer endpoint in this Region, from the data layer, handed to the application's Applications."
  type        = string

  validation {
    condition     = length(var.database_host) > 0
    error_message = "database_host must not be empty: the application chart's schema requires it."
  }
}

variable "operator_role_name" {
  description = "Name of the Operator permission set's role in this account (AWSReservedSSO_Operator_<hash>), for the operator API (#111)."
  type        = string

  validation {
    condition     = can(regex("^AWSReservedSSO_Operator_[0-9a-f]+$", var.operator_role_name))
    error_message = "operator_role_name must be the Identity Center role AWSReservedSSO_Operator_<hash>."
  }
}

variable "argocd_url" {
  description = "Argo CD's URL as people reach it: through the Systems Manager tunnel to localhost (ADR-0021). Sign-in redirects use it."
  type        = string
  default     = "https://localhost:8443"

  validation {
    condition     = startswith(var.argocd_url, "https://")
    error_message = "argocd_url must be an https:// URL."
  }
}

variable "identity_center_saml" {
  description = <<-EOT
    Argo CD's sign-in through IAM Identity Center (ADR-0004): the SAML application's sign-in URL and its signing
    certificate (PEM, base64-encoded), from the customer managed application made in the management account, and the
    IDs of the groups that get read-only access (Identity Center sends group IDs, not names). Null until that
    application exists: then nobody can sign in, because the local admin is disabled.
  EOT
  type = object({
    sso_url           = string
    ca_data           = string
    readonly_group_id = string
    operator_group_id = string
  })
  default = null

  validation {
    condition     = var.identity_center_saml == null ? true : startswith(var.identity_center_saml.sso_url, "https://")
    error_message = "identity_center_saml.sso_url must be an https:// URL."
  }
}

variable "github_app" {
  description = <<-EOT
    The GitHub App, limited to deployments, through which Argo CD notifications post deployment statuses for the
    promotion gate (ADR-0005). Its private key is in Secrets Manager at
    sft/<env>/platform/argocd/github-app-private-key and reaches Argo CD through External Secrets. Null for no
    notifications.
  EOT
  type = object({
    app_id          = string
    installation_id = string
  })
  default = null

  validation {
    condition     = var.github_app == null ? true : can(regex("^[0-9]+$", var.github_app.app_id)) && can(regex("^[0-9]+$", var.github_app.installation_id))
    error_message = "github_app.app_id and installation_id must be numbers."
  }
}

variable "cognito_login_domain" {
  description = "The user pool's managed login domain in this Region, the API listener's one name besides Cognito's API. Null until the pool exists."
  type        = string
  default     = null

  validation {
    condition     = var.cognito_login_domain == null ? true : can(regex("^[a-z0-9.-]+$", var.cognito_login_domain))
    error_message = "cognito_login_domain must be a plain host name."
  }
}

variable "additional_mirror_digests" {
  description = <<-EOT
    Digests of third-party images in mirror/ that the application runs (clamd, for example), reviewed in Git, which
    Kyverno admits besides the platform's own (ADR-0007). The platform's are in images.tf.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for d in var.additional_mirror_digests : can(regex("^sha256:[0-9a-f]{64}$", d))])
    error_message = "Each digest must be sha256:<64 hex characters>."
  }
}

variable "host_access_namespaces" {
  description = <<-EOT
    Namespaces whose pods may use host namespaces, host paths and host ports: the node agents of ADR-0009, once their
    namespace exists. Privileged containers stay refused everywhere.
  EOT
  type        = list(string)
  default     = []
}

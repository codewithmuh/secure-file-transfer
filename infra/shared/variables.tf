variable "account_id" {
  description = "ID of the shared AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "management_account_id" {
  description = "ID of the management account, which owns the organization trail. TF_VAR_management_account_id, never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be a 12-digit AWS account ID."
  }
}

variable "member_account_ids" {
  description = "dev, staging and prod account IDs by environment, as they come to exist. TF_VAR_member_account_ids, never committed."
  type        = map(string)
  default     = {}
}

variable "domain" {
  description = "The maintainer's domain; the zone is sft.<domain> (PRD open question 5). TF_VAR_domain, never committed."
  type        = string
}

variable "replicate_to_osaka" {
  description = "Replicate the registry to Osaka. Turn on when staging is built (capacity 5.4)."
  type        = bool
  default     = false
}

variable "mirror_repositories" {
  description = <<-EOT
    Third-party images mirrored by digest into mirror/<name> (ADR-0007): every image modules/cluster-bootstrap/images.tf
    pins, clamd's (deploy/charts/sft), and KEDA's for ADR-0004's autoscaling. deploy/tests checks that the first two
    are all here. The mirror workflow's issue keeps this list.
  EOT
  type        = list(string)
  default = [
    "argoproj/argocd",
    "clamav/clamav",
    "dexidp/dex",
    "docker/library/redis",
    "eks/aws-load-balancer-controller",
    "envoyproxy/envoy",
    "external-secrets/external-secrets",
    "karpenter/controller",
    "kedacore/keda",
    "kedacore/keda-metrics-apiserver",
    "kyverno/background-controller",
    "kyverno/cleanup-controller",
    "kyverno/kyverno",
    "kyverno/kyverno-cli",
    "kyverno/kyvernopre",
    "kyverno/readiness-checker",
    "kyverno/reports-controller",
  ]
}

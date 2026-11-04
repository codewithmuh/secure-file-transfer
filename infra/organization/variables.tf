variable "account_id" {
  description = "ID of the management AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "account_emails" {
  description = "Root email address of each member account: shared, dev, staging and prod. Each must be unique in AWS and can never be reused once its account closes. Supplied at plan time, never committed."
  type        = map(string)

  validation {
    condition     = toset(keys(var.account_emails)) == toset(["shared", "dev", "staging", "prod"])
    error_message = "account_emails must have exactly the keys shared, dev, staging and prod."
  }

  validation {
    condition     = alltrue([for email in values(var.account_emails) : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email))])
    error_message = "Every account email must be an email address."
  }

  validation {
    condition     = length(distinct([for email in values(var.account_emails) : lower(email)])) == length(var.account_emails)
    error_message = "Each account needs its own email address."
  }
}

variable "budget_notification_emails" {
  description = "Addresses the budget alarms email (NFR-20). AWS allows at most 10. Supplied at plan time, never committed."
  type        = list(string)

  validation {
    condition     = length(var.budget_notification_emails) >= 1 && length(var.budget_notification_emails) <= 10
    error_message = "Name between 1 and 10 addresses."
  }

  validation {
    condition     = alltrue([for email in var.budget_notification_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email))])
    error_message = "Every budget notification address must be an email address."
  }
}

variable "identity_center_enabled" {
  description = "Whether IAM Identity Center is enabled for the organization in Tokyo. False only for the first apply, before the console step that enables it (runbook step 6)."
  type        = bool
  default     = true
}

variable "identity_center_group_members" {
  description = "Identity Center user names in each group: readonly, operators, breakglass_approvers, audit_readers. The users are created in the console first. Supplied at plan time, never committed."
  type        = map(list(string))
  default     = {}

  validation {
    condition = length(setsubtract(
      keys(var.identity_center_group_members),
      ["readonly", "operators", "breakglass_approvers", "audit_readers"],
    )) == 0
    error_message = "Groups are readonly, operators, breakglass_approvers and audit_readers. Admin and BreakGlass are never held through a group."
  }
}

variable "activate_cost_allocation_tags" {
  description = "Activate the environment, component and stack cost allocation tags. False until AWS has seen the tags on a bill, up to a day after the first tagged resource (runbook step 5)."
  type        = bool
  default     = true
}

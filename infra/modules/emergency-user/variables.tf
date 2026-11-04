variable "user_name" {
  description = "Name of the user, from the conventions module's emergency_user (sft-<env>-emergency)."
  type        = string

  validation {
    condition     = can(regex("^sft-[a-z]+-emergency$", var.user_name))
    error_message = "user_name must be sft-<env>-emergency, the name the bucket and key policies and the SCPs expect."
  }
}

variable "iam_path" {
  description = "IAM path of the user, from the conventions module's emergency_user (/sft-emergency/)."
  type        = string

  validation {
    condition     = var.iam_path == "/sft-emergency/"
    error_message = "iam_path must be /sft-emergency/, the path the bucket and key policies and the SCPs expect."
  }
}

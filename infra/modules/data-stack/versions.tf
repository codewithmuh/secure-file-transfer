# The AWS provider for the account's EBS default encryption (storage.tf); everything else is in the modules this one
# calls, which inherit the root's provider, and the built-in terraform_remote_state.
terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"
    }
  }
}

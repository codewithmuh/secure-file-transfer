# No required_providers: this module declares no AWS resources itself, only the modules it calls (which require the AWS
# provider and inherit the root's) and the built-in terraform_remote_state.
terraform {
  required_version = ">= 1.11.0"
}

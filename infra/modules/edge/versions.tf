terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"

      # aws.dns: the shared account, through the environment's DNS role, for the records in the shared zone.
      configuration_aliases = [aws.dns]
    }
  }
}

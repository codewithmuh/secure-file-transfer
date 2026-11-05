terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"

      # aws.us_east_1: the DNSSEC signing key, which Route 53 requires there (NFR-21's exception).
      configuration_aliases = [aws.us_east_1]
    }
  }
}

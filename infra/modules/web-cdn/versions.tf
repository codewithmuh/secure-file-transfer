terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"

      # aws.us_east_1: the certificate, the web ACL and the log delivery CloudFront needs there (NFR-21's exception).
      # aws.dns: the shared account, through the environment's DNS role.
      configuration_aliases = [aws.us_east_1, aws.dns]
    }
  }
}

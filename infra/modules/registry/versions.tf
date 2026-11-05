terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"

      # aws.osaka: the registry key's replica and the replication template (ap-northeast-3).
      configuration_aliases = [aws.osaka]
    }
  }
}

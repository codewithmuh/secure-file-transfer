terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"

      # aws.us_east_1: the Route 53 health check alarms, their topics and key, the one place AWS publishes health
      # check metrics (NFR-21's exception). Osaka's roots pass it too and create nothing there.
      configuration_aliases = [aws.us_east_1]
    }
  }
}

# staging in Tokyo, cluster layer. The EKS cluster, its `system` node group, Karpenter's IAM and the workload roles
# (ADR-0004).
#
# Skeleton from #54: providers, backend and conventions only. An M4 issue fills it.

terraform {
  required_version = "~> 1.17.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.71.0"
    }
  }

  # Partial backend. The bucket names the account, so it comes from -backend-config at init; the key is this
  # directory under infra/ (infra/README.md, "State").
  backend "s3" {
    key          = "environments/staging/ap-northeast-1/cluster/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-1/cluster"
  component   = "cluster"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

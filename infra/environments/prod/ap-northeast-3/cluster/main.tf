# prod in Osaka, cluster layer. The EKS cluster, its `system` node group, Karpenter's IAM and the workload roles
# (ADR-0004). A control plane and one always-on `system` node (architecture 3.2).
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
    key          = "environments/prod/ap-northeast-3/cluster/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-3/cluster"
  component   = "cluster"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

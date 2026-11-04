# prod in Tokyo, cluster-bootstrap layer. Argo CD's Helm release (ADR-0005). Planned and applied only on main, by the
# job that opens the Systems Manager tunnel (ADR-0021), so pull request plans never reach a cluster API.
#
# Skeleton from #54: providers, backend and conventions only. An M4 issue fills it and adds the helm and kubernetes
# providers.

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
    key          = "environments/prod/ap-northeast-1/cluster-bootstrap/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-1/cluster-bootstrap"
  component   = "cluster-bootstrap"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

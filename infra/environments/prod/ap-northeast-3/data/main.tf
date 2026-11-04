# prod in Osaka, data layer. Stateful services: Aurora PostgreSQL, the files buckets, the queues, the rate-limit store
# and the environment's KMS keys (ADR-0011 to ADR-0014, ADR-0017). dev and staging also keep their audit archive here;
# prod keeps it in the retained stack (encryption 8.4). In Osaka these are the pilot light's replicas: the Aurora
# secondary, replica buckets and key replicas (architecture 3.2).
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
    key          = "environments/prod/ap-northeast-3/data/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-3/data"
  component   = "data"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

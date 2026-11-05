# staging in Osaka, data layer. Stateful services: Aurora PostgreSQL, the files buckets, the queues, the rate-limit
# store and the environment's KMS keys (ADR-0011 to ADR-0014, ADR-0017). dev and staging also keep their audit archive
# here; prod keeps it in the retained stack (encryption 8.4).
# In Osaka these are the pilot light's replicas: the Aurora secondary, replica buckets and key replicas
# (architecture 3.2).
#
# Everything comes from modules/data-stack, which holds what every data root shares: Aurora, the counter store and
# the queues (#101), and the keys, buckets and audit archive (#102). This root passes only what differs.
#
# The pilot light's data: the secondary of staging's global database on Aurora Serverless v2, so the first failover
# drill measures its ACUs and its promotion (ADR-0011, capacity 4.5), and an idle counter store and queues.

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
    key          = "environments/staging/ap-northeast-3/data/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-3/data"
  component   = "data"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

module "data" {
  source = "../../../../modules/data-stack"

  account_id  = var.account_id
  conventions = module.conventions

  aurora = {
    cluster_role          = "secondary"
    instance_class        = "db.serverless"
    serverless_capacity   = { min = 1, max = 16 }
    backup_retention_days = 14
  }
  primary_key_arns                 = var.primary_key_arns
  osaka_malware_protection_enabled = var.malware_protection_enabled
  teardown                         = var.teardown
}

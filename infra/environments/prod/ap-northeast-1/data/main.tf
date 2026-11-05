# prod in Tokyo, data layer. Stateful services: Aurora PostgreSQL, the files buckets, the queues, the rate-limit
# store and the environment's KMS keys (ADR-0011 to ADR-0014, ADR-0017). dev and staging also keep their audit archive
# here; prod keeps it in the retained stack (encryption 8.4).
#
# Everything comes from modules/data-stack, which holds what every data root shares: Aurora, the counter store and
# the queues (#101), and the keys, buckets and audit archive (#102). This root passes only what differs.
#
# The primary of prod's global database, with a db.r8g.large writer and a reader in another AZ (ADR-0011), the counter
# store and the queues.

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
    key          = "environments/prod/ap-northeast-1/data/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-1/data"
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
    cluster_role                       = "primary"
    instance_class                     = "db.r8g.large"
    instance_count                     = 2
    backup_retention_days              = 14
    master_secret_recovery_window_days = 30
  }
  osaka_ready             = var.osaka_ready
  master_password_version = var.master_password_version
  teardown                = var.teardown
}

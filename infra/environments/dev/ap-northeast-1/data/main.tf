# dev in Tokyo, data layer. Stateful services: Aurora PostgreSQL, the files buckets, the queues, the rate-limit
# store and the environment's KMS keys (ADR-0011 to ADR-0014, ADR-0017). dev and staging also keep their audit archive
# here; prod keeps it in the retained stack (encryption 8.4).
#
# #101 fills this file, variables.tf and outputs.tf: Aurora, the counter store and the queues, through
# modules/data-stack, which holds what every data root shares. #102 adds the keys and buckets in their own files.
#
# dev's shape (capacity 5.3): one db.t4g.medium writer with no global database, the counter store and the queues.

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
    key          = "environments/dev/ap-northeast-1/data/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "dev"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/dev/ap-northeast-1/data"
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

  # The environment's keys (encryption 4.1). Until #102 merges they come in as a variable; then this line becomes
  # module.kms.key_arns, the keys module in kms.tf.
  kms_key_arns = var.kms_key_arns

  aurora = {
    cluster_role          = "standalone"
    instance_class        = "db.t4g.medium"
    backup_retention_days = 7
  }
  master_password_version = var.master_password_version
  teardown                = var.teardown
}

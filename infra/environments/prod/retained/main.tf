# The retained stack, prod only (encryption 8.4): the audit archive buckets in both Regions, the audit key and its
# replica, and what guards them after teardown: its own state bucket under the audit key, its own deploy role, a trail,
# EventBridge rules in both Regions with an alert topic, and the NFR-19 budget. One root for both Regions, unlike the
# environment's layers: the archive and its key are one unit that outlives prod, and nothing in a failover changes it.
# Its state lives in its own bucket, never the environment's.
#
# Skeleton from #54. #102 adds the audit key, its Osaka replica and the archive buckets in both Regions (archive.tf),
# through the ap-northeast-3 provider alias below. #254 adds the teardown apply (TF_VAR_teardown=true): the key-admin
# role leaves the key policy, and the NFR-19 budget (budget.tf). Still to come: its own state bucket, deploy role,
# trail, EventBridge rules with the alert topic; and, in modules/kms-keys and modules/audit-archive, the teardown
# inputs that take the environment's workload roles out of the key and bucket policies and turn rotation off
# (docs/runbooks/teardown.md lists them as the open prerequisites of a prod teardown).

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
    key          = "environments/prod/retained/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/prod/retained"
  component   = "retained"

  extra_tags = {
    "retention" = "audit-archive"
  }
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# Osaka: the archive bucket and the key replica there. Its region tag names Osaka (infra/README.md, Tags).
provider "aws" {
  alias               = "osaka"
  region              = "ap-northeast-3"
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = merge(module.conventions.tags, { "region" = "ap-northeast-3" })
  }
}

# prod in Tokyo, cluster layer. The EKS cluster with a private API only, its system node group, Karpenter's IAM and
# interruption queue, the workload roles with their Pod Identity associations, and the access entries (ADR-0004,
# ADR-0021; modules/eks-cluster). IAM is global: this stack creates the account's roles, for this cluster and Osaka's.

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
    key          = "environments/prod/ap-northeast-1/cluster/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-1/cluster"
  component   = "cluster"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# The network layer of this environment and Region, from its state in the same bucket: subnets, security groups and
# the Karpenter discovery tag.
data "terraform_remote_state" "network" {
  backend = "s3"

  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/prod/ap-northeast-1/network/terraform.tfstate"
    region = module.conventions.region
  }
}

# Our organization's ID, for the image pull conditions (ADR-0007): read from AWS, never committed.
data "aws_organizations_organization" "current" {
  return_organization_only = true
}

locals {
  network = data.terraform_remote_state.network.outputs
}

module "cluster" {
  source = "../../../../modules/eks-cluster"

  conventions = module.conventions

  environment        = "prod"
  region             = module.conventions.region
  account_id         = var.account_id
  name_prefix        = module.conventions.name_prefix
  global_name_prefix = module.conventions.global_name_prefix
  kms_alias_prefix   = module.conventions.kms_alias_prefix
  organization_id    = data.aws_organizations_organization.current.id
  deploy_role_arn    = module.conventions.bootstrap_role_arns.terraform_deploy

  cluster_regions          = ["ap-northeast-1", "ap-northeast-3"]
  create_iam               = true
  permissions_boundary_arn = "arn:aws:iam::${var.account_id}:policy${module.conventions.bootstrap_iam_path}${module.conventions.global_name_prefix}-workload-boundary"

  availability_zone_ids   = local.network.availability_zone_ids
  private_subnet_ids      = local.network.private_subnet_ids
  endpoint_subnet_ids     = local.network.endpoint_subnet_ids
  security_group_ids      = local.network.security_group_ids
  karpenter_discovery_tag = local.network.karpenter_discovery_tag

  kubernetes_version = "1.37"
  # prod's clusters can't be deleted until the teardown apply turns this off (TF_VAR_teardown, NFR-19, #263).
  deletion_protection = !var.teardown

  # Two always-on system nodes in different AZs (capacity 4.2, 4.3).
  system_node_count = 2
}

# dev in Tokyo, cluster layer. The EKS cluster with a private API only, its system node group, Karpenter's IAM and
# interruption queue, the workload roles with their Pod Identity associations, and the access entries (ADR-0004,
# ADR-0021; modules/eks-cluster). dev is Tokyo only, so this stack creates the account's roles and its trust names one cluster.

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
    key          = "environments/dev/ap-northeast-1/cluster/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "dev"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/dev/ap-northeast-1/cluster"
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
    key    = "environments/dev/ap-northeast-1/network/terraform.tfstate"
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

  environment        = "dev"
  region             = module.conventions.region
  account_id         = var.account_id
  name_prefix        = module.conventions.name_prefix
  global_name_prefix = module.conventions.global_name_prefix
  kms_alias_prefix   = module.conventions.kms_alias_prefix
  organization_id    = data.aws_organizations_organization.current.id
  deploy_role_arn    = module.conventions.bootstrap_role_arns.terraform_deploy

  cluster_regions          = ["ap-northeast-1"]
  create_iam               = true
  permissions_boundary_arn = "arn:aws:iam::${var.account_id}:policy${module.conventions.bootstrap_iam_path}${module.conventions.global_name_prefix}-workload-boundary"

  availability_zone_ids   = local.network.availability_zone_ids
  private_subnet_ids      = local.network.private_subnet_ids
  endpoint_subnet_ids     = local.network.endpoint_subnet_ids
  security_group_ids      = local.network.security_group_ids
  karpenter_discovery_tag = local.network.karpenter_discovery_tag

  kubernetes_version  = "1.37"
  deletion_protection = false

  # Two always-on system nodes in different AZs (capacity 4.2, 4.3).
  system_node_count = 2

  # dev's smaller pools (capacity 4.3): 2 main and 1 scan node at idle, 50 GB volumes (A28).
  node_pools = {
    main = { instance_types = ["m8g.xlarge"], volume_size_gib = 50, cpu_limit = 16, expire_after = "720h", consolidate_after = "5m" }
    scan = { instance_types = ["m8g.xlarge"], volume_size_gib = 50, cpu_limit = 8, expire_after = "720h", consolidate_after = "5m" }
  }
}

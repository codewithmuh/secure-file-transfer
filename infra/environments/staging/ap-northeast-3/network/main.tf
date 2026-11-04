# staging in Osaka, network layer. The VPC, subnets, NAT gateways, VPC endpoints and Route 53 Resolver DNS Firewall
# (ADR-0021). Same module as Tokyo, so the pilot light can't fall behind (T-79).
#
# The pilot light keeps its whole network, so a failover adds no network step (architecture 3.2, ADR-0004):
# three AZs, a NAT gateway and every interface endpoint in each, and S3 in Tokyo as the cross-Region endpoint.

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
    key          = "environments/staging/ap-northeast-3/network/terraform.tfstate"
    region       = "ap-northeast-3"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-3"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-3/network"
  component   = "network"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# Our organization's ID, for the endpoint policies (ADR-0021): read from AWS, never committed. A member account may
# describe its own organization.
data "aws_organizations_organization" "current" {
  return_organization_only = true
}

module "network" {
  source = "../../../../modules/network"

  name_prefix     = module.conventions.name_prefix
  region          = module.conventions.region
  organization_id = data.aws_organizations_organization.current.id

  vpc_cidr_block        = "10.21.0.0/16"
  availability_zone_ids = ["apne3-az1", "apne3-az2", "apne3-az3"]
  peer_region           = "ap-northeast-1"

  flow_log_destination_arn = var.flow_log_destination_arn
}

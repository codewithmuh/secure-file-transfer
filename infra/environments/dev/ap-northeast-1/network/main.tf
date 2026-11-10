# dev in Tokyo, network layer. The VPC, subnets, NAT gateways, VPC endpoints and Route 53 Resolver DNS Firewall
# (ADR-0021).
#
# dev's reduced network (capacity 5.3): two AZs, one NAT gateway, the interface endpoints in one AZ and no
# cross-Region endpoint, since dev is Tokyo only.

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
    key          = "environments/dev/ap-northeast-1/network/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "dev"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/dev/ap-northeast-1/network"
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

  vpc_cidr_block        = "10.10.0.0/16"
  availability_zone_ids = ["apne1-az1", "apne1-az2"]

  # One NAT gateway, and the interface endpoints in one AZ (capacity 5.3). Pods in the other AZ cross to them.
  nat_gateway_availability_zone_ids        = ["apne1-az1"]
  interface_endpoint_availability_zone_ids = ["apne1-az1"]

  flow_log_destination_arn = var.flow_log_destination_arn

  # The API's and the web app's names, for the synthetic probe (#259).
  service_domain = "dev.sft.${var.domain}"
}

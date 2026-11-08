# prod in Tokyo, network layer. The VPC, subnets, NAT gateways, VPC endpoints and Route 53 Resolver DNS Firewall
# (ADR-0021).
#
# Three AZs, a NAT gateway and every interface endpoint in each, and S3 in Osaka as the cross-Region endpoint
# (architecture 3.1).

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
    key          = "environments/prod/ap-northeast-1/network/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "prod"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/prod/ap-northeast-1/network"
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

  vpc_cidr_block        = "10.30.0.0/16"
  availability_zone_ids = ["apne1-az1", "apne1-az2", "apne1-az4"]
  peer_region           = "ap-northeast-3"

  # The key rotation job writes Osaka's idp-client and rotates Osaka's app client from Tokyo, through its proxy
  # listener (encryption 6.4, #185).
  dns_firewall_additional_domains = ["cognito-idp.ap-northeast-3.amazonaws.com", "secretsmanager.ap-northeast-3.amazonaws.com"]

  flow_log_destination_arn = var.flow_log_destination_arn
}

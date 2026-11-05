# staging in Tokyo, cluster-bootstrap layer: the cluster's platform and Argo CD's root Application
# (modules/cluster-bootstrap, ADR-0004, ADR-0005, ADR-0021). Planned and applied only on main, by the job that opens
# the Systems Manager tunnel to a system node (ADR-0021), so pull request plans never reach a cluster API.
#
# One replica of each component (capacity 4.3).

terraform {
  required_version = "~> 1.17.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.71.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "3.3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "3.4.0"
    }
  }

  # Partial backend. The bucket names the account, so it comes from -backend-config at init; the key is this
  # directory under infra/ (infra/README.md, "State").
  backend "s3" {
    key          = "environments/staging/ap-northeast-1/cluster-bootstrap/terraform.tfstate"
    region       = "ap-northeast-1"
    use_lockfile = true
  }
}

module "conventions" {
  source = "../../../../modules/conventions"

  environment = "staging"
  region      = "ap-northeast-1"
  account_id  = var.account_id
  stack       = "environments/staging/ap-northeast-1/cluster-bootstrap"
  component   = "cluster-bootstrap"
}

provider "aws" {
  region              = module.conventions.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = module.conventions.tags
  }
}

# The cluster layer's outputs (#103) and the data layer's database endpoint, from their states in this account's
# bucket.
data "terraform_remote_state" "cluster" {
  backend = "s3"
  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/staging/ap-northeast-1/cluster/terraform.tfstate"
    region = module.conventions.region
  }
}

data "terraform_remote_state" "data" {
  backend = "s3"
  config = {
    bucket = module.conventions.state_bucket_name
    key    = "environments/staging/ap-northeast-1/data/terraform.tfstate"
    region = module.conventions.region
  }
}

# The Operator permission set's role in this account, for the operator API (#111). Identity Center names it.
data "aws_iam_roles" "operator" {
  name_regex  = "^AWSReservedSSO_Operator_[0-9a-f]+$"
  path_prefix = "/aws-reserved/sso.amazonaws.com/"
}

locals {
  cluster = data.terraform_remote_state.cluster.outputs

  # Through the tunnel the API is at a local address, and TLS still checks the cluster's own name (ADR-0021).
  cluster_api_host = coalesce(var.cluster_api_tunnel_url, local.cluster.cluster_endpoint)
  cluster_api_tls_server_name = (
    var.cluster_api_tunnel_url == null ? null : trimprefix(local.cluster.cluster_endpoint, "https://")
  )
  cluster_api_exec = {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", local.cluster.cluster_name, "--region", module.conventions.region]
  }
}

# Short-lived tokens from the deploy role, fetched per call, so a long apply never outlives its token.
provider "kubernetes" {
  host                   = local.cluster_api_host
  tls_server_name        = local.cluster_api_tls_server_name
  cluster_ca_certificate = base64decode(local.cluster.cluster_certificate_authority_data)

  exec {
    api_version = local.cluster_api_exec.api_version
    command     = local.cluster_api_exec.command
    args        = local.cluster_api_exec.args
  }
}

provider "helm" {
  kubernetes = {
    host                   = local.cluster_api_host
    tls_server_name        = local.cluster_api_tls_server_name
    cluster_ca_certificate = base64decode(local.cluster.cluster_certificate_authority_data)
    exec                   = local.cluster_api_exec
  }
}

module "cluster_bootstrap" {
  source = "../../../../modules/cluster-bootstrap"

  environment       = "staging"
  region            = module.conventions.region
  name_prefix       = module.conventions.name_prefix
  account_id        = var.account_id
  shared_account_id = var.shared_account_id
  pilot_light       = false
  high_availability = false

  cluster = {
    name                           = local.cluster.cluster_name
    endpoint                       = local.cluster.cluster_endpoint
    vpc_id                         = local.cluster.vpc_id
    karpenter_interruption_queue   = local.cluster.karpenter.interruption_queue_name
    karpenter_node_class_manifests = local.cluster.karpenter_node_classes
    karpenter_node_pool_manifests  = local.cluster.karpenter_node_pools
  }

  database_host      = data.terraform_remote_state.data.outputs.aurora_endpoint.host
  operator_role_name = one(data.aws_iam_roles.operator.names)

  # What the application's settings need besides the database (deploy/charts/sft): the environment's names in the
  # shared zone (the edge stack's service_domain), the counter store and the files key, from the data layer.
  service_domain = "staging.sft.${var.domain}"
  valkey_host    = data.terraform_remote_state.data.outputs.valkey_endpoint.address
  files_key_arn  = data.terraform_remote_state.data.outputs.kms_key_arns["files"]

  # clamd's image (mirror/clamav/clamav 1.5.4-debian), the one third-party image the application runs; the same
  # digest as deploy/charts/sft/values.yaml, which deploy/tests checks (ADR-0007).
  additional_mirror_digests = ["sha256:c21aa18cc0a358678255a3dfb343a4555b58f71b97d7b869df8fdf7ea0a5b4b1"]

  identity_center_saml = var.identity_center_saml
  github_app           = var.github_app
  cognito_login_domain = var.cognito_login_domain
  cognito_user_pool_id = var.cognito_user_pool_id
}

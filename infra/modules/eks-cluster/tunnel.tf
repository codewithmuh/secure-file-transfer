# The Systems Manager session document for the cluster tunnel (ADR-0021, authn-authz 8.1). The cluster API is private,
# so people and the cluster-bootstrap job reach it by port forwarding through the Systems Manager agent on a system
# node. Unlike AWS-StartPortForwardingSessionToRemoteHost, this document forwards only to the cluster API endpoint (and
# any host in tunnel_extra_hosts) on 443, so a session can't reach anything else in the VPC.
#
# Who may start a session lives with the principals: the deploy role's StartSession grant in the terraform-oidc-roles
# module (cluster-bootstrap, #104), and ReadOnly's and Operator's in the organization stack's permission sets. Each
# names this document and the system node group's instances (eks:nodegroup-name), and nothing else.

locals {
  cluster_endpoint_host = trimprefix(aws_eks_cluster.this.endpoint, "https://")
}

resource "aws_ssm_document" "tunnel" {
  name            = "${var.name_prefix}-cluster-tunnel"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Port forwarding to the private API of ${local.cluster_name} on 443, and nowhere else (ADR-0021)."
    sessionType   = "Port"
    parameters = {
      host = {
        type          = "String"
        description   = "The cluster API endpoint, or another host this document allows."
        allowedValues = concat([local.cluster_endpoint_host], var.tunnel_extra_hosts)
        default       = local.cluster_endpoint_host
      }
      portNumber = {
        type          = "String"
        description   = "Remote port: 443 only."
        allowedValues = ["443"]
        default       = "443"
      }
      localPortNumber = {
        type           = "String"
        description    = "Local port; 0 picks a free one."
        allowedPattern = "^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
        default        = "0"
      }
    }
    properties = {
      type            = "LocalPortForwarding"
      host            = "{{ host }}"
      portNumber      = "{{ portNumber }}"
      localPortNumber = "{{ localPortNumber }}"
    }
  })

  tags = {
    component = "eks"
  }
}

# What the cluster-bootstrap layer (#104) builds on, read from the cluster root's state.

output "cluster_name" {
  description = "Name of the EKS cluster: sft-<env>-<region-short>-eks."
  value       = aws_eks_cluster.this.name
}

output "cluster_arn" {
  description = "ARN of the EKS cluster."
  value       = aws_eks_cluster.this.arn
}

output "cluster_endpoint" {
  description = "The cluster API's private endpoint (ADR-0021). Reachable only from the VPC, so from outside through the tunnel."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority_data" {
  description = "The cluster's certificate authority, base64-encoded, for kubeconfig and providers."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_version" {
  description = "The cluster's Kubernetes minor version."
  value       = aws_eks_cluster.this.version
}

output "oidc_issuer_url" {
  description = "The cluster's OIDC issuer. For reference only: workloads use Pod Identity, never IRSA (ADR-0004)."
  value       = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

output "cluster_security_group_id" {
  description = "EKS's own cluster security group. No node uses it: it allows all egress (network module)."
  value       = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
}

output "system_node_group_name" {
  description = "Name of the system managed node group; EKS tags its instances eks:nodegroup-name with it (the tunnel's end)."
  value       = aws_eks_node_group.system.node_group_name
}

output "karpenter" {
  description = "What Karpenter's Helm values need: its role, its nodes' role and instance profile, and the interruption queue."
  value = {
    controller_role_arn        = local.role_arns.karpenter
    node_role_name             = local.role_names.karpenter_node
    node_instance_profile_name = local.role_names.karpenter_node
    interruption_queue_name    = aws_sqs_queue.interruption.name
    namespace                  = local.karpenter_namespace
    service_account            = local.karpenter_service_account
  }
}

output "karpenter_node_classes" {
  description = "Karpenter v1 EC2NodeClass manifests, keyed main and scan, for cluster-bootstrap to apply as they are."
  value       = local.karpenter_node_classes
}

output "karpenter_node_pools" {
  description = "Karpenter v1 NodePool manifests, keyed main and scan, for cluster-bootstrap to apply as they are."
  value       = local.karpenter_node_pools
}

output "pod_identity" {
  description = <<-EOT
    Every Pod Identity role by workload: namespace, service accounts (service_account is the first) and role ARN.
    The associations exist already; the Helm chart and cluster-bootstrap only create the service accounts.
  EOT
  value = {
    for k, p in local.pod_identities : k => {
      namespace        = p.namespace
      service_account  = p.service_accounts[0]
      service_accounts = p.service_accounts
      role_arn         = local.role_arns[k]
    }
  }
}

output "role_arns" {
  description = "ARNs of every role this module names, by key: cluster, node roles, controllers and workloads."
  value       = local.role_arns
}

output "systems_manager" {
  description = "The tunnel: the session document's name and the system node group whose instances end it (ADR-0021)."
  value = {
    document_name   = aws_ssm_document.tunnel.name
    node_group_name = aws_eks_node_group.system.node_group_name
  }
}

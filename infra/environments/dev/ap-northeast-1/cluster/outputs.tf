# Read by the cluster-bootstrap stack of this environment and Region (#104), and by the runbooks.

output "cluster_name" {
  description = "Name of the EKS cluster."
  value       = module.cluster.cluster_name
}

output "cluster_arn" {
  description = "ARN of the EKS cluster."
  value       = module.cluster.cluster_arn
}

output "cluster_endpoint" {
  description = "The cluster API's private endpoint, reached through the Systems Manager tunnel (ADR-0021)."
  value       = module.cluster.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "The cluster's certificate authority, base64-encoded."
  value       = module.cluster.cluster_certificate_authority_data
}

output "cluster_version" {
  description = "The cluster's Kubernetes minor version."
  value       = module.cluster.cluster_version
}

output "oidc_issuer_url" {
  description = "The cluster's OIDC issuer, for reference only: workloads use Pod Identity, never IRSA (ADR-0004)."
  value       = module.cluster.oidc_issuer_url
}

output "cluster_security_group_id" {
  description = "EKS's own cluster security group, which no node uses."
  value       = module.cluster.cluster_security_group_id
}

output "vpc_id" {
  description = "The VPC, for the Load Balancer Controller, which can't read it from IMDS with a hop limit of 1."
  value       = local.network.vpc_id
}

output "node_security_group_ids" {
  description = "Node security groups by role: nodes, system_nodes, main_nodes, scan_nodes (network layer)."
  value       = { for k in ["nodes", "system_nodes", "main_nodes", "scan_nodes"] : k => local.network.security_group_ids[k] }
}

output "private_subnet_ids" {
  description = "The private subnets the nodes run in."
  value       = values(local.network.private_subnet_ids)
}

output "karpenter_discovery_tag" {
  description = "Tag on the private subnets that the Karpenter node classes select."
  value       = local.network.karpenter_discovery_tag
}

output "system_node_group_name" {
  description = "The system managed node group, whose instances end the tunnel (eks:nodegroup-name)."
  value       = module.cluster.system_node_group_name
}

output "karpenter" {
  description = "Karpenter's controller role, node role, instance profile, interruption queue, namespace and service account."
  value       = module.cluster.karpenter
}

output "karpenter_node_classes" {
  description = "Karpenter v1 EC2NodeClass manifests, keyed main and scan."
  value       = module.cluster.karpenter_node_classes
}

output "karpenter_node_pools" {
  description = "Karpenter v1 NodePool manifests, keyed main and scan."
  value       = module.cluster.karpenter_node_pools
}

output "pod_identity" {
  description = "Pod Identity roles by workload: namespace, service accounts and role ARN."
  value       = module.cluster.pod_identity
}

output "role_arns" {
  description = "ARNs of the account's cluster, node, controller and workload roles."
  value       = module.cluster.role_arns
}

output "systems_manager" {
  description = "The tunnel's session document and the node group that ends it (ADR-0021)."
  value       = module.cluster.systems_manager
}

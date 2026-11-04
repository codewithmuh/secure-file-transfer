# Read by the data, cluster and edge stacks of this environment and Region (infra/modules/network/outputs.tf).

output "vpc_id" {
  description = "ID of the VPC."
  value       = module.network.vpc_id
}

output "vpc_cidr_block" {
  description = "The VPC's IPv4 range."
  value       = module.network.vpc_cidr_block
}

output "availability_zone_ids" {
  description = "The VPC's AZ IDs."
  value       = module.network.availability_zone_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs by AZ ID: the load balancer and the NAT gateways."
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnet IDs by AZ ID: nodes, pods and the Cognito trigger functions."
  value       = module.network.private_subnet_ids
}

output "endpoint_subnet_ids" {
  description = "Endpoint subnet IDs by AZ ID: the cluster API's network interfaces and the interface endpoints."
  value       = module.network.endpoint_subnet_ids
}

output "isolated_subnet_ids" {
  description = "Isolated subnet IDs by AZ ID, with no route out: Aurora and Valkey."
  value       = module.network.isolated_subnet_ids
}

output "private_subnet_cidr_blocks" {
  description = "Private subnet ranges by AZ ID."
  value       = module.network.private_subnet_cidr_blocks
}

output "endpoint_subnet_cidr_blocks" {
  description = "Endpoint subnet ranges by AZ ID, which network policies let pods reach on 443."
  value       = module.network.endpoint_subnet_cidr_blocks
}

output "isolated_subnet_cidr_blocks" {
  description = "Isolated subnet ranges by AZ ID, where Aurora and Valkey listen."
  value       = module.network.isolated_subnet_cidr_blocks
}

output "private_route_table_ids" {
  description = "Private route table IDs by AZ ID."
  value       = module.network.private_route_table_ids
}

output "nat_gateway_public_ips" {
  description = "The NAT gateways' public addresses by AZ ID, for the sign-in web ACL (abuse 3.2)."
  value       = module.network.nat_gateway_public_ips
}

output "security_group_ids" {
  description = "Security group IDs by role: endpoints, cluster_api, nodes, system_nodes, main_nodes, scan_nodes."
  value       = module.network.security_group_ids
}

output "s3_prefix_list_id" {
  description = "Prefix list of S3 in this Region (the gateway endpoint)."
  value       = module.network.s3_prefix_list_id
}

output "vpc_endpoint_ids" {
  description = "VPC endpoint IDs by key, for aws:SourceVpce conditions in bucket and key policies."
  value       = module.network.vpc_endpoint_ids
}

output "dns_firewall_allowed_domains" {
  description = "Every name DNS Firewall answers in this VPC."
  value       = module.network.dns_firewall_allowed_domains
}

output "flow_log_id" {
  description = "ID of the VPC flow log, or null until flow_log_destination_arn is set."
  value       = module.network.flow_log_id
}

output "karpenter_discovery_tag" {
  description = "Tag on the private subnets for Karpenter's subnetSelectorTerms."
  value       = module.network.karpenter_discovery_tag
}

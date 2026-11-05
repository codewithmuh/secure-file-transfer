# Read by the mirror workflow (ADR-0007) and the cluster-bootstrap job.

output "mirrored_images" {
  description = "Third-party images the platform runs, upstream and mirror/ by digest."
  value       = module.cluster_bootstrap.mirrored_images
}

output "charts" {
  description = "The Helm charts installed, by exact version."
  value       = module.cluster_bootstrap.charts
}

output "egress_proxy" {
  description = "The egress proxy's listeners, for HTTPS_PROXY."
  value       = module.cluster_bootstrap.egress_proxy
}

output "argocd" {
  description = "Argo CD's URL and the root Application's source."
  value       = module.cluster_bootstrap.argocd
}

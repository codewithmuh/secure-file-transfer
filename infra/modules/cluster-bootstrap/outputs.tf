output "mirrored_images" {
  description = "Every third-party image the platform runs: upstream reference and the mirror/ repository it is copied to, by digest (ADR-0007). The mirror workflow reads it."
  value = {
    for k, i in local.images : k => {
      upstream = "${i.upstream}@${i.digest}"
      mirror   = "${i.repository}@${i.digest}"
      tag      = i.tag
    }
  }
}

output "charts" {
  description = "The Helm charts installed, by name and exact version."
  value       = { for k, c in local.charts : k => "${c.chart}@${c.version}" }
}

output "egress_proxy" {
  description = "The egress proxy's Service and its listeners' URLs by workload, for HTTPS_PROXY (ADR-0021)."
  value = {
    host      = local.proxy_host
    listeners = local.proxy_url
    no_proxy  = local.no_proxy
  }
}

output "argocd" {
  description = "Argo CD's URL through the tunnel, and what the root Application syncs."
  value = {
    url             = var.argocd_url
    root_repository = local.repository_url
    root_revision   = "main"
    root_path       = "deploy/argocd"
  }
}

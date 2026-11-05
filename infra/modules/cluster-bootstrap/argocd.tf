# Argo CD (ADR-0004, ADR-0005) on the system nodes, and the root Application that installs the application from
# deploy/argocd on main (#106).
#
# - Git is the only way in: auto-sync with prune and self-heal, the local admin off, exec off, and Identity Center
#   groups mapped to read-only, so nobody changes an Application's source, revision, parameters or sync by hand.
# - Sign-in is SAML through Identity Center's customer managed application, by Dex; people reach the API server
#   through the Systems Manager tunnel (ADR-0021).
# - Notifications post a GitHub deployment status per Application and cluster, which the promotion gate reads
#   (ADR-0005), through the Argo CD listener of the egress proxy.

locals {
  repository_url = "https://github.com/codewithmuh/secure-file-transfer.git"

  # GitHub deployment environments, one per Application and cluster. Named apart from dev, staging, prod and shared,
  # the GitHub environments the deploy roles trust (T-71).
  deployment_environment = "argocd-${var.name_prefix}-{{.app.metadata.name}}"

  argocd_component = {
    nodeSelector = local.system_scheduling.nodeSelector
    tolerations  = local.system_scheduling.tolerations
  }

  dex_config = var.identity_center_saml == null ? null : yamlencode({
    connectors = [{
      type = "saml"
      id   = "identity-center"
      name = "AWS IAM Identity Center"
      config = {
        ssoURL       = var.identity_center_saml.sso_url
        caData       = var.identity_center_saml.ca_data
        redirectURI  = "${var.argocd_url}/api/dex/callback"
        entityIssuer = "${var.argocd_url}/api/dex/callback"
        usernameAttr = "email"
        emailAttr    = "email"
        groupsAttr   = "groups"
      }
    }]
  })

  # Read-only for ReadOnly and Operator (authn-authz 8.1); nobody else may do anything. Identity Center's assertion
  # carries group IDs.
  rbac_policy = var.identity_center_saml == null ? "" : join("\n", [
    "g, ${var.identity_center_saml.readonly_group_id}, role:readonly",
    "g, ${var.identity_center_saml.operator_group_id}, role:readonly",
    "",
  ])

  deployment_status = {
    for name, state in { "app-deployed" = "success", "app-sync-failed" = "failure", "app-degraded" = "error" } :
    "template.${name}" => yamlencode({
      message = "{{.app.metadata.name}} in ${var.name_prefix}: ${state} at {{.app.status.sync.revision}}"
      github = {
        repoURLPath  = "{{.app.spec.source.repoURL}}"
        revisionPath = "{{.app.status.sync.revision}}"
        deployment = {
          state                = state
          environment          = local.deployment_environment
          logURL               = "{{.context.argocdUrl}}/applications/argocd/{{.app.metadata.name}}"
          reference            = "{{.app.status.sync.revision}}"
          requiredContexts     = []
          autoMerge            = false
          transientEnvironment = false
        }
      }
    })
  }

  notification_triggers = {
    "trigger.on-deployed" = yamlencode([{
      when    = "app.status.operationState != nil and app.status.operationState.phase in ['Succeeded'] and app.status.health.status == 'Healthy'"
      oncePer = "app.status.sync.revision"
      send    = ["app-deployed"]
    }])
    "trigger.on-sync-failed" = yamlencode([{
      when = "app.status.operationState != nil and app.status.operationState.phase in ['Error', 'Failed']"
      send = ["app-sync-failed"]
    }])
    "trigger.on-health-degraded" = yamlencode([{
      when = "app.status.health.status == 'Degraded'"
      send = ["app-degraded"]
    }])
  }
}

resource "helm_release" "argocd" {
  name             = "argocd"
  repository       = local.charts.argo_cd.repository
  chart            = local.charts.argo_cd.chart
  version          = local.charts.argo_cd.version
  namespace        = kubernetes_namespace_v1.platform["argocd"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 900

  values = [yamlencode({
    global = merge(local.argocd_component, {
      domain = trimprefix(var.argocd_url, "https://")
      image = {
        repository = local.image_repo["argocd"]
        tag        = local.image_tag["argocd"]
      }
      networkPolicy = { create = true, defaultDenyIngress = true }
    })
    crds = { install = true, keep = true }
    configs = {
      cm = merge({
        url                                  = var.argocd_url
        "admin.enabled"                      = false
        "exec.enabled"                       = false
        "users.anonymous.enabled"            = false
        "statusbadge.enabled"                = false
        "timeout.reconciliation"             = "180s"
        "application.resourceTrackingMethod" = "annotation"
        }, local.dex_config == null ? {} : {
        "dex.config" = local.dex_config
      })
      rbac = {
        "policy.default" = ""
        "policy.csv"     = local.rbac_policy
        scopes           = "[groups]"
      }
      params = {
        # Applications live in argocd only, and ApplicationSets may not read source code hosts' APIs.
        "applicationsetcontroller.enable.scm.providers" = false
      }
    }
    controller     = { replicas = 1 }
    applicationSet = { replicas = 1 }
    server         = { replicas = local.replicas }
    # The repository server reads Git from github.com through the proxy (ADR-0005, ADR-0021).
    repoServer = { replicas = local.replicas, env = local.proxy_env["argocd"] }
    redis = {
      image = { repository = local.image_repo["redis"], tag = local.image_tag["redis"] }
    }
    dex = {
      enabled = var.identity_center_saml != null
      image   = { repository = local.image_repo["dex"], tag = local.image_tag["dex"] }
    }
    notifications = {
      enabled  = var.github_app != null
      extraEnv = local.proxy_env["argocd"]
      context  = { argocdUrl = var.argocd_url }
      # External Secrets writes it from Secrets Manager (external-secrets.tf).
      secret = { create = false }
      notifiers = var.github_app == null ? {} : {
        "service.github" = yamlencode({
          appID          = tonumber(var.github_app.app_id)
          installationID = tonumber(var.github_app.installation_id)
          privateKey     = "$github-privateKey"
        })
      }
      templates = local.deployment_status
      triggers  = local.notification_triggers
      subscriptions = [{
        recipients = ["github"]
        triggers   = ["on-deployed", "on-sync-failed", "on-health-degraded"]
      }]
    }
  })]

  depends_on = [helm_release.kyverno_policies, helm_release.external_secrets_store]
}

# The root Application and its project (#106). Project bootstrap may sync only this repository's deploy/argocd into
# the argocd namespace, and only AppProjects and Applications, so everything the application runs is in a project of
# its own that Git defines. The cluster facts the application needs, which are never committed, are handed in here.
resource "helm_release" "argocd_root" {
  name             = "argocd-root"
  repository       = local.charts.argocd_apps.repository
  chart            = local.charts.argocd_apps.chart
  version          = local.charts.argocd_apps.version
  namespace        = kubernetes_namespace_v1.platform["argocd"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 300

  values = [yamlencode({
    projects = {
      bootstrap = {
        namespace                  = "argocd"
        description                = "The root Application: AppProjects and Applications from deploy/argocd on main."
        sourceRepos                = [local.repository_url]
        destinations               = [{ server = "https://kubernetes.default.svc", namespace = "argocd" }]
        clusterResourceWhitelist   = []
        namespaceResourceWhitelist = [{ group = "argoproj.io", kind = "AppProject" }, { group = "argoproj.io", kind = "Application" }]
      }
    }
    applications = {
      root = {
        namespace = "argocd"
        project   = "bootstrap"
        source = {
          repoURL = local.repository_url
          # main only (ADR-0005, T-72): every change Argo CD applies was reviewed and merged.
          targetRevision = "main"
          path           = "deploy/argocd"
          helm = {
            valuesObject = {
              environment = var.environment
              region      = var.region
              # The facts deploy/argocd's schema requires, and the user pool's once it exists (null is left out,
              # so the application chart names what is missing).
              cluster = { for k, v in {
                registry           = local.registry
                databaseHost       = var.database_host
                accountId          = var.account_id
                operatorRoleName   = var.operator_role_name
                serviceDomain      = var.service_domain
                valkeyHost         = var.valkey_host
                filesKeyArn        = var.files_key_arn
                userPoolId         = var.cognito_user_pool_id
                cognitoLoginDomain = var.cognito_login_domain
              } : k => v if v != null }
            }
          }
        }
        destination = { server = "https://kubernetes.default.svc", namespace = "argocd" }
        syncPolicy = {
          automated = { prune = true, selfHeal = true }
          retry     = { limit = 10, backoff = { duration = "30s", factor = 2, maxDuration = "10m" } }
        }
      }
    }
  })]

  depends_on = [helm_release.argocd]
}

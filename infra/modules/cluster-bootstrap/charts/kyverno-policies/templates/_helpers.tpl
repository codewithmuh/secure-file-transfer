{{/* The pod controllers each pod policy also covers, so a bad Deployment fails at once, not at its first pod. */}}
{{- define "policies.autogen" -}}
autogen:
  podControllers:
    controllers: [deployments, statefulsets, daemonsets, jobs, cronjobs, replicasets]
{{- end }}

{{/* Every container of a pod: regular, init and ephemeral. */}}
{{- define "policies.containers" -}}
- name: containers
  expression: >-
    object.spec.containers +
    object.spec.?initContainers.orValue([]) +
    object.spec.?ephemeralContainers.orValue([])
{{- end }}

{{- define "policies.podRules" -}}
resourceRules:
- apiGroups: [""]
  apiVersions: [v1]
  operations: [CREATE, UPDATE]
  resources: [pods, pods/ephemeralcontainers]
{{- end }}

{{- define "policies.labels" -}}
app.kubernetes.io/part-of: sft-platform
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "prom.image" -}}
{{- $root := index . 0 }}{{ $image := index . 1 -}}
{{ required "global.imageRegistry is required" $root.Values.global.imageRegistry }}/{{ $image.repository }}:{{ $image.tag }}@{{ $image.digest }}
{{- end }}

{{- /* sft-<env>-<region-short>, the cluster's name prefix in AWS (infra/modules/conventions). */}}
{{- define "prom.prefix" -}}
sft-{{ required "global.sft.environment is required" .Values.global.sft.environment }}-{{ ternary "apne1" "apne3" (eq (required "global.sft.region is required" .Values.global.sft.region) "ap-northeast-1") }}
{{- end }}

{{- define "prom.labels" -}}
app.kubernetes.io/part-of: sft-observability
{{- end }}

{{- /* The container rules of ADR-0004 for every container here. */}}
{{- define "prom.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: [ALL] }
{{- end }}

{{- define "prom.podSecurity" -}}
runAsNonRoot: true
runAsUser: 65534
runAsGroup: 65534
fsGroup: 65534
seccompProfile: { type: RuntimeDefault }
{{- end }}

{{- /* Network policy rules (ADR-0021). */}}
{{- define "prom.dns" -}}
- to:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
      podSelector: { matchLabels: { k8s-app: kube-dns } }
  ports:
    - { port: 53, protocol: UDP }
    - { port: 53, protocol: TCP }
{{- end }}

{{- define "prom.podIdentity" -}}
- to:
    - ipBlock: { cidr: {{ .Values.network.podIdentityAgent }} }
  ports:
    - { port: 80, protocol: TCP }
{{- end }}

{{- define "prom.clusterApi" -}}
- to:
    - ipBlock: { cidr: {{ required "network.endpointSubnetsCidr is required" .Values.network.endpointSubnetsCidr }} }
  ports:
    - { port: 443, protocol: TCP }
{{- end }}

{{- define "prom.platformProxy" -}}
- to:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: {{ .Values.network.egressProxy.namespace }} } }
      podSelector: { matchLabels: {{ toJson .Values.network.egressProxy.podLabels }} }
  ports:
    - { port: {{ .Values.network.egressProxy.platformPort }}, protocol: TCP }
{{- end }}

{{- define "prom.fromPrometheus" -}}
- from:
    - podSelector: { matchLabels: { app.kubernetes.io/name: prometheus } }
  ports:
    {{- range . }}
    - { port: {{ . }}, protocol: TCP }
    {{- end }}
{{- end }}

{{- define "prom.fromGrafana" -}}
- from:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: grafana } }
      podSelector: { matchLabels: { app.kubernetes.io/name: grafana } }
  ports:
    {{- range . }}
    - { port: {{ . }}, protocol: TCP }
    {{- end }}
{{- end }}

{{- /*
deploy/alerts/alertmanager.yaml's matchers ("name=\"value\"", "name!=\"v\"", "name=~\"re\"", "name!~\"re\"") as
AlertmanagerConfig matchers. Call with the list of strings.
*/}}
{{- define "prom.amMatchers" -}}
{{- $pattern := "^([a-zA-Z_][a-zA-Z0-9_]*)(=~|!~|!=|=)\"(.*)\"$" }}
{{- range . }}
{{- if not (regexMatch $pattern .) }}{{ fail (printf "alertmanager.yaml: unsupported matcher %q" .) }}{{ end }}
- name: {{ regexReplaceAll $pattern . "${1}" }}
  matchType: {{ regexReplaceAll $pattern . "${2}" | quote }}
  value: {{ regexReplaceAll $pattern . "${3}" | quote }}
{{- end }}
{{- end }}

{{- /* One route of deploy/alerts/alertmanager.yaml, and its child routes, in AlertmanagerConfig's names. */}}
{{- define "prom.amRoute" -}}
receiver: {{ .receiver }}
{{- with .group_by }}
groupBy: {{ toJson . }}
{{- end }}
{{- with .group_wait }}
groupWait: {{ . }}
{{- end }}
{{- with .group_interval }}
groupInterval: {{ . }}
{{- end }}
{{- with .repeat_interval }}
repeatInterval: {{ . }}
{{- end }}
{{- with .matchers }}
matchers:
  {{- include "prom.amMatchers" . | nindent 2 }}
{{- end }}
{{- with .routes }}
routes:
  {{- range . }}
  - {{- include "prom.amRoute" . | nindent 4 }}
  {{- end }}
{{- end }}
{{- end }}

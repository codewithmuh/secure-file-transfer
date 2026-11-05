{{- define "egress-proxy.labels" -}}
app.kubernetes.io/name: egress-proxy
app.kubernetes.io/part-of: sft-platform
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "egress-proxy.selector" -}}
app.kubernetes.io/name: egress-proxy
{{- end }}

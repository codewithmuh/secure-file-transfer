{{- define "grafana.cluster" -}}
sft-{{ .Values.global.sft.environment }}-{{ ternary "apne1" "apne3" (eq .Values.global.sft.region "ap-northeast-1") }}
{{- end }}

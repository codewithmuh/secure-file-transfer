{{- define "collectors.image" -}}
{{ required "global.imageRegistry is required" .Values.global.imageRegistry }}/{{ .Values.collectorImage.repository }}:{{ .Values.collectorImage.tag }}@{{ .Values.collectorImage.digest }}
{{- end }}

{{- define "collectors.cluster" -}}
sft-{{ .Values.global.sft.environment }}-{{ ternary "apne1" "apne3" (eq .Values.global.sft.region "ap-northeast-1") }}
{{- end }}

{{- /* The container rules of ADR-0004 that apply to every collector: no capabilities, no escalation, read-only root. */}}
{{- define "collectors.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: [ALL] }
{{- end }}

{{- define "collectors.dns" -}}
- to:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
      podSelector: { matchLabels: { k8s-app: kube-dns } }
  ports:
    - { port: 53, protocol: UDP }
    - { port: 53, protocol: TCP }
{{- end }}

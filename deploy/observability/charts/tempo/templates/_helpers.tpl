{{- /*
Network policy rules shared by the observability charts (ADR-0021): CoreDNS, the Pod Identity agent on the node, and S3
through its gateway endpoint, which a pod reaches as addresses outside the VPC on 443 (the node security groups narrow
them to S3's prefix list). Each chart keeps its own copy of these few lines.
*/}}
{{- define "obs.dns" -}}
- to:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
      podSelector: { matchLabels: { k8s-app: kube-dns } }
  ports:
    - { port: 53, protocol: UDP }
    - { port: 53, protocol: TCP }
{{- end }}

{{- define "obs.podIdentity" -}}
- to:
    - ipBlock: { cidr: {{ .Values.network.podIdentityAgent }} }
  ports:
    - { port: 80, protocol: TCP }
{{- end }}

{{- define "obs.s3" -}}
- to:
    - ipBlock: { cidr: 0.0.0.0/0, except: [{{ required "network.vpcCidr is required" .Values.network.vpcCidr }}, 169.254.0.0/16] }
  ports:
    - { port: 443, protocol: TCP }
{{- end }}

{{- define "obs.from" -}}
- from:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: {{ .namespace }} } }
      podSelector: { matchLabels: { app.kubernetes.io/name: {{ .name }} } }
  ports:
    {{- range .ports }}
    - { port: {{ . }}, protocol: TCP }
    {{- end }}
{{- end }}

{{/* clamd's and its updater's configuration files, as ConfigMap data. */}}
{{- define "sft.clamavConfig" -}}
clamd.conf: |
  {{- tpl (.Files.Get "files/clamd.conf") . | nindent 2 }}
freshclam.conf: |
  {{- tpl (.Files.Get "files/freshclam-clamd.conf") . | nindent 2 }}
{{- end -}}

{{/* Required: never two pods of this component on one node. */}}
{{- define "sft.onePerNode" -}}
podAntiAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    - topologyKey: kubernetes.io/hostname
      labelSelector:
        matchLabels:
          app.kubernetes.io/name: sft
          app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Required: on a node with a scan worker of this pool, and never beside another pod of this component. */}}
{{- define "sft.besideWorker" -}}
podAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    - topologyKey: kubernetes.io/hostname
      labelSelector:
        matchLabels:
          app.kubernetes.io/name: sft
          app.kubernetes.io/component: scan-worker
          sft.io/scan-pool: {{ .pool }}
{{ include "sft.onePerNode" . }}
{{- end -}}

{{/* Copies the signatures baked into the image into the writable database directory, so clamd starts without the mirror. */}}
{{- define "sft.seedSignatures" -}}
- name: seed-signatures
  image: {{ include "sft.clamavImage" . }}
  imagePullPolicy: IfNotPresent
  command: [cp, -R, /var/lib/clamav/., /seed/]
  resources:
    requests: { cpu: 100m, memory: 64Mi }
    limits: { memory: 128Mi }
  securityContext:
    {{- include "sft.containerSecurityContext" . | nindent 4 }}
  volumeMounts:
    - { name: signatures, mountPath: /seed }
{{- end -}}

{{- define "sft.clamdContainers" -}}
{{- $c := .Values.clamd -}}
- name: clamd
  image: {{ include "sft.clamavImage" . }}
  imagePullPolicy: IfNotPresent
  # The image's unprivileged entry point: clamd plus freshclam, which updates from the private mirror only.
  command: [/init-unprivileged]
  env:
    - { name: CLAMAV_NO_MILTERD, value: "true" }
  ports:
    - { name: clamd, containerPort: {{ $c.port }}, protocol: TCP }
  startupProbe: # loading the signatures takes a while
    tcpSocket: { port: clamd }
    periodSeconds: 5
    failureThreshold: 60
  livenessProbe:
    tcpSocket: { port: clamd }
    periodSeconds: 15
    timeoutSeconds: 5
    failureThreshold: 4
  readinessProbe: # PING over the socket
    exec: { command: [clamdcheck.sh] }
    periodSeconds: 10
    timeoutSeconds: 5
    failureThreshold: 3
  resources:
    {{- toYaml $c.resources | nindent 4 }}
  securityContext:
    {{- include "sft.containerSecurityContext" . | nindent 4 }}
  volumeMounts:
    - { name: tmp, mountPath: /tmp }
    - { name: config, mountPath: /etc/clamav, readOnly: true }
    - { name: signatures, mountPath: /var/lib/clamav }
    - { name: run, mountPath: /run/clamav }
    - { name: scratch, mountPath: /scratch }
{{- end -}}

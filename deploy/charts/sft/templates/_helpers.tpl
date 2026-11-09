{{/*
Shared pieces. Every pod is built from these, so the runtime contract (architecture 8) and the pod security of
ADR-0004 are written once: deploy/tests/ checks every rendered container against them.
*/}}

{{/* Fails the render on a missing setting, so a bad values file stops in CI and in Argo CD, never in a pod. */}}
{{- define "sft.validate" -}}
{{- $v := .Values -}}
{{- if not (has $v.environment (list "dev" "staging" "prod")) }}{{ fail "environment must be dev, staging or prod (from the root Application)" }}{{ end -}}
{{- if not (has $v.region (list "ap-northeast-1" "ap-northeast-3")) }}{{ fail "region must be ap-northeast-1 or ap-northeast-3 (from the root Application)" }}{{ end -}}
{{- if not (has $v.part (list "application" "operator")) }}{{ fail "part must be application or operator" }}{{ end -}}
{{- if not (regexMatch "^[0-9]{12}\\.dkr\\.ecr\\.ap-northeast-[13]\\.amazonaws\\.com$" (required "cluster.registry is required (from the root Application)" $v.cluster.registry)) }}{{ fail "cluster.registry must be <account>.dkr.ecr.<region>.amazonaws.com" }}{{ end -}}
{{- if not (contains $v.region $v.cluster.registry) }}{{ fail "cluster.registry must be the registry in this cluster's region" }}{{ end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" (required "image.digest is required (the cluster's values file)" $v.image.digest)) }}{{ fail "image.digest must be sha256: and 64 hex digits" }}{{ end -}}
{{- $_ := required "cluster.databaseHost is required (from the root Application)" $v.cluster.databaseHost -}}
{{- $_ := required "cluster.valkeyHost is required (from the root Application)" $v.cluster.valkeyHost -}}
{{- if not (regexMatch "^[0-9]{12}$" (toString (required "cluster.accountId is required (from the root Application)" $v.cluster.accountId))) }}{{ fail "cluster.accountId must be 12 digits, quoted" }}{{ end -}}
{{- if eq $v.part "application" -}}
{{- if not (regexMatch "^([a-z0-9-]+\\.)*sft\\.[a-z0-9.-]+$" (required "cluster.serviceDomain is required (from the root Application)" $v.cluster.serviceDomain)) }}{{ fail "cluster.serviceDomain must be sft.<domain> or <env>.sft.<domain>" }}{{ end -}}
{{- if not (regexMatch (printf "^arn:aws:kms:%s:[0-9]{12}:key/mrk-[0-9a-f]{32}$" $v.region) (required "cluster.filesKeyArn is required (from the root Application)" $v.cluster.filesKeyArn)) }}{{ fail "cluster.filesKeyArn must be the files key's ARN in this cluster's region" }}{{ end -}}
{{- if not (regexMatch (printf "^%s_[0-9A-Za-z]+$" $v.region) (required "cluster.userPoolId is required (from the root Application, once the user pool exists)" $v.cluster.userPoolId)) }}{{ fail "cluster.userPoolId must be a user pool ID in this cluster's region" }}{{ end -}}
{{- if not (regexMatch "^[a-z0-9.-]+$" (required "cluster.cognitoLoginDomain is required (from the root Application, once the user pool exists)" $v.cluster.cognitoLoginDomain)) }}{{ fail "cluster.cognitoLoginDomain must be a plain host name" }}{{ end -}}
{{- if ne (required "cluster.sesConfigurationSet is required (from the root Application, once the identity layer exists)" $v.cluster.sesConfigurationSet) (printf "sft-%s" $v.environment) }}{{ fail "cluster.sesConfigurationSet must be sft-<env>" }}{{ end -}}
{{- if eq $v.region "ap-northeast-1" -}}
{{- if not (regexMatch "^[0-9a-z]+$" (required "cluster.appClientId is required in Tokyo, for the key rotation job (from the root Application)" $v.cluster.appClientId)) }}{{ fail "cluster.appClientId must be an app client ID" }}{{ end -}}
{{- if ne $v.environment "dev" -}}
{{- if not (regexMatch "^ap-northeast-3_[0-9A-Za-z]+$" (required "cluster.standbyUserPoolId is required in Tokyo outside dev (Osaka's pool, for the key rotation job)" $v.cluster.standbyUserPoolId)) }}{{ fail "cluster.standbyUserPoolId must be a user pool ID in Osaka" }}{{ end -}}
{{- if not (regexMatch "^[0-9a-z]+$" (required "cluster.standbyAppClientId is required in Tokyo outside dev (Osaka's app client)" $v.cluster.standbyAppClientId)) }}{{ fail "cluster.standbyAppClientId must be an app client ID" }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq $v.part "operator" -}}
{{- $_ := required "cluster.operatorRoleName is required (from the root Application)" $v.cluster.operatorRoleName -}}
{{- end -}}
{{- range $key := list "vpcCidr" "publicSubnetsCidr" "endpointSubnetsCidr" "isolatedSubnetsCidr" -}}
{{- $_ := required (printf "network.%s is required (the cluster's values file)" $key) (index $v.network $key) -}}
{{- end -}}
{{- end -}}

{{/* apne1 or apne3, and the regional prefix sft-<env>-<region-short> the Terraform names use (infra/README.md). */}}
{{- define "sft.regionShort" -}}
{{- index (dict "ap-northeast-1" "apne1" "ap-northeast-3" "apne3") .Values.region -}}
{{- end -}}

{{- define "sft.namePrefix" -}}
sft-{{ .Values.environment }}-{{ include "sft.regionShort" . }}
{{- end -}}

{{- define "sft.labels" -}}
app.kubernetes.io/name: sft
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/part-of: secure-file-transfer
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
sft.io/environment: {{ .root.Values.environment }}
{{- with .pool }}
sft.io/scan-pool: {{ . }}
{{- end }}
{{- end -}}

{{- define "sft.selectorLabels" -}}
app.kubernetes.io/name: sft
app.kubernetes.io/component: {{ .component }}
{{- with .pool }}
sft.io/scan-pool: {{ . }}
{{- end }}
{{- end -}}

{{- define "sft.appImage" -}}
{{ .Values.cluster.registry }}/{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- end -}}

{{- define "sft.clamavImage" -}}
{{ .Values.cluster.registry }}/{{ .Values.clamav.repository }}@{{ .Values.clamav.digest }}
{{- end -}}

{{/*
Replicas: zero in the pilot light (architecture 3.2), and for a worker (`held`) while a failover holds the workers
(failover.holdWorkers, docs/runbooks/regional-failover.md). Call with (dict "root" $ "replicas" n ["held" true]).
*/}}
{{- define "sft.replicas" -}}
{{- if or .root.Values.pilotLight (and .held .root.Values.failover.holdWorkers) }}0{{ else }}{{ .replicas }}{{ end -}}
{{- end -}}

{{/*
Whether the CronJobs are suspended: in the pilot light, where the database is a read-only replica, and while a
failover holds the workers, so no job acts before the recovery job has re-applied the security-critical changes
(architecture 7). Call with the root context.
*/}}
{{- define "sft.cronSuspended" -}}
{{- if or .Values.pilotLight .Values.failover.holdWorkers }}true{{ else }}false{{ end -}}
{{- end -}}

{{/* Pod-level security, PSA `restricted` (ADR-0004). Call with the user and group ID. */}}
{{- define "sft.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ . }}
runAsGroup: {{ . }}
fsGroup: {{ . }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* Container-level security: read-only root, no capabilities, no escalation (architecture 8). */}}
{{- define "sft.containerSecurityContext" -}}
allowPrivilegeEscalation: false
privileged: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* The common pod settings: no token, no service links (architecture 8), the pool's nodes. */}}
{{- define "sft.podCommon" -}}
{{- $pool := index .root.Values.pools (default "main" .nodePool) -}}
serviceAccountName: {{ .serviceAccount }}
automountServiceAccountToken: false
enableServiceLinks: false
{{- with .grace }}
terminationGracePeriodSeconds: {{ . }}
{{- end }}
nodeSelector:
  {{- toYaml $pool.nodeSelector | nindent 2 }}
{{- with $pool.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "sft.databaseUrl" -}}
{{- $db := .root.Values.database -}}
postgresql://{{ .role }}@{{ .root.Values.cluster.databaseHost }}:{{ $db.port }}/{{ $db.name }}{{ with $db.options }}?{{ . }}{{ end }}
{{- end -}}

{{/*
The counter store's URL for one workload (ADR-0014): TLS, and the workload's own IAM-authenticated user,
sft-<env>-<user>, with no password. Call with (dict "root" $ "user" name).
*/}}
{{- define "sft.valkeyUrl" -}}
rediss://sft-{{ .root.Values.environment }}-{{ .user }}@{{ .root.Values.cluster.valkeyHost }}:6379
{{- end -}}

{{/* The serverless cache's name, sft-<env>-<region-short>-valkey (infra/modules/valkey): what Valkey's IAM tokens sign. */}}
{{- define "sft.valkeyCache" -}}
{{ include "sft.namePrefix" . }}-valkey
{{- end -}}

{{/*
A keyring setting that names its secret in this region's Secrets Manager (encryption 6.4, #184): the process reads it
at start and every 5 minutes, as its own role, so no keyring is in a Kubernetes Secret or the pod spec.
*/}}
{{- define "sft.keyringRef" -}}
secretsmanager:sft/{{ .root.Values.environment }}/app/{{ .name }}
{{- end -}}

{{/* Settings every application container gets. Environment variables only (architecture 8). */}}
{{- define "sft.commonEnv" -}}
- name: LOG_LEVEL
  value: {{ .Values.logLevel | quote }}
- name: AWS_REGION
  value: {{ .Values.region | quote }}
- name: BIND_HOST
  value: "0.0.0.0"
{{- end -}}

{{/*
HTTPS_PROXY for the workloads with a proxy listener (ADR-0021). NO_PROXY keeps AWS calls on the VPC endpoints and
in-cluster calls direct; Cognito is deliberately not in it, so it goes through the listener.
*/}}
{{- define "sft.proxyEnv" -}}
{{- $proxy := .root.Values.network.egressProxy -}}
{{- $region := .root.Values.region -}}
{{- $other := ternary "ap-northeast-3" "ap-northeast-1" (eq $region "ap-northeast-1") -}}
{{- $noProxy := list "localhost" "127.0.0.1" "169.254.170.23" ".svc" ".cluster.local" -}}
{{- range $service := list "sqs" "kms" "secretsmanager" "sts" "email" -}}
{{- $noProxy = append $noProxy (printf "%s.%s.amazonaws.com" $service $region) -}}
{{- end -}}
{{- range $r := list $region $other -}}
{{- $noProxy = concat $noProxy (list (printf "s3.%s.amazonaws.com" $r) (printf ".s3.%s.amazonaws.com" $r)) -}}
{{- end -}}
- name: HTTPS_PROXY
  value: {{ printf "http://%s:%v" $proxy.host (index $proxy.ports .listener) | quote }}
- name: NO_PROXY
  value: {{ join "," $noProxy | quote }}
{{- end -}}

{{/*
Settings read from the External Secrets Secret (encryption 6.4), never a value in the pod spec. Call with a dict of
variable name to Secret name; each variable is that Secret's key of the same name.
*/}}
{{- define "sft.secretEnv" -}}
{{- range $name := keys . | sortAlpha }}
- name: {{ $name }}
  valueFrom:
    secretKeyRef: { name: {{ index $ $name }}, key: {{ $name }} }
{{- end }}
{{- end -}}

{{/*
The extra env of a workload, from a map, sorted so renders are stable. Call with (dict "env" map "reserved" list):
names the container already sets (the database, Valkey, proxy and secret settings) are left out, so a values file
can't replace them (Kubernetes takes the last of two entries with one name).
*/}}
{{- define "sft.extraEnv" -}}
{{- $env := .env -}}
{{- range $name := keys $env | sortAlpha }}
{{- if not (has $name $.reserved) }}
- name: {{ $name }}
  value: {{ index $env $name | toString | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/* Probes on the internal port (architecture 8): liveness never checks dependencies, readiness fails at shutdown. */}}
{{- define "sft.appProbes" -}}
startupProbe:
  httpGet: { path: /healthz, port: internal }
  periodSeconds: 2
  failureThreshold: 30
livenessProbe:
  httpGet: { path: /healthz, port: internal }
  periodSeconds: 10
  timeoutSeconds: 2
  failureThreshold: 3
readinessProbe:
  httpGet: { path: /readyz, port: internal }
  periodSeconds: 5
  timeoutSeconds: 2
  failureThreshold: 2
{{- end -}}

{{/*
A container of our image running `python -m <module>`, with the internal port and its probes. Optional: publicPort
(served with TLS), databaseRole and valkeyUser (each signed in with IAM tokens), proxyListener, env, secretEnv, preStop,
volumeMounts; traced for a workload that exports its spans (sft.core.settings._Traced: the API, the operator API and
the workers); ports (YAML) for an entry point with a port of its own beside the internal one (the DLP inspector); job
for a run-to-completion entry point with no listener, so no internal port and no probes (the invitation backlog).
*/}}
{{- define "sft.appContainer" -}}
- name: {{ .name }}
  image: {{ include "sft.appImage" .root }}
  imagePullPolicy: IfNotPresent
  command: [python, -m, {{ .module }}]
  {{- if not .job }}
  ports:
    {{- with .publicPort }}
    - { name: http, containerPort: {{ . }}, protocol: TCP }
    {{- end }}
    {{- with .ports }}
    {{- . | nindent 4 }}
    {{- end }}
    - { name: internal, containerPort: 8001, protocol: TCP }
  {{- end }}
  env:
    {{- include "sft.commonEnv" .root | nindent 4 }}
    {{- with .publicPort }}
    # TLS on the public port, with the certificate the pod makes at start (encryption 2.2, #184).
    - name: PUBLIC_TLS
      value: "generated"
    {{- end }}
    {{- with .databaseRole }}
    - name: DATABASE_URL
      value: {{ include "sft.databaseUrl" (dict "root" $.root "role" .) | quote }}
    - name: DATABASE_IAM_AUTH # an IAM token per connection, as the login role (encryption 6.3)
      value: "true"
    {{- end }}
    {{- with .valkeyUser }}
    - name: VALKEY_URL
      value: {{ include "sft.valkeyUrl" (dict "root" $.root "user" .) | quote }}
    - name: VALKEY_IAM_CACHE # an IAM token per connection, as the workload's user (ADR-0014)
      value: {{ include "sft.valkeyCache" $.root | quote }}
    {{- end }}
    {{- with .proxyListener }}
    {{- include "sft.proxyEnv" (dict "root" $.root "listener" .) | nindent 4 }}
    {{- end }}
    {{- if and .traced .root.Values.telemetry.otlpEndpoint }}
    - name: OTEL_EXPORTER_OTLP_ENDPOINT # the node's OpenTelemetry agent (ADR-0009)
      value: {{ .root.Values.telemetry.otlpEndpoint | quote }}
    {{- end }}
    {{- with .env }}
    {{- $reserved := concat (list "LOG_LEVEL" "AWS_REGION" "BIND_HOST" "PUBLIC_TLS" "DATABASE_URL" "DATABASE_IAM_AUTH" "VALKEY_URL" "VALKEY_IAM_CACHE" "HTTPS_PROXY" "NO_PROXY" "OTEL_EXPORTER_OTLP_ENDPOINT") (keys (default (dict) $.secretEnv)) }}
    {{- include "sft.extraEnv" (dict "env" . "reserved" $reserved) | trim | nindent 4 }}
    {{- end }}
    {{- with .secretEnv }}
    {{- include "sft.secretEnv" . | trim | nindent 4 }}
    {{- end }}
  {{- if not .job }}
  {{- include "sft.appProbes" . | nindent 2 }}
  {{- end }}
  {{- if .preStop }}
  lifecycle:
    preStop:
      sleep: { seconds: {{ .root.Values.preStopSleepSeconds }} }
  {{- end }}
  resources:
    {{- toYaml .resources | nindent 4 }}
  securityContext:
    {{- include "sft.containerSecurityContext" . | nindent 4 }}
  volumeMounts:
    - { name: tmp, mountPath: /tmp }
    {{- with .volumeMounts }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
{{- end -}}

{{/* /tmp on a read-only root: small, on the node's disk. */}}
{{- define "sft.tmpVolume" -}}
- name: tmp
  emptyDir: { sizeLimit: 64Mi }
{{- end -}}

{{/* A PodDisruptionBudget that lets one pod go at a time, and never blocks a drain on a pod that isn't ready. */}}
{{- define "sft.pdb" -}}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ .name }}
  namespace: {{ .root.Release.Namespace }}
  labels:
    {{- include "sft.labels" . | nindent 4 }}
spec:
  maxUnavailable: 1
  unhealthyPodEvictionPolicy: AlwaysAllow
  selector:
    matchLabels:
      {{- include "sft.selectorLabels" . | nindent 6 }}
{{- end -}}

{{/*
A Deployment around rendered containers. Call with a dict: root, name, component, pool (scan pools only), nodePool,
replicas, serviceAccount, grace, user, containers, and optionally initContainers, volumes and affinity (YAML).
*/}}
{{- define "sft.deployment" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .name }}
  namespace: {{ .root.Release.Namespace }}
  labels:
    {{- include "sft.labels" . | nindent 4 }}
spec:
  replicas: {{ include "sft.replicas" . }}
  revisionHistoryLimit: 5
  selector:
    matchLabels:
      {{- include "sft.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "sft.labels" . | nindent 8 }}
      {{- with .checksum }}
      annotations:
        sft.io/config-checksum: {{ . }}
      {{- end }}
    spec:
      {{- include "sft.podCommon" . | nindent 6 }}
      securityContext:
        {{- include "sft.podSecurityContext" (default 10001 .user) | nindent 8 }}
      {{- with .affinity }}
      affinity:
        {{- . | nindent 8 }}
      {{- end }}
      {{- with .initContainers }}
      initContainers:
        {{- . | nindent 8 }}
      {{- end }}
      containers:
        {{- .containers | nindent 8 }}
      volumes:
        {{- include "sft.tmpVolume" . | nindent 8 }}
        {{- with .volumes }}
        {{- . | nindent 8 }}
        {{- end }}
{{- end -}}

{{/*
The pod of a run-to-completion job (lifecycle jobs, the migration job): our image, `python -m <module>`, no ports or
probes, never restarted in place. Call with a dict: root, component, module, serviceAccount, env (list of name/value
YAML), resources.
*/}}
{{- define "sft.jobPod" -}}
metadata:
  labels:
    {{- include "sft.labels" . | nindent 4 }}
spec:
  {{- include "sft.podCommon" . | nindent 2 }}
  restartPolicy: Never
  securityContext:
    {{- include "sft.podSecurityContext" 10001 | nindent 4 }}
  containers:
    - name: {{ .component }}
      image: {{ include "sft.appImage" .root }}
      imagePullPolicy: IfNotPresent
      command: [python, -m, {{ .module }}]
      env:
        - name: LOG_LEVEL
          value: {{ .root.Values.logLevel | quote }}
        - name: AWS_REGION
          value: {{ .root.Values.region | quote }}
        - name: DATABASE_IAM_AUTH # every job connects as its login role with an IAM token (encryption 6.3)
          value: "true"
        {{- .env | nindent 8 }}
      resources:
        {{- toYaml .resources | nindent 8 }}
      securityContext:
        {{- include "sft.containerSecurityContext" . | nindent 8 }}
      volumeMounts:
        - { name: tmp, mountPath: /tmp }
  volumes:
    {{- include "sft.tmpVolume" . | nindent 4 }}
{{- end -}}

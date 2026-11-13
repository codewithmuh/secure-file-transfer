#!/usr/bin/env bash
# The cluster tunnel for the cluster-bootstrap job (ADR-0021, #279): the cluster API is private, so the job reaches it
# by port forwarding through the Systems Manager agent on a system node, with the cluster's own session document,
# which forwards only to the cluster API on 443 (infra/modules/eks-cluster/tunnel.tf). The deploy role may start that
# session and nothing else there (infra/modules/terraform-oidc-roles/permissions-cluster-bootstrap.tf).
#
# Usage (with the deploy role's credentials, aws, kubectl and session-manager-plugin on PATH):
#   cluster-tunnel.sh open ENV REGION PORT KUBECONFIG   start the session in the background, wait for the local port,
#                                                       and write a kubeconfig for https://127.0.0.1:PORT that checks
#                                                       the cluster's own name (tls-server-name)
#   cluster-tunnel.sh close                             end the session this job started
set -euo pipefail

state="${RUNNER_TEMP:-/tmp}/cluster-tunnel"

die() {
  echo "cluster-tunnel: $*" >&2
  exit 1
}

cmd_open() {
  local env=$1 region=$2 port=$3 kubeconfig=$4 short name instance cluster endpoint host arn
  [[ $env =~ ^(dev|staging|prod)$ ]] || die "unknown environment '$env'"
  case $region in
    ap-northeast-1) short=apne1 ;;
    ap-northeast-3) short=apne3 ;;
    *) die "unknown Region '$region'" ;;
  esac
  [[ $port =~ ^[0-9]+$ ]] || die "'$port' is not a port"
  command -v session-manager-plugin >/dev/null || die "the Session Manager plugin isn't installed on this runner"
  name="sft-$env-$short"

  # A running system node: every cluster keeps one, Osaka's pilot light too (ADR-0021).
  instance=$(aws ec2 describe-instances --region "$region" \
    --filters "Name=tag:eks:nodegroup-name,Values=$name-system" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].InstanceId' --output text | tr '\t' '\n' | sed -n 1p)
  [[ $instance =~ ^i-[0-9a-f]+$ ]] || die "no running system node in $name"
  cluster=$(aws eks describe-cluster --region "$region" --name "$name-eks" --query 'cluster.[endpoint,arn]' --output text)
  read -r endpoint arn <<<"$cluster"
  host=${endpoint#https://}
  [[ -n $host && $arn == arn:aws:eks:* ]] || die "can't read $name-eks"

  # A listener already on the port would answer the readiness probe below in the tunnel's place (#299).
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then die "port $port is already in use on this machine"; fi
  mkdir -p "$state"
  aws ssm start-session --region "$region" --target "$instance" --document-name "$name-cluster-tunnel" \
    --parameters "{\"host\":[\"$host\"],\"portNumber\":[\"443\"],\"localPortNumber\":[\"$port\"]}" \
    >"$state/session.log" 2>&1 &
  echo $! >"$state/pid"
  echo "$region" >"$state/region"

  local attempt
  for attempt in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
    kill -0 "$(cat "$state/pid")" 2>/dev/null || { cat "$state/session.log" >&2; die "the session ended before it opened"; }
    [[ $attempt == 60 ]] && die "the tunnel didn't open within a minute"
    sleep 1
  done

  # Credentials come from `aws eks get-token`, per call, as the deploy role; the server is the tunnel's local end, and
  # TLS still checks the cluster's own name.
  aws eks update-kubeconfig --region "$region" --name "$name-eks" --kubeconfig "$kubeconfig" --alias "$name" >/dev/null
  kubectl --kubeconfig "$kubeconfig" config set-cluster "$arn" \
    --server "https://127.0.0.1:$port" --tls-server-name "$host" >/dev/null
  kubectl --kubeconfig "$kubeconfig" get --raw /readyz >/dev/null || die "the cluster API doesn't answer through the tunnel"
  echo "Tunnel to $name-eks open on 127.0.0.1:$port through $instance." >&2
}

cmd_close() {
  local id
  [[ -f $state/pid ]] || return 0
  # Systems Manager prints the session's ID when it starts; ending it there too means no session is left open.
  id=$(sed -n 's/.*SessionId: *\([A-Za-z0-9._-]*\).*/\1/p' "$state/session.log" | sed -n 1p)
  if [[ -n $id ]]; then
    aws ssm terminate-session --region "$(cat "$state/region")" --session-id "$id" >/dev/null || true
  fi
  # The CLI runs the Session Manager plugin as its child, which holds the local port: end both (#299).
  pkill -TERM -P "$(cat "$state/pid")" 2>/dev/null || true
  kill "$(cat "$state/pid")" 2>/dev/null || true
  rm -rf "$state"
}

case "${1:-}" in
  open)
    [[ $# -eq 5 ]] || die "usage: open ENV REGION PORT KUBECONFIG"
    shift
    cmd_open "$@"
    ;;
  close) cmd_close ;;
  *) die "usage: open ENV REGION PORT KUBECONFIG | close" ;;
esac

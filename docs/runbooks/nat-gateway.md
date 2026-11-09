# Runbook: NAT gateway (`sft-<env>-<rs>-nat-<id>-port-allocation`, `-packet-drops`)

CloudWatch alarms on the NAT gateways under the egress proxy ([ADR-0021](../adr/0021-network-design-and-egress.md)),
defined in [`infra/modules/alarms/nat.tf`](../../infra/modules/alarms/nat.tf). Severity: ticket.

## Symptoms

- `ErrorPortAllocation` above zero: the gateway ran out of source ports to one destination, or
- `PacketsDropCount` above 0.01 % of its packets for 15 minutes.

## Impact

Only the `system` nodes route through NAT, and only the egress proxy's traffic goes there: member sign-in's code
exchanges and Cognito admin calls, Argo CD's pulls from GitHub, the signature mirror and AWS APIs with no endpoint.
Sending, downloads, uploads and the Osaka writes use VPC endpoints and aren't affected (architecture 6).

## Confirm

```bash
kubectl -n egress-proxy logs deploy/egress-proxy --since=30m | grep -c ' 503 '      # failed upstream connections
aws ec2 describe-nat-gateways --region <region> --nat-gateway-ids <id>               # state, AZ (live run)
```

On the proxy dashboard: which listener's connections fail. Check the AWS Health Dashboard for EC2 in the AZ.

## Mitigate

1. **Port allocation errors**: many connections to one destination, usually a client that doesn't reuse connections or
   a retry loop. Find the listener and the workload behind it, and fix or roll back.
2. **Drops in one AZ**: an AZ problem; the proxy's other replica, in another AZ, carries on. Follow AWS Health.
3. **Drops everywhere**: check the NAT gateways' bandwidth against capacity 3; a burst of signature downloads or image
   pulls without the endpoints would show here.

## Escalate

If member sign-in fails (the sign-in error alerts fire too), it is a page: escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the cause in the operating log.

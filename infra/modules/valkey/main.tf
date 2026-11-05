# One Region's counter store (ADR-0014): ElastiCache Serverless for Valkey, encrypted at rest with the platform key and
# always TLS in transit, with IAM authentication for the five workloads that use it and nothing else. Nothing in it
# must survive, so it keeps no snapshots and nothing replicates to the other Region (abuse 4.2).

locals {
  name = "${var.name_prefix}-valkey"
}

resource "aws_security_group" "this" {
  name        = local.name
  description = "Valkey counter store: 6379 from the main and scan node groups only (ADR-0014, ADR-0021)"
  vpc_id      = var.vpc_id

  tags = {
    Name = local.name
  }
}

# 6379 only: the workloads read from the primary endpoint, so the reader endpoint's 6380 stays closed.
resource "aws_vpc_security_group_ingress_rule" "clients" {
  for_each = var.client_security_group_ids

  security_group_id            = aws_security_group.this.id
  description                  = "Valkey from ${each.key}; network policies narrow it to the workloads that use it"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = each.value
}

# IAM authentication needs the user ID and the user name to be the same. Each workload's role gets elasticache:Connect
# on the cache and on its own user only (cluster layer). A Valkey user group needs no default user, so no
# password-based user exists.
resource "aws_elasticache_user" "workload" {
  for_each = var.workloads

  engine        = "valkey"
  user_id       = "${var.user_name_prefix}-${each.value}"
  user_name     = "${var.user_name_prefix}-${each.value}"
  access_string = var.access_string

  authentication_mode {
    type = "iam"
  }
}

resource "aws_elasticache_user_group" "this" {
  engine        = "valkey"
  user_group_id = local.name
  user_ids      = [for u in aws_elasticache_user.workload : u.user_id]
}

resource "aws_elasticache_serverless_cache" "this" {
  name                 = local.name
  description          = "Rate-limit counters, leases and sign-in state (ADR-0014)"
  engine               = "valkey"
  major_engine_version = var.major_engine_version

  kms_key_id         = var.kms_key_arn
  security_group_ids = [aws_security_group.this.id]
  subnet_ids         = var.subnet_ids
  user_group_id      = aws_elasticache_user_group.this.user_group_id

  # Nothing here is needed after a failure (abuse 4.1), so no snapshots.
  snapshot_retention_limit = 0

  cache_usage_limits {
    data_storage {
      maximum = var.max_data_storage_gb
      unit    = "GB"
    }

    ecpu_per_second {
      maximum = var.max_ecpu_per_second
    }
  }
}

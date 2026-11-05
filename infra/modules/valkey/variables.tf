variable "name_prefix" {
  description = "Prefix for regional resource names, from the caller's conventions module: sft-<env>-<region-short>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]$", var.name_prefix))
    error_message = "name_prefix must be sft-<dev|staging|prod>-<apne1|apne3>, the conventions module's name_prefix."
  }
}

variable "user_name_prefix" {
  description = <<-EOT
    Prefix for the IAM-authenticated users, from the conventions module's global_name_prefix: sft-<env>. Users are
    regional, but each workload's IAM role is the same in both Regions, so the names are too.
  EOT
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)$", var.user_name_prefix))
    error_message = "user_name_prefix must be sft-<dev|staging|prod>, the conventions module's global_name_prefix."
  }
}

variable "workloads" {
  description = <<-EOT
    The workloads that may use the store, one IAM-authenticated user each, named <user_name_prefix>-<workload> like
    their IAM roles: the API, the sign-in triggers, the scan worker (scan leases) and the notification worker
    (per-address caps across tenants), and nothing else (ADR-0014).
  EOT
  type        = set(string)
  default     = ["api", "signin-trigger", "scan", "notify"]

  validation {
    condition     = length(var.workloads) > 0 && alltrue([for w in var.workloads : can(regex("^[a-z][a-z0-9-]{1,23}$", w))])
    error_message = "Each workload must be lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "access_string" {
  description = <<-EOT
    What each user may do: only keys under rl: (ADR-0014's key format), only reads, writes and connection commands,
    and nothing dangerous (no KEYS, FLUSHALL, CONFIG, DEBUG or MONITOR). -@all also leaves out pub/sub.
    -function takes FUNCTION LOAD, DELETE and FLUSH back out of +@write. Of the scripting commands only the two the
    service sends: EVALSHA, and SCRIPT LOAD when the cache doesn't know a script yet (valkey-py's Script, used by
    sft.data.counters), so no EVAL, FCALL, SCRIPT FLUSH or SCRIPT KILL. CLUSTER SLOTS and CLUSTER SHARDS are the two
    read-only topology calls a cluster client makes at start; a serverless cache runs in cluster mode (ADR-0014).
    Checked with ACL DRYRUN against Valkey 9.0.7 (the README's table).
  EOT
  type        = string
  default     = "on ~rl:* -@all +@read +@write +@connection -@dangerous -function +evalsha +script|load +cluster|slots +cluster|shards"
}

variable "major_engine_version" {
  description = "Valkey's major version: 9, the version compose.yaml runs locally (docs/local-development.md)."
  type        = string
  default     = "9"
}

variable "vpc_id" {
  description = "The VPC, from the network stack."
  type        = string
}

variable "subnet_ids" {
  description = "The isolated subnets, from the network stack (ADR-0021): two or three AZs."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) >= 2 && length(var.subnet_ids) <= 3
    error_message = "subnet_ids must name two or three subnets."
  }
}

variable "client_security_group_ids" {
  description = <<-EOT
    Security groups admitted on 6379, by role: the network module's main_nodes and scan_nodes, and, once they exist,
    the sign-in triggers' group (ADR-0014, ADR-0021). Network policies narrow the nodes to the three workloads above.
  EOT
  type        = map(string)

  validation {
    condition     = length(var.client_security_group_ids) > 0
    error_message = "client_security_group_ids must name at least one security group."
  }
}

variable "kms_key_arn" {
  description = "This Region's platform key (alias/sft/<env>/platform), for encryption at rest (encryption 3.1)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-[13]:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN in Tokyo or Osaka."
  }
}

variable "max_data_storage_gb" {
  description = "Most data the cache may hold, in GB. Counters, leases and sign-in state need a few MB; the meter starts at 0.1 GB (capacity 5.1)."
  type        = number
  default     = 1

  validation {
    condition     = var.max_data_storage_gb >= 1 && var.max_data_storage_gb <= 5000
    error_message = "max_data_storage_gb must be between 1 and 5000."
  }
}

variable "max_ecpu_per_second" {
  description = <<-EOT
    Most ECPUs a second, a ceiling on cost under attack. The store must take 10 times 1,200 operations a second
    during an attack (abuse 4.2); scripts cost more than one ECPU, so the ceiling leaves room above that. The load test
    measures ECPUs per request (capacity section 8).
  EOT
  type        = number
  default     = 30000

  validation {
    condition     = var.max_ecpu_per_second >= 1000 && var.max_ecpu_per_second <= 15000000
    error_message = "max_ecpu_per_second must be between 1,000 and 15,000,000."
  }
}

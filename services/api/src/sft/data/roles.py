"""The PostgreSQL roles: one login role per workload, plus two roles nobody logs in as (ADR-0020).

Authentication and authorization 7.3 says what each role may reach. The roles themselves are
created by the bootstrap job (`sft.data.bootstrap`), never by a migration: migrations run as
`sft_owner`, which can't create roles. Migrations grant each workload role its tables and write its
policies, through `sft.data.rls`.
"""

from __future__ import annotations

from typing import Final

OWNER: Final = "sft_owner"
"""Owns every table. Nobody logs in as it; only `sft_migrate` may become it, with `SET ROLE`."""

LOOKUP: Final = "sft_lookup"
"""Owns the credential lookup functions (data model 4.2). Nobody logs in as it."""

MIGRATE: Final = "sft_migrate"
"""The migration job's login role. It has no privileges of its own until it becomes the owner."""

API: Final = "sft_api"
OPERATOR: Final = "sft_operator"
SCAN: Final = "sft_scan"
NOTIFY: Final = "sft_notify"
RELAY: Final = "sft_relay"
JOBS: Final = "sft_jobs"
ARCHIVE: Final = "sft_archive"
RECOVERY: Final = "sft_recovery"
BREAK_GLASS: Final = "sft_breakglass"
"""A person's role, not a workload's: an operator with an active break-glass grant logs in as it
(authn and authz 8.3, #232). It reads the grant's tenants' rows of a few tables and nothing else,
through policies that end with the grant. Held to the workload roles' rules: listed with them."""

WORKLOAD_ROLES: Final = (API, OPERATOR, SCAN, NOTIFY, RELAY, JOBS, ARCHIVE, RECOVERY, BREAK_GLASS)
"""The roles that log in to use tables: each running workload's, and break-glass's. Each is granted
only the tables it needs."""

LOGIN_ROLES: Final = (*WORKLOAD_ROLES, MIGRATE)
"""Every role that logs in: with IAM database authentication in AWS, a password only locally."""

ALL_ROLES: Final = (OWNER, LOOKUP, *LOGIN_ROLES)

# Every workload transaction ends within 30 seconds, so the audit archive cursor keeps moving
# (data model 2.5). One statement or one idle wait in a transaction gets a third of that. The
# migration role isn't held to these limits (data model 7).
WORKLOAD_ROLE_SETTINGS: Final = {
    "statement_timeout": "10s",
    "idle_in_transaction_session_timeout": "10s",
    "transaction_timeout": "30s",
}

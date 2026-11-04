# AWS Budgets (NFR-20, capacity 7.3) and the cost allocation tags (capacity 7.3, infra/README.md "Tags").
#
# Budgets live here, in the management account, so they see consolidated billing, exist before any workload, and
# outlive every environment's teardown. They email directly: no SNS topic or key to keep. Each budget alarms at 50 %
# of actual spend, a pacing check, and at 80 % and 100 % of both actual and forecast spend (capacity 7.3). Five
# notifications per budget is also AWS's limit.

locals {
  # The $6,500 cap and the account budgets that add up to it (capacity 7.3, ADR-0006). The retained stack's $7 budget
  # (NFR-19) is created by that stack in the prod account (encryption 8.4).
  monthly_budgets_usd = {
    total   = { limit = 6500, account = null }
    shared  = { limit = 20, account = "shared" }
    dev     = { limit = 500, account = "dev" }
    staging = { limit = 800, account = "staging" }
    prod    = { limit = 5180, account = "prod" }
  }

  budget_notifications = [
    { threshold = 50, type = "ACTUAL" },
    { threshold = 80, type = "ACTUAL" },
    { threshold = 80, type = "FORECASTED" },
    { threshold = 100, type = "ACTUAL" },
    { threshold = 100, type = "FORECASTED" },
  ]

  # Activated in the payer account so Cost Explorer can split cost by environment, layer and stack (capacity 7.3).
  # retention joins them if the retained stack's budget ever filters on it before teardown (encryption 8.4).
  cost_allocation_tags = toset(["component", "environment", "stack"])
}

resource "aws_budgets_budget" "monthly" {
  for_each = local.monthly_budgets_usd

  name         = "${module.conventions.global_name_prefix}-budget-${each.key}"
  budget_type  = "COST"
  time_unit    = "MONTHLY"
  limit_amount = tostring(each.value.limit)
  limit_unit   = "USD"

  dynamic "cost_filter" {
    for_each = each.value.account == null ? [] : [each.value.account]

    content {
      name   = "LinkedAccount"
      values = [local.account_ids[cost_filter.value]]
    }
  }

  dynamic "notification" {
    for_each = local.budget_notifications

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = var.budget_notification_emails
    }
  }
}

# AWS can activate a tag key only after it has seen the key on a resource in a bill, which takes up to a day after the
# first tagged resource exists. Until then, apply with activate_cost_allocation_tags = false (runbook step 5).
resource "aws_ce_cost_allocation_tag" "this" {
  for_each = var.activate_cost_allocation_tags ? local.cost_allocation_tags : toset([])

  tag_key = each.key
  status  = "Active"
}

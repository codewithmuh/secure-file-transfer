# The NFR-19 budget: after teardown the prod account holds only this stack, which must cost at most $7 a month
# (encryption 8.4, capacity 7.3 and 7.4). The teardown apply creates it, so it never counts prod's own spend and needs
# no cost allocation tag: from then on the account's whole bill is this stack's. It emails directly, like the
# organization's budgets, so it needs no topic or key, and alarms at the same points: 50 % of actual spend, and 80 %
# and 100 % of actual and forecast spend (infra/organization/budgets.tf).

locals {
  retained_budget_notifications = [
    { threshold = 50, type = "ACTUAL" },
    { threshold = 80, type = "ACTUAL" },
    { threshold = 80, type = "FORECASTED" },
    { threshold = 100, type = "ACTUAL" },
    { threshold = 100, type = "FORECASTED" },
  ]
}

resource "aws_budgets_budget" "retained" {
  count = var.teardown ? 1 : 0

  name         = "${module.conventions.global_name_prefix}-retained-budget"
  budget_type  = "COST"
  time_unit    = "MONTHLY"
  limit_amount = "7"
  limit_unit   = "USD"

  dynamic "notification" {
    for_each = local.retained_budget_notifications

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.budget_email]
    }
  }
}

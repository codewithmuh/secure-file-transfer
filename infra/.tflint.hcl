# tflint for every root and module under infra/, run by infra/scripts/check.sh tflint (locally and in CI).

config {
  # Lint the local modules through the roots that call them, with the roots' values.
  call_module_type = "local"
}

# Terraform's own rules, all of them: naming, documented and typed variables and outputs, pinned versions, unused
# declarations and the standard module structure.
plugin "terraform" {
  enabled = true
  preset  = "all"
}

# AWS rules: invalid instance types, names and arguments, deprecated resources. Static only: deep checks would call
# AWS, which nothing here may do.
plugin "aws" {
  enabled = true
  version = "0.50.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

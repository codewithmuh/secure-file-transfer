# The account's emergency IAM user, sft-<env>-emergency under /sft-emergency/ (authn-authz 8.4, #81).
#
# People sign in through IAM Identity Center, whose home Region is Tokyo, so losing Tokyo loses every permission set
# (ADR-0006). This user is the way in that doesn't depend on it. It has AdministratorAccess, bound like every other
# principal in a member account by the SCPs, and in staging and prod the Osaka state bucket and tfstate key name it
# as a bootstrap admin, so Osaka's bootstrap stack can still be applied in a Tokyo outage.
#
# Terraform creates only the user and its policy. The maintainer, as Admin, gives it a console password kept offline
# and a security key as its MFA device in the console (docs/runbooks/organization-and-bootstrap.md, step 11), so
# neither is ever in state. It never has access keys: SCP 4 denies them to everyone. Only Admin may create or change
# IAM users, their passwords or their MFA devices (SCP 4), so nobody else can take its name or its credentials.
#
# prevent_destroy, like the key-admin role: the last apply before a final teardown lifts it (encryption 8.4).
# force_destroy lets that destroy remove the console password and the MFA device made outside Terraform.

resource "aws_iam_user" "emergency" {
  name          = var.user_name
  path          = var.iam_path
  force_destroy = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_user_policy_attachment" "administrator" {
  user       = aws_iam_user.emergency.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

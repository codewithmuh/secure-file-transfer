#!/usr/bin/env python3
"""Measure the IAM policies in a Terraform plan before it is applied (#312).

IAM's size limits apply to the rendered JSON, which only a plan shows, so no static check sees them; dev's first
bootstrap apply found two managed policies over the limit 57 resources in. Run this on the plan instead:

    terraform plan -out=bootstrap.tfplan
    terraform show -json bootstrap.tfplan > bootstrap.json
    infra/scripts/check-policy-sizes.py bootstrap.json

It fails (exit 1) on any of these, counted the way IAM counts them, without white space:
  - a managed policy (aws_iam_policy) over 6,144 characters
  - a role whose inline policies (aws_iam_role_policy) come to more than 10,240 characters together
  - a role's trust policy over --max-trust (default 2,048, IAM's default "Role trust policy length")
  - a role with more managed policies attached than --max-attached (default 20: the "Managed policies per role" quota,
    L-0DA4ABF3, which infra/README.md's "IAM quotas" says to raise to 20 before the bootstrap)
  - a managed or inline policy that the plan doesn't know yet, so it can't be measured (--allow-unknown lists them
    instead). A trust policy not known yet is only listed: on a first bootstrap the roles' trust names the GitHub OIDC
    provider the same apply creates, and each is one short statement.

A role that doesn't exist yet has an unknown ID, so its inline policies and attachments are grouped by the role they
refer to in the plan's configuration. User and group policies aren't checked: no root here makes any.
`--self-test` checks the script itself (check.sh runs it, and CI runs check.sh).
"""

import argparse
import collections
import json
import re
import sys

MANAGED_LIMIT = 6144
INLINE_PER_ROLE_LIMIT = 10240


def size(policy):
    """IAM's count: the policy's characters without white space."""
    return len(re.sub(r"\s", "", policy))


def kept(change):
    """The resource's planned state, or None when the plan deletes or forgets it."""
    if set(change["change"]["actions"]) <= {"delete", "forget"}:
        return None
    return change["change"].get("after")


def role_references(plan):
    """For each inline policy and attachment in the configuration, the role it refers to (module path included).

    The plan's own values can't say which role while the role is still to be created: its ID is unknown."""
    refs = {}

    def walk(module, prefix):
        for res in module.get("resources", []):
            references = (
                res.get("expressions", {}).get("role", {}).get("references", [])
            )
            roles = [
                r
                for r in references
                if re.fullmatch(r"aws_iam_role\.[\w-]+(\[[^\]]+\])?", r)
            ]
            if roles:
                refs[prefix + res["address"]] = prefix + max(roles, key=len)
        for name, call in module.get("module_calls", {}).items():
            walk(call.get("module", {}), f"{prefix}module.{name}.")

    walk(plan.get("configuration", {}).get("root_module", {}), "")
    return refs


def without_index(address):
    """module.a["x"].aws_b.c[0] -> module.a.aws_b.c: the configuration's address of a planned resource."""
    return re.sub(r"\[[^\]]*\]", "", address)


def role_of(change, after, refs):
    role = after.get("role")
    if role:
        return role
    ref = refs.get(without_index(change["address"]))
    return f"{ref} (to be created)" if ref else change["address"]


def check(plan, max_attached, max_trust=2048):
    problems, report, unknown, report_unknown_trust = [], [], [], []
    inline = collections.Counter()
    attached = collections.Counter()
    refs = role_references(plan)
    for change in plan.get("resource_changes", []):
        after = kept(change)
        if after is None:
            continue
        address, kind = change["address"], change["type"]
        if kind in ("aws_iam_policy", "aws_iam_role_policy"):
            policy = after.get("policy")
            if not policy:
                unknown.append(address)
                continue
            n = size(policy)
            if kind == "aws_iam_policy":
                report.append((n, after.get("name") or address))
                if n > MANAGED_LIMIT:
                    problems.append(
                        f"{after.get('name') or address}: {n:,} characters, over IAM's {MANAGED_LIMIT:,}"
                    )
            else:
                inline[role_of(change, after, refs)] += n
        elif kind == "aws_iam_role":
            trust = after.get("assume_role_policy")
            if not trust:
                report_unknown_trust.append(f"{address} (trust policy)")
            elif size(trust) > max_trust:
                problems.append(
                    f"{after.get('name') or address}: trust policy of {size(trust):,} characters, over {max_trust:,}"
                )
        elif kind == "aws_iam_role_policy_attachment":
            attached[role_of(change, after, refs)] += 1
    for role, n in inline.items():
        if n > INLINE_PER_ROLE_LIMIT:
            problems.append(
                f"{role}: inline policies of {n:,} characters together, over IAM's {INLINE_PER_ROLE_LIMIT:,}"
            )
    for role, n in attached.items():
        if n > max_attached:
            problems.append(
                f"{role}: {n} managed policies attached, over the quota of {max_attached}"
            )
    return (
        problems,
        sorted(report, reverse=True),
        (unknown, report_unknown_trust),
        attached,
    )


def self_test():
    def plan(*changes):
        return {"resource_changes": list(changes)}

    def res(kind, after, actions=("create",)):
        return {
            "address": f"{kind}.x",
            "type": kind,
            "change": {"actions": list(actions), "after": after},
        }

    small = json.dumps(
        {"Statement": [{"Action": "s3:GetObject", "Resource": "*"}]}, indent=2
    )
    big = json.dumps({"Statement": [{"Sid": "A" * 6200}]})
    ok, *_ = check(plan(res("aws_iam_policy", {"name": "small", "policy": small})), 20)
    assert ok == [], ok
    bad, *_ = check(plan(res("aws_iam_policy", {"name": "big", "policy": big})), 20)
    assert len(bad) == 1 and bad[0].startswith("big:"), bad
    gone, *_ = check(
        plan(res("aws_iam_policy", {"name": "big", "policy": big}, ("delete",))), 20
    )
    assert gone == [], gone
    many = [res("aws_iam_role_policy_attachment", {"role": "deploy"}) for _ in range(3)]
    over, *_ = check(plan(*many), 2)
    assert over == ["deploy: 3 managed policies attached, over the quota of 2"], over
    inline = [
        res(
            "aws_iam_role_policy",
            {"role": "r", "policy": json.dumps({"S": "x" * 6000})},
        )
        for _ in range(2)
    ]
    over, *_ = check(plan(*inline), 20)
    assert len(over) == 1 and over[0].startswith("r: inline"), over
    _, _, (unknown, unknown_trust), _ = check(
        plan(res("aws_iam_policy", {"name": "later"})), 20
    )
    assert unknown == ["aws_iam_policy.x"] and unknown_trust == [], unknown
    _, _, (unknown, unknown_trust), _ = check(
        plan(res("aws_iam_role", {"name": "r"})), 20
    )
    assert unknown == [] and unknown_trust == ["aws_iam_role.x (trust policy)"], (
        unknown_trust
    )
    forgot = {
        "address": "aws_iam_role_policy_attachment.f",
        "type": "aws_iam_role_policy_attachment",
        "change": {"actions": ["forget"], "after": None},
    }
    none, _, _, attached = check(plan(forgot), 0)
    assert none == [] and not attached, (none, attached)
    cfg = {
        "root_module": {
            "module_calls": {
                "roles": {
                    "module": {
                        "resources": [
                            {
                                "address": f"aws_iam_role_policy.p{i}",
                                "expressions": {
                                    "role": {
                                        "references": [
                                            "aws_iam_role.deploy[0].id",
                                            "aws_iam_role.deploy[0]",
                                            "aws_iam_role.deploy",
                                        ]
                                    }
                                },
                            }
                            for i in range(2)
                        ]
                    }
                }
            }
        }
    }
    unknown_role = {
        "configuration": cfg,
        "resource_changes": [
            {
                "address": f"module.roles.aws_iam_role_policy.p{i}[0]",
                "type": "aws_iam_role_policy",
                "change": {
                    "actions": ["create"],
                    "after": {"policy": json.dumps({"S": "x" * 6000})},
                },
            }
            for i in range(2)
        ],
    }
    over, *_ = check(unknown_role, 20)
    assert len(over) == 1 and "module.roles.aws_iam_role.deploy[0]" in over[0], over
    trust = res(
        "aws_iam_role",
        {"name": "t", "assume_role_policy": json.dumps({"S": "x" * 2100})},
    )
    over, *_ = check(plan(trust), 20)
    assert over and over[0].startswith("t: trust policy"), over
    assert size('{ "a" :\n  "b" }') == len('{"a":"b"}')
    print("check-policy-sizes self-test passed")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "plan_json", nargs="?", help="the output of `terraform show -json <plan file>`"
    )
    parser.add_argument(
        "--max-attached",
        type=int,
        default=20,
        help="managed policies allowed per role (default 20)",
    )
    parser.add_argument(
        "--max-trust",
        type=int,
        default=2048,
        help="characters allowed in a trust policy (default 2,048)",
    )
    parser.add_argument(
        "--allow-unknown",
        action="store_true",
        help="list policies not known until apply, don't fail",
    )
    parser.add_argument(
        "--self-test", action="store_true", help="check this script and exit"
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.plan_json:
        parser.error("give the plan's JSON, or --self-test")
    with open(args.plan_json, encoding="utf-8") as f:
        plan = json.load(f)
    problems, report, unknown, attached = check(plan, args.max_attached, args.max_trust)
    for n, name in report:
        print(f"{n:6,d}  {'OVER ' if n > MANAGED_LIMIT else '     '}{name}")
    for role, n in attached.most_common():
        print(f"{n:6d}  managed policies on {role}")
    unknown, unknown_trust = unknown
    for address in unknown + unknown_trust:
        print(f"     ?  {address}: not known until apply, so not measured")
    if unknown and not args.allow_unknown:
        problems.append(
            f"{len(unknown)} policies can't be measured before apply (above); --allow-unknown to accept"
        )
    if problems:
        print("\nRefusing this plan:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    print(
        "\nThe plan's managed, inline and trust policies, and the policies per role, are inside IAM's limits."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

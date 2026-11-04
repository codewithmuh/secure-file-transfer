import pytest

from sft.data.rls import grant_sql, policy_sql, tenant_rls_sql


def test_a_tenant_table_gets_rls_grants_and_the_tenant_policy() -> None:
    assert tenant_rls_sql(
        "widgets", grants={"sft_api": "insert, select, UPDATE", "sft_jobs": "SELECT"}
    ) == [
        "ALTER TABLE widgets ENABLE ROW LEVEL SECURITY",
        "GRANT SELECT, INSERT, UPDATE ON widgets TO sft_api",
        "GRANT SELECT ON widgets TO sft_jobs",
        "CREATE POLICY tenant_isolation ON widgets FOR ALL TO sft_api, sft_jobs "
        "USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id())",
    ]


def test_the_tenant_column_can_be_named() -> None:
    policy = tenant_rls_sql("tenants", grants={"sft_api": "SELECT"}, key="id")[-1]
    assert policy.endswith("USING (id = app_tenant_id()) WITH CHECK (id = app_tenant_id())")


def test_a_tenant_table_is_granted_to_someone() -> None:
    with pytest.raises(ValueError, match="at least one workload role"):
        tenant_rls_sql("widgets", grants={})


@pytest.mark.parametrize("privileges", ["TRUNCATE", "SELECT, TRUNCATE", "ALL", "REFERENCES", ""])
def test_only_reads_and_writes_can_be_granted(privileges: str) -> None:
    with pytest.raises(ValueError, match="grant only"):
        grant_sql("widgets", "sft_api", privileges)


@pytest.mark.parametrize("role", ["sft_owner", "sft_migrate", "sft_lookup", "postgres", "PUBLIC"])
def test_only_workload_roles_can_be_granted(role: str) -> None:
    with pytest.raises(ValueError, match="not a workload role"):
        grant_sql("widgets", role, "SELECT")


@pytest.mark.parametrize("table", ["Widgets", "widgets; DROP TABLE tenants", "a.b", "1table", ""])
def test_names_are_plain_identifiers(table: str) -> None:
    with pytest.raises(ValueError, match="identifier"):
        grant_sql(table, "sft_api", "SELECT")


def test_policies_for_other_scopes() -> None:
    assert policy_sql(
        "jobs_find", "widgets", roles=["sft_jobs"], command="SELECT", using="app_scope() = 'system'"
    ) == (
        "CREATE POLICY jobs_find ON widgets FOR SELECT TO sft_jobs USING (app_scope() = 'system')"
    )
    assert policy_sql(
        "audit_tenant_insert",
        "audit_events",
        roles=["sft_api", "sft_scan"],
        command="INSERT",
        with_check="tenant_id = app_tenant_id()",
    ) == (
        "CREATE POLICY audit_tenant_insert ON audit_events FOR INSERT TO sft_api, sft_scan "
        "WITH CHECK (tenant_id = app_tenant_id())"
    )


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"roles": []}, "names the roles"),
        ({"command": "SELECT", "using": "true", "with_check": "true"}, "has no WITH CHECK"),
        ({"command": "DELETE", "using": "true", "with_check": "true"}, "has no WITH CHECK"),
        ({"command": "INSERT", "using": "true"}, "has no USING"),
        ({"command": "ALL"}, "needs USING, WITH CHECK or both"),
        ({"roles": ["sft_owner"], "using": "true"}, "not a workload role"),
    ],
)
def test_policy_mistakes_are_caught(options: dict[str, object], message: str) -> None:
    arguments: dict[str, object] = {"roles": ["sft_api"], **options}
    with pytest.raises(ValueError, match=message):
        policy_sql("p", "widgets", **arguments)  # type: ignore[arg-type]

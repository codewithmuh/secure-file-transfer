import pytest

from sft.data.rls import (
    grant_sql,
    lookup_function_sql,
    lookup_read_sql,
    policy_sql,
    tenant_foreign_key_sql,
    tenant_keys_sql,
    tenant_rls_sql,
)


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


def test_tenant_keys_reference_the_tenant_and_give_children_a_key() -> None:
    assert tenant_keys_sql("files") == [
        "ALTER TABLE files ADD CONSTRAINT files_tenant_id_fkey "
        "FOREIGN KEY (tenant_id) REFERENCES tenants (id)",
        "ALTER TABLE files ADD CONSTRAINT files_tenant_id_id_key UNIQUE (tenant_id, id)",
    ]


def test_a_child_refers_to_its_parent_with_the_tenant() -> None:
    assert tenant_foreign_key_sql("files", "transfer_id", "transfers", on_delete="CASCADE") == (
        "ALTER TABLE files ADD CONSTRAINT files_tenant_id_transfer_id_fkey "
        "FOREIGN KEY (tenant_id, transfer_id) REFERENCES transfers (tenant_id, id) "
        "ON DELETE CASCADE"
    )
    assert tenant_foreign_key_sql("files", "transfer_id", "transfers").endswith("(tenant_id, id)")


@pytest.mark.parametrize(
    "arguments", [("files", "transfer_id; --", "transfers"), ("files", "transfer_id", "Transfers")]
)
def test_tenant_key_names_are_plain_identifiers(arguments: tuple[str, str, str]) -> None:
    with pytest.raises(ValueError, match="identifier"):
        tenant_foreign_key_sql(*arguments)


def test_a_child_key_never_sets_its_tenant_null() -> None:
    # SET NULL or SET DEFAULT would also clear tenant_id, which is NOT NULL.
    with pytest.raises(ValueError, match="would break the tenant key"):
        tenant_foreign_key_sql("files", "transfer_id", "transfers", on_delete="SET NULL")  # type: ignore[arg-type]


def test_lookup_read_grants_columns_and_a_lookup_scope_policy() -> None:
    assert lookup_read_sql("member_sessions", ["id", "tenant_id", "session_hash"]) == [
        "GRANT SELECT (id, tenant_id, session_hash) ON member_sessions TO sft_lookup",
        "CREATE POLICY lookup_read ON member_sessions FOR SELECT TO sft_lookup "
        "USING (app_scope() = 'lookup')",
    ]
    with pytest.raises(ValueError, match="name the columns"):
        lookup_read_sql("member_sessions", [])


def test_a_lookup_function_is_pinned_owned_by_sft_lookup_and_only_for_the_api() -> None:
    statements = lookup_function_sql(
        "lookup_api_key(p_key_hash bytea)",
        returns="TABLE (key_id uuid, owner_tenant_id uuid)",
        body="SELECT id, tenant_id FROM public.api_keys WHERE key_hash = p_key_hash",
    )
    assert statements == [
        "CREATE FUNCTION lookup_api_key(p_key_hash bytea) "
        "RETURNS TABLE (key_id uuid, owner_tenant_id uuid) "
        "LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp "
        "AS $$ SELECT id, tenant_id FROM public.api_keys WHERE key_hash = p_key_hash $$",
        "REVOKE ALL ON FUNCTION lookup_api_key(p_key_hash bytea) FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION lookup_api_key(p_key_hash bytea) TO sft_api",
        "ALTER FUNCTION lookup_api_key(p_key_hash bytea) OWNER TO sft_lookup",
    ]


@pytest.mark.parametrize(
    ("signature", "body", "message"),
    [
        ("lookup_x", "SELECT 1", "signature"),
        ("lookup_x(a text); DROP TABLE tenants; --()", "SELECT 1", "signature"),
        ("Lookup_x(a text)", "SELECT 1", "signature"),
        ("lookup_x(a text)", "SELECT 1 $$; DROP TABLE tenants; $$", r"\$\$"),
    ],
)
def test_lookup_function_mistakes_are_caught(signature: str, body: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        lookup_function_sql(signature, returns="int", body=body)


def test_only_lookup_read_policies_name_the_lookup_role() -> None:
    sql = policy_sql("lookup_read", "t", roles=["sft_lookup"], command="SELECT", using="true")
    assert sql.endswith("TO sft_lookup USING (true)")


def test_grants_can_be_limited_to_columns() -> None:
    assert grant_sql("audit_events", "sft_api", "INSERT", columns=["id", "action"]) == (
        "GRANT INSERT (id, action) ON audit_events TO sft_api"
    )
    assert grant_sql("widgets", "sft_api", "SELECT, UPDATE", columns=["name"]) == (
        "GRANT SELECT (name), UPDATE (name) ON widgets TO sft_api"
    )
    with pytest.raises(ValueError, match="whole rows"):
        grant_sql("widgets", "sft_api", "DELETE", columns=["name"])
    with pytest.raises(ValueError, match="identifier"):
        grant_sql("widgets", "sft_api", "INSERT", columns=["name; DROP TABLE tenants"])

"""The real revisions: numbered in a line, honest about what they serve, in step with the models."""

import ast
import re
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from pg import ScratchDatabase
from sft.data.database import sync_engine
from sft.data.migrate import alembic_config, compatible_with
from sft.data.models import Base
from sft.data.rls import tenant_rls_sql

SCRIPTS = ScriptDirectory.from_config(alembic_config())


def test_revisions_form_one_numbered_line() -> None:
    # Linear history keeps "older" and "newer" unambiguous for the migration job.
    revisions = list(reversed(list(SCRIPTS.walk_revisions())))
    assert SCRIPTS.get_heads() == [revisions[-1].revision]
    for number, script in enumerate(revisions, start=1):
        assert script.revision == f"{number:04d}"
        assert script.down_revision == (None if number == 1 else f"{number - 1:04d}")
        assert re.fullmatch(rf"{script.revision}_[a-z0-9_]+\.py", Path(script.path).name)


def test_compatible_with_names_only_earlier_revisions() -> None:
    for script in SCRIPTS.walk_revisions():
        earlier = (
            {s.revision for s in SCRIPTS.iterate_revisions(script.down_revision, "base")}
            if script.down_revision
            else set()
        )
        assert set(compatible_with(script)) <= earlier, script.revision


def test_revisions_keep_literal_sql_and_import_nothing_of_ours() -> None:
    # A revision that called sft.data.rls would change what it does whenever the helpers change.
    for script in SCRIPTS.walk_revisions():
        tree = ast.parse(Path(str(script.path)).read_text())
        modules = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        modules += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        ours = [m for m in modules if m == "sft" or m.startswith("sft.")]
        assert ours == [], f"{script.revision} imports {ours}"


def test_0001_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    # 0001 was written by pasting this output. If a helper changes on purpose, 0001 must not:
    # replace the call below with the old output, as a literal, and keep the test.
    frozen = SCRIPTS.get_revision("0001").module.TENANTS_RLS
    assert list(frozen) == tenant_rls_sql(
        "tenants", key="id", grants={"sft_api": "SELECT", "sft_operator": "SELECT, INSERT, UPDATE"}
    )


def test_the_models_match_the_migrations(migrated_db: ScratchDatabase) -> None:
    engine = sync_engine(migrated_db.admin)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()


def test_the_job_recorded_what_head_serves(migrated_db: ScratchDatabase) -> None:
    head = SCRIPTS.get_current_head()
    assert migrated_db.sql("SELECT version_num FROM alembic_version") == [(head,)]
    rows = migrated_db.sql(
        "SELECT compatible_with FROM schema_compatibility WHERE revision = :head", head=head
    )
    assert rows == [(list(compatible_with(SCRIPTS.get_revision(head))),)]

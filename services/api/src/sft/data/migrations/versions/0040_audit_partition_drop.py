"""Audit events past their 365 days: the monthly partitions are dropped (#255; NFR-9; data model 6).

Revision 0040, after 0039 (the archive's surviving-region mode). Expand only (data model 7): two
new functions and their grants, so the code of the revisions in `compatible_with` still runs on
this schema. Renumbering it changes only `revision`, `down_revision` and the file name.

- `audit_drop_expired_partitions(as_of)` drops each monthly partition of `audit_events` whose
  newest possible row is 365 days old: the month's end is at least 365 days before `as_of`. It
  drops a month only when every row in it is archived in both regions: below the archive job's
  cursor (revision 0034), and below every range still waiting for its back-fill to the other
  region (revision 0039). A month that isn't is `unarchived`, kept, and tried again by the next
  run. A month the function can't lock within a second, or can't drop, is `failed`, kept too.
- `audit_expired_partitions(as_of)` counts the expired months still there, which the lifecycle
  job exports as `sft_audit_expired_partitions` for the `AuditPartitions` alert.

**Who may drop.** Dropping a partition needs its owner, `sft_owner`. The choice was between the
owner's credentials in a job of their own, and a narrow `SECURITY DEFINER` function the daily
partition job (`sft_jobs`) may call. It is the function, as for creating partitions (revision
0002): the owner's login stays in the migration job alone, and the function can do one thing,
drop a month that the retention and the archive both allow. The retention is fixed here, not an
argument, and `as_of` can only make it later, never earlier: a time after the database's own
`now()` is taken as `now()`. So a caller with a wrong clock, or a compromised `sft_jobs`, can
never drop a month the database's clock still keeps. No application role may drop, detach or
truncate a partition itself (tests/test_audit_hardening.py).

**Locks.** The function takes the partition upkeep's advisory lock, so it never runs beside
`audit_create_partitions`. For each month it locks the partition against writes, checks it, and
drops it, which takes `audit_events` itself in `ACCESS EXCLUSIVE` mode for a moment: audit inserts
wait for at most the second of the lock timeout, once a month.

Like every revision, it keeps the literal SQL it runs.
"""

from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

# Two new functions and their grants: no earlier code is affected. Back to 0017, as 0039 does.
compatible_with: tuple[str, ...] = (
    down_revision,
    "0038",
    "0037",
    "0036",
    "0035",
    "0034",
    "0033",
    "0032",
    "0031",
    "0030",
    "0029",
    "0028",
    "0027",
    "0026",
    "0025",
    "0024",
    "0023",
    "0022",
    "0021",
    "0020",
    "0019",
    "0018",
    "0017",
)

# Both functions know a partition by its name, `audit_events_yYYYYmMM`, a whole UTC month, which
# `audit_create_partitions` and the runbook's manual move both follow; its month ends a month after
# its first day.
DROP_EXPIRED = r"""
    CREATE FUNCTION audit_drop_expired_partitions(as_of timestamptz DEFAULT NULL)
        RETURNS TABLE (partition_name text, status text)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        SET lock_timeout = '1s'
        AS $$
    DECLARE
        -- NFR-9: 365 days. A later `as_of` than the database's clock counts as the clock.
        cutoff timestamptz := least(coalesce(as_of, now()), now()) - interval '365 days';
        archived xid8;
        waiting xid8;
        part record;
        unarchived boolean;
    BEGIN
        IF NOT pg_try_advisory_xact_lock(50000001) THEN
            RETURN;
        END IF;
        -- Archived in both regions: below the cursor, and below any range written to one
        -- region alone that waits for its back-fill (revision 0039).
        SELECT c.archived_up_to_tx INTO archived FROM public.audit_archive_cursor c;
        SELECT min(s.from_tx) INTO waiting FROM public.audit_archive_single_region s;
        IF waiting IS NOT NULL AND waiting < archived THEN
            archived := waiting;
        END IF;
        FOR part IN
            SELECT c.relname,
                   (make_date(substr(c.relname, 15, 4)::integer,
                              substr(c.relname, 20, 2)::integer, 1)
                    + interval '1 month') AT TIME ZONE 'UTC' AS ends
              FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = 'public.audit_events'::regclass
               AND c.relname ~ '^audit_events_y[0-9]{4}m(0[1-9]|1[0-2])$'
             ORDER BY c.relname
        LOOP
            CONTINUE WHEN part.ends > cutoff;
            partition_name := part.relname;
            BEGIN
                -- No row can be added to the month between the check and the drop.
                EXECUTE format('LOCK TABLE public.%I IN SHARE MODE', part.relname);
                IF archived IS NULL THEN
                    unarchived := true;
                ELSE
                    EXECUTE format('SELECT EXISTS (SELECT FROM public.%I WHERE tx_id >= $1)',
                                   part.relname)
                        INTO unarchived USING archived;
                END IF;
                IF unarchived THEN
                    status := 'unarchived';
                ELSE
                    EXECUTE format('DROP TABLE public.%I', part.relname);
                    status := 'dropped';
                END IF;
            EXCEPTION
                WHEN OTHERS THEN
                    RAISE WARNING 'audit partition % not dropped: % (%)',
                                  part.relname, SQLERRM, SQLSTATE;
                    status := 'failed';
            END;
            RETURN NEXT;
        END LOOP;
    END
    $$
"""

# What the alert watches: expired months still there. It reads the catalog only, so it needs no
# definer's rights.
EXPIRED = r"""
    CREATE FUNCTION audit_expired_partitions(as_of timestamptz DEFAULT NULL)
        RETURNS integer
        LANGUAGE sql STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
    SELECT count(*)::integer
      FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
     WHERE i.inhparent = 'public.audit_events'::regclass
       AND c.relname ~ '^audit_events_y[0-9]{4}m(0[1-9]|1[0-2])$'
       AND (make_date(substr(c.relname, 15, 4)::integer, substr(c.relname, 20, 2)::integer, 1)
            + interval '1 month') AT TIME ZONE 'UTC'
           <= least(coalesce(as_of, now()), now()) - interval '365 days'
    $$
"""

GRANTS = (
    "REVOKE EXECUTE ON FUNCTION audit_drop_expired_partitions(timestamptz) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION audit_drop_expired_partitions(timestamptz) TO sft_jobs",
    "REVOKE EXECUTE ON FUNCTION audit_expired_partitions(timestamptz) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION audit_expired_partitions(timestamptz) TO sft_jobs",
)


def upgrade() -> None:
    op.execute(DROP_EXPIRED)
    op.execute(EXPIRED)
    for statement in GRANTS:
        op.execute(statement)


def downgrade() -> None:
    # Deploys and rollbacks never run a down-migration (ADR-0005).
    raise NotImplementedError

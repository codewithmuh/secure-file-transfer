"""The audit helpers' checks, without a database: what may go into an event, and the trigger SQL."""

import uuid
from datetime import datetime
from ipaddress import ip_address

import pytest

from sft.data import audit
from sft.data.audit import Actor, ActorType, Origin, Target
from sft.data.audit_required import require_audit_sql


def test_the_trigger_watches_every_change_by_default() -> None:
    assert require_audit_sql("transfers") == (
        "CREATE CONSTRAINT TRIGGER audit_required AFTER INSERT OR UPDATE OR DELETE ON transfers "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit_required()"
    )


def test_the_trigger_can_watch_some_commands_and_columns() -> None:
    assert require_audit_sql(
        "api_keys", commands=("UPDATE", "INSERT"), update_of=("revoked_at", "scopes")
    ) == (
        "CREATE CONSTRAINT TRIGGER audit_required AFTER INSERT OR UPDATE OF revoked_at, scopes "
        "ON api_keys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit_required()"
    )


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"commands": ()}, "each audited command once"),
        ({"commands": ("INSERT", "INSERT")}, "each audited command once"),
        ({"commands": ("TRUNCATE",)}, "only INSERT, UPDATE or DELETE"),
        ({"commands": ("INSERT",), "update_of": ("status",)}, "narrows UPDATE"),
        ({"update_of": ("status; DROP TABLE tenants",)}, "identifier"),
    ],
)
def test_trigger_mistakes_are_caught(options: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        require_audit_sql("widgets", **options)  # type: ignore[arg-type]


def test_actors() -> None:
    Actor(ActorType.SYSTEM)
    Actor(ActorType.MEMBER, uuid.uuid4())
    with pytest.raises(ValueError, match="system actor has no ID"):
        Actor(ActorType.MEMBER)
    with pytest.raises(ValueError, match="system actor has no ID"):
        Actor(ActorType.SYSTEM, uuid.uuid4())
    with pytest.raises(TypeError, match="ActorType"):
        Actor("member", uuid.uuid4())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="UUID"):
        Actor(ActorType.MEMBER, str(uuid.uuid4()))  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["Transfer", "transfer.file", "contract.pdf", "", "a" * 65, 7])
def test_target_types_are_codes(kind: object) -> None:
    with pytest.raises(ValueError, match="lower-case code"):
        Target(kind, uuid.uuid4())  # type: ignore[arg-type]


def test_targets_are_referred_to_by_id() -> None:
    with pytest.raises(TypeError, match="UUID"):
        Target("transfer", "contract.pdf")  # type: ignore[arg-type]


def test_origins_take_parsed_addresses() -> None:
    Origin(source_ip=ip_address("192.0.2.1"), user_agent="curl/8")
    with pytest.raises(TypeError, match="ipaddress"):
        Origin(source_ip="192.0.2.1")  # type: ignore[arg-type]


@pytest.mark.parametrize("action", ["revoked", "Transfer.Revoked", "transfer.", "a.b c", 1])
def test_actions_are_dotted_codes(action: object) -> None:
    with pytest.raises(ValueError, match="dotted lower-case code"):
        audit._action(action)


@pytest.mark.parametrize(
    "value",
    ["contract.pdf", "alice@example.com", b"bytes", 1.5, ["a"], {"nested": 1}],
)
def test_details_refuse_anything_that_could_carry_free_text(value: object) -> None:
    with pytest.raises(TypeError, match="never free text"):
        audit._details({"value": value})  # type: ignore[dict-item]


def test_details_keys_are_codes_and_times_are_aware() -> None:
    with pytest.raises(ValueError, match="lower-case code"):
        audit._details({"File Name": 1})
    with pytest.raises(ValueError, match="aware datetime"):
        audit._details({"at": datetime(2026, 11, 4)})


def test_uuid7_is_version_7_and_sorts_by_time() -> None:
    first, second = audit.uuid7(), audit.uuid7()
    assert (first.version, first.variant) == (7, uuid.RFC_4122)
    assert first.int >> 80 <= second.int >> 80

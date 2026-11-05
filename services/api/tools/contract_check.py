"""The generated-spec check: the API the code builds must match the contract (ADR-0002, #53).

The contract, docs/api/openapi.yaml, is written first and leads. This check builds the OpenAPI
document of each app the service runs, as FastAPI generates it, and compares every operation in it
with the contract:

- an operation that isn't in the contract fails, and so does a route the document doesn't show;
- an operation that is in the contract must match it in method, path, operation ID, parameters,
  request body, success responses and error responses (status codes, media types and schemas), so
  a route that declares an error the contract doesn't, or leaves one out, fails;
- contract operations the code doesn't implement yet are allowed, and counted.

Schemas are compared after both sides are normalised, so that two ways of writing the same schema
compare equal. docs/api/README.md section 11 lists what is compared, what isn't, and why.

Run it from services/api with `uv run python -m tools.contract_check`, or `make contract` from the
repository root.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import yaml
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts

from sft.api.app import create_app
from sft.api.operator.app import create_operator_app

CONTRACT: Final = Path(__file__).resolve().parents[3] / "docs" / "api" / "openapi.yaml"

# The contract's servers. An operation belongs to the server its path item or the document names.
PUBLIC_SERVER: Final = "/v1"
OPERATOR_SERVER: Final = "http://127.0.0.1:{local_port}/v1"

METHODS: Final = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# Keywords that only document a schema. Everything else in a schema is compared.
_ANNOTATIONS: Final = frozenset(
    {"title", "description", "example", "examples", "$comment", "externalDocs", "xml", "$schema"}
)
_SCHEMA_MAPS: Final = ("properties", "patternProperties", "dependentSchemas")
_SCHEMA_LISTS: Final = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_VALUES: Final = (
    "items",
    "additionalProperties",
    "unevaluatedProperties",
    "unevaluatedItems",
    "not",
    "if",
    "then",
    "else",
    "contains",
    "propertyNames",
    "contentSchema",
)
_NULL: Final = {"type": "null"}

Json = Any  # a parsed JSON or YAML value


def service_apps() -> dict[str, FastAPI]:
    """Each app the service runs, by the contract server it serves."""
    return {PUBLIC_SERVER: create_app(), OPERATOR_SERVER: create_operator_app()}


class ContractError(Exception):
    """The contract or a generated document can't be read."""


class _ContractLoader(yaml.SafeLoader):
    """Reads YAML 1.2 scalars, as Redocly and oasdiff do.

    PyYAML follows YAML 1.1, where `yes`, `no`, `on` and `off` are booleans and `2026-11-04` is a
    date. In YAML 1.2 only `true` and `false` are booleans, and dates are strings.
    """


_ContractLoader.yaml_implicit_resolvers = {
    first: [
        (tag, regexp)
        for tag, regexp in resolvers
        if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp")
    ]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_ContractLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def load_contract(path: Path) -> dict[str, Json]:
    # _ContractLoader is a SafeLoader, so S506's warning about unsafe loaders doesn't apply.
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=_ContractLoader)  # noqa: S506
    if not isinstance(document, dict):
        raise ContractError(f"{path} isn't an OpenAPI document")
    return document


# ---- normalisation ----


def _sort_key(value: Json) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _unique(values: Sequence[Json]) -> list[Json]:
    seen: dict[str, Json] = {}
    for value in values:
        seen.setdefault(_sort_key(value), value)
    return list(seen.values())


def _merge_all_of(schema: dict[str, Json]) -> dict[str, Json]:
    """Flattens `allOf` of object schemas, as Pydantic writes a subclass. Gives up on a conflict."""
    merged = {key: value for key, value in schema.items() if key != "allOf"}
    for branch in schema["allOf"]:
        for key, value in branch.items():
            if key == "properties":
                properties = dict(merged.get("properties", {}))
                for name, subschema in value.items():
                    if properties.get(name, subschema) != subschema:
                        return schema
                    properties[name] = subschema
                merged["properties"] = properties
            elif key == "required":
                merged["required"] = [*merged.get("required", []), *value]
            elif merged.get(key, value) != value:
                return schema
            else:
                merged[key] = value
    return merged


def _merge_nullable(schema: dict[str, Json], keyword: str) -> dict[str, Json]:
    """`anyOf: [X, {type: null}]`, as Pydantic writes `X | None`, becomes `type: [..., null]`."""
    branches = schema[keyword]
    if len(branches) != 2 or _NULL not in branches:
        return schema
    other = branches[1] if branches[0] == _NULL else branches[0]
    if not isinstance(other.get("type"), str | list) or any(
        key in other for key in ("anyOf", "oneOf", "allOf", "not")
    ):
        return schema
    nullable = dict(other)
    types = [other["type"]] if isinstance(other["type"], str) else list(other["type"])
    nullable["type"] = [*types, "null"]
    if "enum" in nullable:  # a branch is canonical already: `const` became `enum`
        nullable["enum"] = [*nullable["enum"], None]
    rest = {key: value for key, value in schema.items() if key != keyword}
    if any(nullable.get(key, value) != value for key, value in rest.items()):
        return schema
    return {**nullable, **rest}


def _canonical(schema: dict[str, Json]) -> dict[str, Json]:
    """One spelling for schemas that mean the same."""
    result = dict(schema)
    if "allOf" in result:
        result = _merge_all_of(result)
    for keyword in ("anyOf", "oneOf"):
        if keyword in result:
            result = _merge_nullable(result, keyword)
    if "const" in result and "enum" not in result:
        result["enum"] = [result.pop("const")]
    if isinstance(result.get("type"), list):
        types = sorted(set(result["type"]))
        result["type"] = types[0] if len(types) == 1 else types
    if "enum" in result:
        result["enum"] = sorted(_unique(result["enum"]), key=_sort_key)
    if "required" in result:
        result["required"] = sorted(set(result["required"]))
    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword in result:
            result[keyword] = sorted(result[keyword], key=_sort_key)
    if result.get("additionalProperties") in ({}, True):
        del result["additionalProperties"]  # the default: any other property is allowed
    if "default" in result and result["default"] is None:
        del result["default"]  # how Pydantic marks an optional field; no default in the contract
    return result


def _without_null(schema: dict[str, Json]) -> dict[str, Json]:
    """Drops `null` from a schema where a client can't send one: parameters, an optional body."""
    result = dict(schema)
    types = result.get("type")
    if isinstance(types, list) and "null" in types:
        rest = [name for name in types if name != "null"]
        result["type"] = rest[0] if len(rest) == 1 else rest
        if "enum" in result:
            result["enum"] = [value for value in result["enum"] if value is not None]
    for keyword in ("anyOf", "oneOf"):
        if keyword in result and _NULL in result[keyword]:
            branches = [branch for branch in result[keyword] if branch != _NULL]
            others = {key: value for key, value in result.items() if key != keyword}
            result = (
                {**branches[0], **others} if len(branches) == 1 else {**others, keyword: branches}
            )
    return result


class _Normaliser:
    """Resolves `$ref`s within one document and puts schemas in canonical form."""

    def __init__(self, document: Mapping[str, Json]) -> None:
        self._document = document

    def pointer(self, ref: str) -> Json:
        if not ref.startswith("#/"):
            raise ContractError(f"only local $refs are supported, not {ref}")
        node: Json = self._document
        for part in ref[2:].split("/"):
            try:
                node = node[part.replace("~1", "/").replace("~0", "~")]
            except (KeyError, IndexError, TypeError) as exc:
                raise ContractError(f"$ref {ref} doesn't resolve") from exc
        return node

    def resolve(self, node: Json) -> Json:
        """Follows a Reference Object to the parameter, request body or response it names."""
        seen: set[str] = set()
        while isinstance(node, Mapping) and "$ref" in node:
            ref = node["$ref"]
            if ref in seen:
                raise ContractError(f"$ref {ref} refers to itself")
            seen.add(ref)
            node = self.pointer(ref)
        return node

    def schema(self, node: Json, stack: tuple[str, ...] = ()) -> Json:
        if node is True:
            return {}
        if node is False:
            return {"not": {}}
        if not isinstance(node, Mapping):
            raise ContractError(f"not a schema: {node!r}")
        if "$ref" in node:
            ref = node["$ref"]
            if ref in stack:  # a recursive schema: mark how far up the cycle closes
                return {"$cycle": len(stack) - stack.index(ref)}
            target = self.schema(self.pointer(ref), (*stack, ref))
            # OpenAPI 3.1 allows keywords beside $ref; the contract uses them for defaults.
            siblings = self.schema({k: v for k, v in node.items() if k != "$ref"}, stack)
            return _canonical({**target, **siblings})
        result: dict[str, Json] = {}
        for key, value in node.items():
            if key in _ANNOTATIONS or key.startswith("x-"):
                continue
            if key in _SCHEMA_MAPS:
                result[key] = {name: self.schema(sub, stack) for name, sub in value.items()}
            elif key in _SCHEMA_LISTS:
                result[key] = [self.schema(sub, stack) for sub in value]
            elif key in _SCHEMA_VALUES:  # `false` stays as written, to read well in a message
                result[key] = value if isinstance(value, bool) else self.schema(value, stack)
            elif key == "discriminator":  # the mapping names components, which differ
                result[key] = {"propertyName": value.get("propertyName")}
            else:
                result[key] = value
        return _canonical(result)


# ---- the parts of an operation that are compared ----


def _parameters(
    path_item: Mapping[str, Json], operation: Mapping[str, Json], normaliser: _Normaliser
) -> dict[tuple[str, str], tuple[str, dict[str, Json]]]:
    """Parameters by location and name (header names ignore case), with the name as written."""
    result: dict[tuple[str, str], tuple[str, dict[str, Json]]] = {}
    for raw in [*path_item.get("parameters", []), *operation.get("parameters", [])]:
        parameter = normaliser.resolve(raw)
        location, name = parameter["in"], parameter["name"]
        style = parameter.get("style", "form" if location in ("query", "cookie") else "simple")
        normalised: dict[str, Json] = {
            "required": bool(parameter.get("required", False)) or location == "path",
            "deprecated": bool(parameter.get("deprecated", False)),
            "style": style,
            "explode": bool(parameter.get("explode", style == "form")),
            "allowReserved": bool(parameter.get("allowReserved", False)),
        }
        if "schema" in parameter:
            # A parameter is text: it can be left out, but it can't be null.
            normalised["schema"] = _without_null(normaliser.schema(parameter["schema"]))
        if "content" in parameter:
            normalised["content"] = _content(parameter["content"], normaliser)
        key = (location, name.lower() if location == "header" else name)
        result[key] = (name, normalised)  # an operation's parameter replaces its path item's
    return result


def _content(content: Mapping[str, Json], normaliser: _Normaliser) -> dict[str, Json]:
    return {
        media_type: normaliser.schema(media.get("schema", {}))
        for media_type, media in content.items()
    }


def _request_body(operation: Mapping[str, Json], normaliser: _Normaliser) -> dict[str, Json] | None:
    if "requestBody" not in operation:
        return None
    body = normaliser.resolve(operation["requestBody"])
    required = bool(body.get("required", False))
    content = _content(body.get("content", {}), normaliser)
    if not required:  # FastAPI writes an optional body as `X | None`
        content = {media_type: _without_null(schema) for media_type, schema in content.items()}
    return {"required": required, "content": content}


def _is_success(status: str) -> bool:
    return status[:1] in ("2", "3")


def _is_error(status: str) -> bool:
    """A 4xx or 5xx status, a range such as `4XX`, or `default`."""
    return status[:1] in ("4", "5") or status == "default"


def _responses(
    operation: Mapping[str, Json], normaliser: _Normaliser, kind: Callable[[str], bool]
) -> dict[str, dict[str, Json]]:
    return {
        str(status): _content(normaliser.resolve(response).get("content", {}), normaliser)
        for status, response in operation.get("responses", {}).items()
        if kind(str(status))
    }


def _show(value: Json) -> str:
    text = json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= 120 else text[:117] + "..."


def _diff(contract: Json, code: Json, pointer: str = "") -> list[str]:
    """Where two normalised values differ, by JSON Pointer."""
    if contract == code:
        return []
    if isinstance(contract, dict) and isinstance(code, dict):
        differences = []
        for key in sorted(set(contract) | set(code)):
            here = f"{pointer}/{key}"
            if key not in code:
                differences.append(
                    f"at {here}: the contract has {_show(contract[key])}, the code nothing"
                )
            elif key not in contract:
                differences.append(
                    f"at {here}: the code has {_show(code[key])}, the contract nothing"
                )
            else:
                differences.extend(_diff(contract[key], code[key], here))
        return differences
    return [f"at {pointer or '/'}: the contract has {_show(contract)}, the code {_show(code)}"]


def _diff_content(contract: Mapping[str, Json], code: Mapping[str, Json], where: str) -> list[str]:
    """Compares media types, then the schema of each."""
    if set(contract) != set(code):
        return [f"{where}: the contract has {sorted(contract)}, the code {sorted(code)}"]
    return [
        f"{where} {media_type} {difference}"
        for media_type in sorted(contract)
        for difference in _diff(contract[media_type], code[media_type])
    ]


# ---- the check ----


@dataclass(frozen=True)
class ContractOperation:
    server: str
    method: str
    path: str
    operation: Mapping[str, Json]
    path_item: Mapping[str, Json]

    @property
    def operation_id(self) -> str:
        return str(self.operation.get("operationId", ""))

    def __str__(self) -> str:
        return f"{self.operation_id} ({self.method.upper()} {self.path})"


def _servers(node: Mapping[str, Json]) -> str | None:
    servers = node.get("servers") or []
    return str(servers[0]["url"]) if servers else None


def contract_operations(contract: Mapping[str, Json]) -> list[ContractOperation]:
    root = _servers(contract) or "/"
    return [
        ContractOperation(
            server=_servers(operation) or _servers(path_item) or root,
            method=method,
            path=path,
            operation=operation,
            path_item=path_item,
        )
        for path, path_item in contract.get("paths", {}).items()
        for method, operation in path_item.items()
        if method in METHODS
    ]


def _shape(path: str) -> str:
    """A path with its parameter names left out, so a renamed parameter is still found."""
    return re.sub(r"\{[^}]*\}", "{}", path)


@dataclass
class Report:
    problems: list[str] = field(default_factory=list)
    implemented: list[ContractOperation] = field(default_factory=list)
    remaining: list[ContractOperation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def render(self, *, list_remaining: bool = False) -> str:
        total = len(self.implemented) + len(self.remaining)
        lines = ["Generated spec check: the code against docs/api/openapi.yaml (ADR-0002)"]
        lines += [f"  - {problem}" for problem in self.problems]
        remain = "remains" if len(self.remaining) == 1 else "remain"
        lines.append(
            f"{len(self.implemented)} of {total} contract operations implemented, "
            f"{len(self.remaining)} {remain}."
        )
        if list_remaining:
            lines += [f"  remaining: {operation}" for operation in self.remaining]
        if self.ok:
            lines.append("OK: every implemented operation matches the contract.")
        else:
            count = len(self.problems)
            lines.append(
                f"FAILED: {count} difference{'s' if count > 1 else ''}. Change the code to match "
                "the contract, or change the contract in the same pull request "
                "(docs/api/README.md, section 11)."
            )
        return "\n".join(lines)


def _compare_info(contract: Mapping[str, Json], document: Mapping[str, Json]) -> list[str]:
    """The title and version of the document, and the OpenAPI version up to the minor."""
    expected, actual = contract.get("info", {}), document.get("info", {})
    differences = [
        f"info/{key}: the contract has {expected.get(key)!r}, the code {actual.get(key)!r}"
        for key in ("title", "version")
        if expected.get(key) != actual.get(key)
    ]
    versions = (str(contract.get("openapi")), str(document.get("openapi")))
    if versions[0].split(".")[:2] != versions[1].split(".")[:2]:
        differences.append(f"openapi: the contract is {versions[0]}, the code {versions[1]}")
    return differences


def _hidden_routes(app: FastAPI) -> list[str]:
    """Routes the OpenAPI document leaves out escape the comparison, so each one is a problem."""
    problems = []
    for context in iter_route_contexts(app.routes):
        if isinstance(context.original_route, APIRoute) and context.include_in_schema:
            continue
        methods = ",".join(sorted(context.methods or ())) or type(context.original_route).__name__
        problems.append(
            f"{methods} {context.path}: a route the OpenAPI document doesn't show "
            "(include_in_schema=False, a mount or a Starlette route), so it can't be checked"
        )
    return problems


def _compare_operation(
    contract_op: ContractOperation,
    contract_normaliser: _Normaliser,
    path: str,
    path_item: Mapping[str, Json],
    operation: Mapping[str, Json],
    normaliser: _Normaliser,
) -> list[str]:
    differences = []
    if path != contract_op.path:
        differences.append(f"path: the contract has {contract_op.path}, the code {path}")
    if operation.get("operationId") != contract_op.operation_id:
        differences.append(
            f"operation ID: the contract has {contract_op.operation_id}, "
            f"the code {operation.get('operationId')}"
        )
    if bool(operation.get("deprecated")) != bool(contract_op.operation.get("deprecated")):
        differences.append(
            f"deprecated: the contract has {bool(contract_op.operation.get('deprecated'))}, "
            f"the code {bool(operation.get('deprecated'))}"
        )

    expected = _parameters(contract_op.path_item, contract_op.operation, contract_normaliser)
    actual = _parameters(path_item, operation, normaliser)
    for key in sorted(set(expected) | set(actual)):
        location = key[0]
        if key not in actual:
            differences.append(f"{location} parameter {expected[key][0]}: missing in the code")
        elif key not in expected:
            differences.append(f"{location} parameter {actual[key][0]}: not in the contract")
        else:
            differences += [
                f"{location} parameter {expected[key][0]} {difference}"
                for difference in _diff(expected[key][1], actual[key][1])
            ]

    contract_body = _request_body(contract_op.operation, contract_normaliser)
    body = _request_body(operation, normaliser)
    if contract_body is not None and body is None:
        differences.append("request body: the contract has one, the code none")
    elif contract_body is None and body is not None:
        differences.append("request body: the code takes one, the contract none")
    elif contract_body is not None and body is not None:
        if contract_body["required"] != body["required"]:
            differences.append(
                f"request body required: the contract has {contract_body['required']}, "
                f"the code {body['required']}"
            )
        differences += _diff_content(contract_body["content"], body["content"], "request body")

    contract_responses = _responses(contract_op.operation, contract_normaliser, _is_success)
    responses = _responses(operation, normaliser, _is_success)
    if set(contract_responses) != set(responses):
        differences.append(
            f"success statuses: the contract has {sorted(contract_responses)}, "
            f"the code {sorted(responses)}"
        )
    for status in sorted(set(contract_responses) & set(responses)):
        differences += _diff_content(
            contract_responses[status], responses[status], f"response {status}"
        )
    return differences + _compare_errors(contract_op, contract_normaliser, operation, normaliser)


def _compare_errors(
    contract_op: ContractOperation,
    contract_normaliser: _Normaliser,
    operation: Mapping[str, Json],
    normaliser: _Normaliser,
) -> list[str]:
    """Each error status the code declares must be one the contract declares, and the reverse."""
    expected = _responses(contract_op.operation, contract_normaliser, _is_error)
    actual = _responses(operation, normaliser, _is_error)
    differences = [
        f"error response {status}: not in the contract, so the route may not answer with it"
        for status in sorted(set(actual) - set(expected))
    ]
    differences += [
        f"error response {status}: missing in the code; declare it with "
        "sft.api.errors.problem_responses()"
        for status in sorted(set(expected) - set(actual))
    ]
    for status in sorted(set(expected) & set(actual)):
        differences += _diff_content(expected[status], actual[status], f"response {status}")
    return differences


def _not_in_contract(
    label: str,
    server: str,
    method: str,
    path: str,
    operation_id: Json,
    operations: Sequence[ContractOperation],
) -> str:
    for other in operations:
        if other.method == method and _shape(other.path) == _shape(path):
            return (
                f"{label}: the contract serves {other} from the server {other.server}, "
                f"not from this app's ({server})"
            )
    for other in operations:
        if other.operation_id == operation_id:
            return f"{label}: not in the contract here; the contract has {other} on {other.server}"
    return f"{label}: not in the contract. Add it to docs/api/openapi.yaml first (ADR-0002)."


def check(apps: Mapping[str, FastAPI], contract: Mapping[str, Json]) -> Report:
    """Compares the OpenAPI document of each app with the contract operations of its server."""
    report = Report()
    operations = contract_operations(contract)
    by_shape = {(op.server, op.method, _shape(op.path)): op for op in operations}
    servers = {op.server for op in operations} | {_servers(contract)}
    contract_normaliser = _Normaliser(contract)
    implemented: set[tuple[str, str, str]] = set()

    for server, app in apps.items():
        if server not in servers:
            report.problems.append(f"server {server}: the contract has no server with this URL")
            continue
        report.problems += [f"{server}: {problem}" for problem in _hidden_routes(app)]
        document = app.openapi()
        report.problems += [f"{server}: {problem}" for problem in _compare_info(contract, document)]
        normaliser = _Normaliser(document)
        base = urlsplit(server).path.rstrip("/")
        for full_path, path_item in document.get("paths", {}).items():
            for method, operation in path_item.items():
                if method not in METHODS:
                    continue
                label = f"{method.upper()} {full_path} ({operation.get('operationId')})"
                if full_path != base and not full_path.startswith(f"{base}/"):
                    report.problems.append(f"{label}: outside the server's base path {base}")
                    continue
                path = full_path[len(base) :] or "/"
                key = (server, method, _shape(path))
                contract_op = by_shape.get(key)
                if contract_op is None:
                    report.problems.append(
                        _not_in_contract(
                            label, server, method, path, operation.get("operationId"), operations
                        )
                    )
                    continue
                implemented.add(key)
                report.problems += [
                    f"{label}: {difference}"
                    for difference in _compare_operation(
                        contract_op, contract_normaliser, path, path_item, operation, normaliser
                    )
                ]

    for op in operations:
        done = (op.server, op.method, _shape(op.path)) in implemented
        (report.implemented if done else report.remaining).append(op)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.contract_check",
        description="Check the OpenAPI document generated from the code against the contract.",
    )
    parser.add_argument("--contract", type=Path, default=CONTRACT, help="the contract to check")
    parser.add_argument(
        "--list-remaining", action="store_true", help="list the operations not implemented yet"
    )
    args = parser.parse_args(argv)
    try:
        report = check(service_apps(), load_contract(args.contract))
    except (ContractError, OSError, yaml.YAMLError) as exc:
        print(f"Generated spec check: {exc}", file=sys.stderr)
        return 2
    print(report.render(list_remaining=args.list_remaining))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())

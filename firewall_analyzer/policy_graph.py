"""Canonical, format-neutral firewall policy graph.

Parsers produce native Chain/Rule objects. The parser boundary converts them
into this mapping-compatible graph so analysis services depend on semantics,
not on a particular firewall syntax.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Iterator, Mapping
import ipaddress
import json

from firewall_analyzer.models import Chain, PortRange, Rule


@dataclass
class PolicyGraph(Mapping[str, Chain]):
    """Normalized firewall policy with generic evaluation scopes."""

    source_format: str
    scopes: dict[str, Chain] = field(default_factory=dict)
    metadata: dict[str, object] = field(default_factory=dict)
    extensions: dict[str, object] = field(default_factory=dict)
    schema_version: str = "1.0"

    # Mapping compatibility keeps existing analysis services stable while they
    # migrate from the old ``dict[str, Chain]`` contract.
    def items(self):
        return self.scopes.items()

    def keys(self):
        return self.scopes.keys()

    def values(self):
        return self.scopes.values()

    def get(self, key: str, default=None):
        return self.scopes.get(key, default)

    def __getitem__(self, key: str) -> Chain:
        return self.scopes[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.scopes)

    def __len__(self) -> int:
        return len(self.scopes)

    def __bool__(self) -> bool:
        return bool(self.scopes)

    def to_dict(self) -> dict:
        """Return the canonical JSON-compatible representation."""
        return {
            "schema_version": self.schema_version,
            "source_format": self.source_format,
            "metadata": self.metadata,
            "extensions": self.extensions,
            "scopes": {
                scope_id: _scope_to_dict(scope)
                for scope_id, scope in self.scopes.items()
            },
        }

    def to_json(self) -> str:
        """Return the canonical graph as a JSON document."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "PolicyGraph":
        """Rebuild a policy graph from canonical JSON data."""
        raw_scopes = data.get("scopes", {})
        if not isinstance(raw_scopes, Mapping):
            raise ValueError("Canonical policy JSON must contain an object named 'scopes'")

        scopes: dict[str, Chain] = {}
        for scope_id, raw_scope in raw_scopes.items():
            if not isinstance(raw_scope, Mapping):
                raise ValueError(f"Scope {scope_id!r} must be an object")
            raw_rules = raw_scope.get("rules", [])
            if not isinstance(raw_rules, list):
                raise ValueError(f"Scope {scope_id!r} rules must be an array")
            rules = [_rule_from_dict(raw_rule) for raw_rule in raw_rules]
            name = str(raw_scope.get("name", scope_id))
            scopes[str(scope_id)] = Chain(
                table=str(raw_scope.get("table", "filter")),
                name=name,
                default_policy=_optional_string(raw_scope.get("default_action")),
                rules=rules,
                metadata=dict(raw_scope.get("metadata", {}))
                if isinstance(raw_scope.get("metadata", {}), Mapping) else {},
            )

        return cls(
            source_format=str(data.get("source_format", "unknown")),
            scopes=scopes,
            metadata=dict(data.get("metadata", {}))
            if isinstance(data.get("metadata", {}), Mapping) else {},
            extensions=dict(data.get("extensions", {}))
            if isinstance(data.get("extensions", {}), Mapping) else {},
            schema_version=str(data.get("schema_version", "1.0")),
        )

    @classmethod
    def from_json(cls, content: str) -> "PolicyGraph":
        value = json.loads(content)
        if not isinstance(value, Mapping):
            raise ValueError("Canonical policy JSON must contain an object at the top level")
        return cls.from_dict(value)


def normalize_chains(
    chains: dict[str, Chain],
    source_format: str,
    metadata: dict[str, object] | None = None,
) -> PolicyGraph:
    """Convert parser-native chains into the canonical policy graph."""
    return PolicyGraph(
        source_format=source_format,
        scopes=dict(chains),
        metadata=metadata or {},
    )


def _scope_to_dict(scope: Chain) -> dict:
    return {
        "id": scope.name,
        "kind": scope.metadata.get("kind", "scope"),
        "table": scope.table,
        "name": scope.name,
        "default_action": scope.default_policy,
        "metadata": scope.metadata,
        "rules": [_rule_to_dict(rule) for rule in scope.rules],
    }


def _rule_to_dict(rule: Rule) -> dict:
    return {
        "action": rule.action,
        "protocol": rule.protocol,
        "sources": [str(value) for value in rule.sources],
        "destinations": [str(value) for value in rule.destinations],
        "source_ports": [
            {"min": port.min_port, "max": port.max_port}
            for port in rule.source_ports
        ],
        "destination_ports": [
            {"min": port.min_port, "max": port.max_port}
            for port in rule.ports
        ],
        "states": list(rule.states),
        "in_interface": rule.in_interface,
        "out_interface": rule.out_interface,
        "is_negated": rule.is_negated,
        "has_comment": rule.has_comment,
        "raw": rule.raw_line,
        "line_number": rule.line_number,
        "source_range": rule.src_range,
        "destination_range": rule.dst_range,
    }


def _rule_from_dict(value: object) -> Rule:
    if not isinstance(value, Mapping):
        raise ValueError("Each canonical rule must be an object")

    def networks(key: str):
        raw = value.get(key, [])
        if not isinstance(raw, list):
            raise ValueError(f"Rule field {key!r} must be an array")
        return [ipaddress.ip_network(str(item), strict=False) for item in raw]

    def ports(key: str):
        raw = value.get(key, [])
        if not isinstance(raw, list):
            raise ValueError(f"Rule field {key!r} must be an array")
        return [PortRange(int(item["min"]), int(item["max"])) for item in raw]

    raw_states = value.get("states", [])
    return Rule(
        action=str(value.get("action", "ACCEPT")),
        chain=str(value.get("chain", "")),
        protocol=_optional_string(value.get("protocol")),
        sources=networks("sources"),
        destinations=networks("destinations"),
        source_ports=ports("source_ports"),
        ports=ports("destination_ports"),
        states=[str(state) for state in raw_states] if isinstance(raw_states, list) else [],
        in_interface=_optional_string(value.get("in_interface")),
        out_interface=_optional_string(value.get("out_interface")),
        is_negated=bool(value.get("is_negated", False)),
        has_comment=bool(value.get("has_comment", False)),
        raw_line=str(value.get("raw", "")),
        line_number=int(value.get("line_number", 0)),
        src_range=_optional_string(value.get("source_range")),
        dst_range=_optional_string(value.get("destination_range")),
    )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None

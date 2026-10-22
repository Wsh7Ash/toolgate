"""Schema and policy validation gate for LLM tool-call arguments.

An agent that lets a model emit tool calls is only as safe as the validation on
those calls. `toolgate` sits between the model and your tool runner: you declare
each tool's argument schema and a set of policies, then call `gate()` on the
arguments the model produced. It returns an allow/deny verdict with structured
reasons, and a redacted preview safe to log.

Two layers, checked in order:

1. **Schema** — required keys, types, and optional per-key constraints
   (allowed values, min/max, regex pattern, max length).
2. **Policy** — deny rules (e.g. argument values matching a dangerous pattern),
   require rules, and a redaction list for sensitive keys.

Offline, deterministic, dependency-free.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Keys whose values are masked in previews by default (lowercased match).
DEFAULT_SENSITIVE_KEYS = (
    "password", "secret", "token", "api_key", "apikey", "authorization",
    "passwd", "credential", "private_key", "access_key",
)


@dataclass
class FieldSpec:
    type: str = "string"            # string | number | integer | boolean | list | dict
    required: bool = False
    allowed: list[Any] | None = None
    min: float | None = None
    max: float | None = None
    pattern: str | None = None
    max_length: int | None = None


@dataclass
class Policy:
    # Each deny entry: {"key":..., "pattern":..., "reason":...} — deny if the
    # value (as a string) matches the regex.
    deny: list[dict] = field(default_factory=list)
    # Keys that must be present and non-empty.
    require: list[str] = field(default_factory=list)
    # Extra key names whose values are redacted in previews.
    redact: list[str] = field(default_factory=list)


@dataclass
class ToolSpec:
    name: str
    schema: dict[str, FieldSpec] = field(default_factory=dict)
    policy: Policy = field(default_factory=Policy)


@dataclass
class Verdict:
    allowed: bool
    tool: str
    reasons: list[str] = field(default_factory=list)
    preview: dict = field(default_factory=dict)


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "list":
        return isinstance(value, list)
    if expected == "dict":
        return isinstance(value, dict)
    return False


def check_schema(args: dict, schema: dict[str, FieldSpec]) -> list[str]:
    """Validate args against the schema; return a list of problem descriptions."""
    problems: list[str] = []
    for key, spec in schema.items():
        if key not in args:
            if spec.required:
                problems.append(f"missing required key {key!r}")
            continue
        value = args[key]
        if not _type_ok(value, spec.type):
            problems.append(f"{key!r}: expected {spec.type}, got {type(value).__name__}")
            continue
        if spec.allowed is not None and value not in spec.allowed:
            problems.append(f"{key!r}: value {value!r} not in allowed set")
        if spec.type in ("number", "integer"):
            if spec.min is not None and value < spec.min:
                problems.append(f"{key!r}: {value} below min {spec.min}")
            if spec.max is not None and value > spec.max:
                problems.append(f"{key!r}: {value} above max {spec.max}")
        if spec.pattern is not None and isinstance(value, str):
            if not re.search(spec.pattern, value):
                problems.append(f"{key!r}: value does not match required pattern")
        if spec.max_length is not None and isinstance(value, str):
            if len(value) > spec.max_length:
                problems.append(f"{key!r}: value longer than {spec.max_length}")
    return problems


def check_policy(args: dict, policy: Policy) -> list[str]:
    """Apply deny/require policy rules; return problems."""
    problems: list[str] = []
    for key in policy.require:
        if key not in args or args[key] in ("", None):
            problems.append(f"policy requires non-empty {key!r}")
    for rule in policy.deny:
        key = rule.get("key")
        pattern = rule.get("pattern", "")
        reason = rule.get("reason", "denied by policy")
        if key in args and re.search(pattern, str(args[key])):
            problems.append(f"{key!r}: {reason}")
    return problems


def redact(args: dict, extra: list[str] | None = None) -> dict:
    """Return a copy of args with sensitive values masked."""
    sensitive = {k.lower() for k in DEFAULT_SENSITIVE_KEYS}
    if extra:
        sensitive |= {k.lower() for k in extra}
    out = {}
    for key, value in args.items():
        if key.lower() in sensitive or any(s in key.lower() for s in sensitive):
            out[key] = "***REDACTED***"
        else:
            out[key] = value
    return out


def gate(tool: ToolSpec, args: dict) -> Verdict:
    """Run schema then policy checks; return an allow/deny verdict with a preview."""
    reasons = check_schema(args, tool.schema)
    reasons += check_policy(args, tool.policy)
    preview = redact(args, extra=tool.policy.redact)
    return Verdict(
        allowed=not reasons,
        tool=tool.name,
        reasons=reasons,
        preview=preview,
    )


def render_verdict(verdict: Verdict) -> str:
    status = "ALLOW" if verdict.allowed else "DENY"
    lines = [f"{status}  tool={verdict.tool}"]
    for reason in verdict.reasons:
        lines.append(f"  - {reason}")
    lines.append(f"  preview: {verdict.preview}")
    return "\n".join(lines)

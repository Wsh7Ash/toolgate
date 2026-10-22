# toolgate

A schema + policy validation gate for LLM tool-call arguments. An agent that
lets a model emit tool calls is only as safe as the validation on those calls —
`toolgate` sits between the model and your tool runner, returns an allow/deny
verdict with structured reasons, and produces a redacted preview that is safe to
log. Offline, deterministic, dependency-free.

## Two layers, checked in order

1. **Schema** — required keys, types (`string`, `number`, `integer`, `boolean`,
   `list`, `dict`), and per-key constraints: `allowed` values, `min`/`max`,
   `pattern`, `max_length`. Python `bool` is explicitly rejected for numeric
   types so `true` never passes as `1`.
2. **Policy** — `deny` rules (regex match on a value → deny with a reason),
   `require` keys, and extra keys to redact.

Sensitive keys (`password`, `secret`, `token`, `api_key`, `authorization`, …) are
masked in previews automatically — the verdict still validates the real values.

## Install

```
pip install -e .
```

## Usage

```
toolgate tool.json args.json     # or: cat args.json | toolgate tool.json -
```

Exits `0` on ALLOW and `1` on DENY, so it drops into a pre-execution hook or CI.

`tool.json`:

```json
{
  "name": "send_email",
  "schema": {
    "to": {"type": "string", "required": true, "pattern": "^[^@]+@[^@]+$"},
    "subject": {"type": "string", "required": true, "max_length": 200}
  },
  "policy": {
    "deny": [{"key": "to", "pattern": "(?i)bcc\s*:", "reason": "hidden recipient"}]
  }
}
```

## Python API

```python
from toolgate import ToolSpec, FieldSpec, Policy, gate, render_verdict

tool = ToolSpec(
    name="send_email",
    schema={"to": FieldSpec(type="string", required=True)},
    policy=Policy(deny=[{"key": "to", "pattern": r"(?i)bcc\s*:", "reason": "hidden recipient"}]),
)
verdict = gate(tool, {"to": "a@b.com"})
print(render_verdict(verdict))
if not verdict.allowed:
    raise PermissionError(verdict.reasons)
```

## License

MIT

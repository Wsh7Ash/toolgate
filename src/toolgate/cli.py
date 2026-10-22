"""Command-line interface for toolgate.

Reads a tool spec and a candidate argument set (both JSON) and prints the
verdict. Exits 0 on ALLOW, 1 on DENY — usable as a pre-execution gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .toolgate import FieldSpec, Policy, ToolSpec, gate, render_verdict


def _parse_tool(data: dict) -> ToolSpec:
    schema = {k: FieldSpec(**v) for k, v in data.get("schema", {}).items()}
    policy = Policy(**data.get("policy", {}))
    return ToolSpec(name=data["name"], schema=schema, policy=policy)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="toolgate",
        description="Validate LLM tool-call arguments against a schema and policy.",
    )
    parser.add_argument("tool_json", help="JSON file describing the tool spec")
    parser.add_argument("args_json", help="JSON file (or '-' for stdin) of candidate arguments")
    args = parser.parse_args(argv)

    tool = _parse_tool(json.loads(Path(args.tool_json).read_text(encoding="utf-8")))
    if args.args_json == "-":
        candidate = json.load(sys.stdin)
    else:
        candidate = json.loads(Path(args.args_json).read_text(encoding="utf-8"))

    verdict = gate(tool, candidate)
    print(render_verdict(verdict))
    return 0 if verdict.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())

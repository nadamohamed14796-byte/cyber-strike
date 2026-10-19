#!/usr/bin/env python3
"""Check a local evidence-manifest JSON for core fields and secret-like values.

Validates metadata shape only. Does not read artifact files or prove complete redaction.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REQUIRED = {"artifact_id", "kind", "target_asset", "captured_at", "test_context",
            "shareable_derivative_path", "redaction_review", "claim_supported", "reviewer", "retention_basis"}
SECRET_VALUE = re.compile(r"(?i)(bearer\s+[a-z0-9._~+/-]{8,}|(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)\s*[:=]\s*\S+)")

def records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("artifacts"), list):
        return [item for item in value["artifacts"] if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        value = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read valid JSON manifest: {exc}", file=sys.stderr)
        return 2
    items = records(value)
    errors: list[str] = []
    if not items:
        errors.append("manifest must be an object, an array of objects, or an object with an artifacts array")
    for i, item in enumerate(items, 1):
        missing = sorted(REQUIRED - set(item))
        if missing:
            errors.append(f"record {i}: missing fields: {', '.join(missing)}")
        if not isinstance(item.get("redaction_review"), dict):
            errors.append(f"record {i}: redaction_review must be an object")
        for key, field_value in item.items():
            rendered = field_value if isinstance(field_value, str) else json.dumps(field_value, ensure_ascii=False)
            if SECRET_VALUE.search(rendered):
                errors.append(f"record {i}: field '{key}' may contain a secret; inspect locally without printing it")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"PASS: {len(items)} evidence manifest record(s) have required fields and no obvious secret-like values.")
    print("Manual review is still required: regex checks cannot prove complete redaction.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

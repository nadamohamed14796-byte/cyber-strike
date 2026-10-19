#!/usr/bin/env python3
"""Validate and expand an explicit, test-owned authorization matrix to JSONL.

Input JSON shape:
{"cases":[{"principal_id":"account-A","object_id":"object-A","action":"read",
"expected_allowed":true,"fixture":"local-test","notes":"owner baseline"}]}
This script generates test cases only. It sends no requests and never guesses permissions.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

REQUIRED = ("principal_id", "object_id", "action", "expected_allowed")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON fixture with an explicit cases array")
    parser.add_argument("-o", "--output", type=Path, required=True, help="output JSONL path")
    args = parser.parse_args()
    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read input JSON: {exc}", file=sys.stderr); return 2
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list):
        print("input must be an object containing a cases array", file=sys.stderr); return 2
    seen = set()
    normalized = []
    errors = []
    for index, case in enumerate(cases, 1):
        if not isinstance(case, dict):
            errors.append({"case": index, "error": "case must be a JSON object"}); continue
        missing = [key for key in REQUIRED if key not in case]
        if missing:
            errors.append({"case": index, "error": "missing required fields", "fields": missing}); continue
        if not all(isinstance(case[key], str) and case[key].strip() for key in REQUIRED[:3]):
            errors.append({"case": index, "error": "principal_id, object_id, and action must be non-empty strings"}); continue
        if not isinstance(case["expected_allowed"], bool):
            errors.append({"case": index, "error": "expected_allowed must be boolean"}); continue
        if not case.get("fixture"):
            errors.append({"case": index, "error": "fixture must identify a test-owned account/object fixture"}); continue
        key = tuple(case[field] for field in REQUIRED[:3])
        if key in seen:
            errors.append({"case": index, "error": "duplicate principal/object/action tuple", "key": list(key)}); continue
        seen.add(key)
        row = dict(case)
        row["case_id"] = f"authz-{len(normalized)+1:04d}"
        row["status"] = "planned_not_executed"
        row["network_requests"] = 0
        normalized.append(row)
    try:
        with args.output.open("w", encoding="utf-8") as stream:
            for row in normalized:
                stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        print(f"cannot write output: {exc}", file=sys.stderr); return 2
    print(json.dumps({"input_cases": len(cases), "planned_cases": len(normalized), "invalid_or_duplicate": len(errors), "network_requests": 0, "output": str(args.output)}, ensure_ascii=False))
    for error in errors:
        print(json.dumps(error, ensure_ascii=False), file=sys.stderr)
    return 1 if errors else 0

if __name__ == "__main__":
    raise SystemExit(main())

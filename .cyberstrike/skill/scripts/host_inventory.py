#!/usr/bin/env python3
"""Normalize hostname observations from JSONL while preserving every source record.

Input: one JSON object per line. Required field: hostname or host.
Optional fields such as source, observed_at, dns_records, ttl, wildcard_control,
tool, and confidence are retained unchanged in each observation.
No network requests are performed.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import Any
try:
    import idna
except ImportError:
    idna = None

def normalize(value: Any) -> str:
    raw = str(value or "").strip().rstrip(".").lower()
    if not raw or any(ch in raw for ch in "/?#@"):
        raise ValueError("expected a hostname, not a URL/path")
    if raw.startswith("*."):
        raw = raw[2:]
    if ":" in raw and not raw.startswith("["):
        # IPv6 literals are not hostnames for this inventory.
        raise ValueError("IP literals are not accepted as hostnames")
    if idna:
        raw = idna.encode(raw, uts46=True).decode("ascii")
    labels = raw.split(".")
    if len(raw) > 253 or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS hostname length")
    if any(not all(c.isalnum() or c == "-" for c in label) or label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("invalid hostname label")
    return raw

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSONL observations; use - for stdin")
    parser.add_argument("-o", "--output", type=Path, help="write JSONL inventory; defaults to stdout")
    parser.add_argument("--errors", type=Path, help="optional JSONL file for invalid records")
    args = parser.parse_args()
    if args.input == Path("-"):
        lines = sys.stdin
    else:
        try:
            lines = args.input.open(encoding="utf-8")
        except OSError as exc:
            print(f"cannot open input: {exc}", file=sys.stderr); return 2
    inventory: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    try:
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("each JSONL line must be an object")
                original = record.get("hostname", record.get("host"))
                hostname = normalize(original)
                entry = inventory.setdefault(hostname, {"hostname": hostname, "observations": []})
                observation = dict(record)
                observation["input_hostname"] = original
                observation["hostname"] = hostname
                entry["observations"].append(observation)
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                errors.append({"line": number, "error": str(exc), "raw": line.rstrip("\\n")})
    finally:
        if args.input != Path("-"):
            lines.close()
    output = args.output.open("w", encoding="utf-8") if args.output else sys.stdout
    try:
        for hostname in sorted(inventory):
            entry = inventory[hostname]
            entry["observation_count"] = len(entry["observations"])
            output.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\\n")
    finally:
        if args.output:
            output.close()
    if args.errors:
        with args.errors.open("w", encoding="utf-8") as stream:
            for error in errors:
                stream.write(json.dumps(error, ensure_ascii=False) + "\\n")
    print(json.dumps({"unique_hostnames": len(inventory), "observations": sum(len(v["observations"]) for v in inventory.values()), "invalid_records": len(errors), "network_requests": 0}, ensure_ascii=False), file=sys.stderr)
    return 1 if errors else 0

if __name__ == "__main__":
    raise SystemExit(main())

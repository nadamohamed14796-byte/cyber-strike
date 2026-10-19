#!/usr/bin/env python3
"""Structural quality checks for CyberStrike skills. Uses Python standard library only.

Run from the repository root:
  python3 .cyberstrike/skill/scripts/validate_skill_catalog.py
  python3 .cyberstrike/skill/scripts/validate_skill_catalog.py --json
  python3 .cyberstrike/skill/scripts/validate_skill_catalog.py --self-test

This does not prove that a skill is safe or that its testing claims are correct.
It flags structural and routing problems for an additional human/content review.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path(".cyberstrike/skill")
HYPOTHESIS_CAP = re.compile(
    r"maximum\s+\d+\s+distinct hypotheses|"
    r"\bup to\s+\d+\s+(?:distinct\s+)?hypotheses\b|"
    r"\b\d+\s*[- ]attempt\s+budget\b|"
    r"(?:validation|attempt|hypothesis)\s+(?:budget|limit).{0,80}\bat most\s+\d+\b",
    re.IGNORECASE,
)


def frontmatter(text: str) -> str | None:
    if not text.startswith("---\n"):
        return None
    match = re.search(r"\n---\s*(?:\n|$)", text[4:])
    if not match:
        return None
    return text[4 : 4 + match.start()]


def scalar(meta: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}:\s*(.*?)\s*$", meta, re.MULTILINE)
    if not match:
        return None
    value = match.group(1).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value or None


def yaml_list(meta: str, key: str) -> list[str]:
    lines = meta.splitlines()
    for index, line in enumerate(lines):
        match = re.match(rf"^{re.escape(key)}:\s*(.*?)\s*$", line)
        if not match:
            continue
        value = match.group(1).strip()
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            if not inner:
                return []
            return [
                item.strip().strip("'\"")
                for item in inner.split(",")
                if item.strip()
            ]
        if value:
            return [value.strip("'\"")]
        result: list[str] = []
        for continuation in lines[index + 1 :]:
            if continuation.strip() and not continuation.lstrip().startswith("-"):
                break
            item = re.match(r"^\s+-\s+(.+?)\s*$", continuation)
            if item:
                result.append(item.group(1).strip().strip("'\""))
        return result
    return []


def self_test() -> int:
    sample = """---
name: sample-skill
description: \"sample description\"
chains_with: [first, 'second']
prerequisites:
  - first
  - second
---
# Sample
"""
    meta = frontmatter(sample)
    assert meta is not None
    assert scalar(meta, "name") == "sample-skill"
    assert yaml_list(meta, "chains_with") == ["first", "second"]
    assert yaml_list(meta, "prerequisites") == ["first", "second"]
    print("self-test: PASS")
    return 0


def scan(root: Path, strict_links: bool = False) -> dict[str, Any]:
    if not root.exists() or not root.is_dir():
        return {"errors": [f"skill root does not exist: {root}"], "warnings": [], "summary": {}}

    all_files = sorted(root.rglob("SKILL.md"))
    direct_skills = sorted(
        (path for path in root.iterdir() if path.is_dir() and (path / "SKILL.md").is_file()),
        key=lambda path: path.name,
    )
    errors: list[str] = []
    warnings: list[str] = []
    all_names: dict[str, list[str]] = defaultdict(list)

    # Build a best-effort name index across all local reference modules.
    for path in all_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        meta = frontmatter(text)
        if meta is None:
            continue
        name = scalar(meta, "name")
        if name:
            all_names[name].append(path.relative_to(root).as_posix())

    duplicate_names = {
        name: paths for name, paths in all_names.items() if len(paths) > 1
    }
    direct_names = {path.name for path in direct_skills}
    custom_count = 0

    for directory in direct_skills:
        path = directory / "SKILL.md"
        text = path.read_text(encoding="utf-8", errors="replace")
        meta = frontmatter(text)
        custom_count += 1
        label = path.relative_to(root).as_posix()
        if meta is None:
            errors.append(f"{label}: missing or malformed YAML frontmatter")
            continue

        name = scalar(meta, "name")
        description = scalar(meta, "description")
        if not name:
            errors.append(f"{label}: required name field is missing")
        elif name != directory.name:
            errors.append(
                f"{label}: name '{name}' does not match directory '{directory.name}'"
            )
        if not description:
            errors.append(f"{label}: required description field is missing")

        if HYPOTHESIS_CAP.search(text):
            errors.append(f"{label}: arbitrary fixed hypothesis ceiling found")

        for field in ("chains_with", "prerequisites"):
            for target in yaml_list(meta, field):
                if target not in all_names:
                    message = f"{label}: {field} target '{target}' did not resolve to a local skill name"
                    (errors if strict_links else warnings).append(message)

        if len(all_names.get(name or "", [])) > 1:
            paths = ", ".join(all_names[name or ""])
            message = f"{label}: duplicate skill name '{name}' also appears at {paths}"
            (errors if strict_links else warnings).append(message)

        if not re.search(r"^##\s+.+", text, re.MULTILINE):
            warnings.append(f"{label}: no markdown level-2 section headings")

    summary = {
        "skill_root": root.as_posix(),
        "all_skill_markdown_files": len(all_files),
        "direct_skill_directories": custom_count,
        "unique_names_with_frontmatter": len(all_names),
        "duplicate_names": duplicate_names,
        "errors": len(errors),
        "warnings": len(warnings),
        "strict_links": strict_links,
    }
    return {"errors": errors, "warnings": warnings, "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="skill root")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--strict-links", action="store_true", help="treat unresolved chain/prerequisite names and duplicate names as errors")
    parser.add_argument("--self-test", action="store_true", help="test the local frontmatter/list parser")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    result = scan(args.root, strict_links=args.strict_links)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result["summary"], indent=2, ensure_ascii=False))
        for item in result["errors"]:
            print(f"ERROR: {item}")
        for item in result["warnings"]:
            print(f"WARNING: {item}")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())

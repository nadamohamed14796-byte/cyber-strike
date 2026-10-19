#!/usr/bin/env python3
"""Conservative Markdown formatter for CyberStrike SKILL.md files.

Default mode reports files that would change. Pass --write to normalize only
safe presentation details: UTF-8/BOM, LF line endings, trailing whitespace,
heading blank lines, fenced-code closing blank lines, and final newline.
It deliberately does not reorder sections, rewrite prose, alter YAML frontmatter,
or touch code-block contents beyond line endings.
Run from repository root:
  python3 .cyberstrike/skill/scripts/format_skill_markdown.py --check
  python3 .cyberstrike/skill/scripts/format_skill_markdown.py --write
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

ROOT = Path(".cyberstrike/skill")
EXCLUDED = {
    "CIS_benchmarks", "NIST", "WEB", "mitre_attack",
    "mitre_attack_ics", "mitre_attack_mobile", "mitre_attack_test",
    "scripts",
}


def format_markdown(raw: str) -> str:
    text = raw.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    out: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    for line in lines:
        candidate = line.rstrip()
        fence = re.match(r"^\\s{0,3}(`{3,}|~{3,})", candidate)
        closing_fence = False
        if fence:
            token = fence.group(1)
            if not in_fence:
                in_fence = True
                fence_char = token[0]
                fence_len = len(token)
            elif token[0] == fence_char and len(token) >= fence_len:
                in_fence = False
                closing_fence = True
        # Preserve code-block payload exactly; normalize whitespace only outside it.
        stripped = line if in_fence and not closing_fence else candidate
        if re.match(r"^#{1,6}\s+\S", stripped):
            while out and out[-1] == "":
                out.pop()
            if out:
                out.append("")
        out.append(stripped)
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out) + "\n"


def candidates() -> list[Path]:
    if not ROOT.is_dir():
        return []
    found = []
    for path in ROOT.rglob("SKILL.md"):
        if any(part in EXCLUDED for part in path.relative_to(ROOT).parts):
            continue
        found.append(path)
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="write normalized Markdown")
    mode.add_argument("--check", action="store_true", help="exit nonzero if changes are needed")
    parser.add_argument("--path", type=Path, help="format/check one SKILL.md")
    args = parser.parse_args()
    paths = [args.path] if args.path else candidates()
    if not paths:
        print(f"ERROR: no SKILL.md files found under {ROOT}", file=sys.stderr)
        return 2
    changed = []
    errors = []
    for path in paths:
        try:
            before = path.read_text(encoding="utf-8")
            after = format_markdown(before)
            if before != after:
                changed.append(path)
                if args.write:
                    path.write_text(after, encoding="utf-8", newline="\n")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path}: {exc}")
    for path in changed:
        print(f"{'FORMATTED' if args.write else 'WOULD_FORMAT'} {path}")
    for error in errors:
        print(f"ERROR {error}", file=sys.stderr)
    print(f"summary: scanned={len(paths)} changed={len(changed)} errors={len(errors)} write={args.write}")
    if errors:
        return 2
    return 1 if args.check and changed else 0


if __name__ == "__main__":
    raise SystemExit(main())

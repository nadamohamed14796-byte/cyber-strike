#!/usr/bin/env python3
"""Audit practical tooling/resource/script coverage for direct CyberStrike skills."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

DEFAULT_ROOT = Path(".cyberstrike/skill")
TOOL_HEADINGS = re.compile(r"^#{1,4}\s+.*\b(tools?|tooling|toolchain|commands?|dependencies)\b", re.I | re.M)
RESOURCE_HEADINGS = re.compile(r"^#{1,4}\s+.*\b(resources?|references?|further reading|documentation|sources)\b", re.I | re.M)
SCRIPT_HEADINGS = re.compile(r"^#{1,4}\s+.*\b(scripts?|helpers?|snippets?|quick checks?|examples?|commands?)\b", re.I | re.M)
CODE_FENCE = re.compile(r"^\x60{3}(?:[a-zA-Z0-9_+.-]+)?\s*$", re.M)
HELPER_PATH = re.compile(r"\.cyberstrike/skill/scripts/[A-Za-z0-9_.-]+")
EXCLUDED = {"CIS_benchmarks", "NIST", "WEB", "mitre_attack", "mitre_attack_ics", "mitre_attack_mobile", "mitre_attack_test", "scripts"}

def inspect_skill(path: Path, root: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    tools = bool(TOOL_HEADINGS.search(text))
    resources = bool(RESOURCE_HEADINGS.search(text)) or bool(re.search(r"https?://", text))
    fences = len(CODE_FENCE.findall(text))
    helpers = sorted(set(HELPER_PATH.findall(text)))
    scripts = bool(SCRIPT_HEADINGS.search(text)) or fences >= 2 or bool(helpers)
    missing = [k for k, ok in (("tools", tools), ("resources", resources), ("scripts_or_snippets", scripts)) if not ok]
    return {"skill": path.parent.name, "path": path.relative_to(root).as_posix(),
            "tools_section": tools, "resource_evidence": resources, "script_or_snippet_evidence": scripts,
            "code_fence_count": fences, "reusable_helpers": helpers, "missing": missing}

def scan(root: Path) -> dict:
    if not root.is_dir():
        return {"error": f"skill root does not exist: {root}", "summary": {}, "skills": []}
    paths = sorted((d / "SKILL.md" for d in root.iterdir()
                    if d.is_dir() and d.name not in EXCLUDED and (d / "SKILL.md").is_file()),
                   key=lambda p: p.parent.name)
    skills = [inspect_skill(p, root) for p in paths]
    summary = {"root": root.as_posix(), "direct_custom_skills": len(skills),
               "with_tools_section": sum(s["tools_section"] for s in skills),
               "with_resource_evidence": sum(s["resource_evidence"] for s in skills),
               "with_script_or_snippet_evidence": sum(s["script_or_snippet_evidence"] for s in skills),
               "missing_any": sum(bool(s["missing"]) for s in skills),
               "missing_by_dimension": {k: sum(k in s["missing"] for s in skills)
                                        for k in ("tools", "resources", "scripts_or_snippets")}}
    return {"summary": summary, "skills": skills}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    result = scan(args.root)
    if "error" in result:
        print(result["error"], file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
        for skill in result["skills"]:
            if skill["missing"]:
                print(f"MISSING {skill['path']}: {', '.join(skill['missing'])}")
    return 1 if args.strict and result["summary"]["missing_any"] else 0

if __name__ == "__main__":
    raise SystemExit(main())

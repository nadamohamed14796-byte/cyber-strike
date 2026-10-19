#!/usr/bin/env python3
"""Audit direct CyberStrike skills for agent-executable CLI tooling guidance."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path

DEFAULT_ROOT=Path(".cyberstrike/skill")
EXCLUDED={"CIS_benchmarks","NIST","WEB","mitre_attack","mitre_attack_ics","mitre_attack_mobile","mitre_attack_test","scripts"}
TOOL_MARKERS=("## Agent-executable CLI tooling, resources, and helper scripts","## Agent-executable CLI tooling (2026-10-19)","## Tool installation and optional tooling (2026-10-19)","## Practical tooling, references, and helper scripts (2026-10-19)")
UI_FIRST=re.compile(r"\b(Burp(?:\s+Suite|\s+(?:Proxy|Repeater|Comparer))?|browser DevTools|Chrome DevTools|DOM Invader|Turbo Intruder|BApp Store)\b",re.I)
URL=re.compile(r"https?://[^\s)]+")
CLI=re.compile(r"`(?:[a-zA-Z0-9_.-]+\s+[^`]+|python3\s+[^`]+)`")
INSTALL=re.compile(r"\b(install|download|go install|pipx|apt install|brew install|winget install|official releases)\b",re.I)

def inspect(path:Path,root:Path)->dict:
    content=path.read_text(encoding="utf-8",errors="replace")
    start=min([content.find(m) for m in TOOL_MARKERS if content.find(m)>=0],default=-1)
    if start >= 0:
        # Audit only the tooling section itself, not unrelated methodology later in the file.
        next_heading = re.search(r"^##\s+", content[start + 2 :], re.MULTILINE)
        section_end = start + 2 + next_heading.start() if next_heading else len(content)
        section = content[start:section_end]
    else:
        section = ""
    tool_heading=bool(re.search(r"^#{1,4}\s+.*\b(tools?|tooling|dependencies|cli)\b",content,re.I|re.M))
    marker_count=sum(content.count(marker) for marker in TOOL_MARKERS)
    has_ref=bool(URL.search(section)) or bool(re.search(r"^#{1,4}\s+.*\b(references?|resources?)\b",section,re.I|re.M))
    has_cli=bool(CLI.search(section)) or bool(re.search(r"\b(subfinder|dnsx|httpx|katana|ffuf|nuclei|sqlmap|gitleaks|trivy|jq|python3)\b",section))
    has_install=bool(INSTALL.search(section))
    ui=sorted(set(UI_FIRST.findall(section)))
    missing=[]
    if start<0: missing.append("agent_tooling_section")
    if marker_count > 1: missing.append("duplicate_tooling_sections")
    if not tool_heading: missing.append("tooling_section")
    if not has_ref: missing.append("official_resources")
    if not has_cli: missing.append("agent_executable_command")
    if not has_install: missing.append("installation_or_verification")
    if ui: missing.append("remove_human_UI_as_agent_dependency")
    return {"skill":path.parent.name,"path":path.relative_to(root).as_posix(),"tooling_section":tool_heading,
            "official_resources":has_ref,"agent_executable_command":has_cli,"installation_or_verification":has_install,
            "human_UI_mentions_in_tooling_section":ui,"tooling_section_count":marker_count,"missing":missing}

def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root",type=Path,default=DEFAULT_ROOT)
    ap.add_argument("--json",action="store_true")
    ap.add_argument("--strict",action="store_true")
    args=ap.parse_args()
    if not args.root.is_dir():
        print(f"skill root not found: {args.root}",file=sys.stderr);return 2
    paths=sorted((d/"SKILL.md" for d in args.root.iterdir() if d.is_dir() and d.name not in EXCLUDED and (d/"SKILL.md").is_file()),key=lambda p:p.parent.name)
    skills=[inspect(p,args.root) for p in paths]
    summary={"direct_custom_skills":len(skills),"with_tooling_section":sum(s["tooling_section"] for s in skills),
             "with_official_resources":sum(s["official_resources"] for s in skills),"with_agent_commands":sum(s["agent_executable_command"] for s in skills),
             "with_install_or_verify_guidance":sum(s["installation_or_verification"] for s in skills),
             "sections_with_human_UI_tool_mentions":sum(bool(s["human_UI_mentions_in_tooling_section"]) for s in skills),
             "skills_with_duplicate_tooling_sections":sum(s["tooling_section_count"] > 1 for s in skills),
             "missing_any":sum(bool(s["missing"]) for s in skills)}
    result={"summary":summary,"skills":skills}
    if args.json: print(json.dumps(result,ensure_ascii=False,indent=2))
    else:
        print(json.dumps(summary,ensure_ascii=False,indent=2))
        for s in skills:
            if s["missing"]: print(f"MISSING {s['path']}: {', '.join(s['missing'])}")
    return 1 if args.strict and summary["missing_any"] else 0

if __name__=="__main__": raise SystemExit(main())

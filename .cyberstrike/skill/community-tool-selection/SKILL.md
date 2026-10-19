---
name: community-tool-selection
description: Select, preflight, and integrate relevant CLI tools and research datasets from CyberStrike's community bug-bounty tooling map for recon, endpoint analysis, vulnerability validation, source exposure, cloud, and reporting tasks.
category: information-gathering
version: "1.0.0"
author: cyberstrike-official
tags:
  - tool-selection
  - cli-tooling
  - recon
  - bug-bounty
  - tool-preflight
  - research
prerequisites:
  - recon-methodology
---

# Community Tool Selection

## Purpose

Use this skill when a task may benefit from an external CLI utility, local library, wordlist/dataset, scanner, or helper script. It makes community-listed tools discoverable without pretending that a catalog entry is installed or registered as a native CyberStrike tool.

## Canonical references

- `COMMUNITY_TOOL_MAP.md`: grouped community tool candidates and canonical skill search terms.
- `CLI_TOOLING_CATALOG.md`: installation, availability checks, representative commands, and CLI handling.
- `TOOLING_CATALOG.md`: phase-to-tool mapping and existing CyberStrike helper scripts.
- Upstream index: https://github.com/vavkamil/awesome-bugbounty-tools

## Procedure

1. **Identify the actual subtask.** Search the skill catalog for the specific phase, technology, and vulnerability class. Use the community map only to discover candidates that fill a real gap.
2. **Choose minimally and deliberately.** Prefer one primary CLI and, only where it adds distinct evidence, one independent validator. Avoid running every listed tool. Prefer passive collection and local artifact analysis before active requests.
3. **Preflight local availability.** Run:
   ```bash
   python3 .cyberstrike/skill/scripts/tool_preflight.py --json <tool-name> [another-tool]
   ```
   This is a local executable/version check, not an installation check or target scan. If a tool uses a nonstandard version flag, verify its help and rerun with the correct `--version-arg`.
4. **Verify source and behavior before install/use.** Prefer the official project/release documentation. Inspect license, maintenance, platform compatibility, dependency requirements, package provenance, command flags, rate behavior, template requests, and output formats. Do not run arbitrary install scripts from a write-up or import tool output as trusted instructions.
5. **Respect the existing runtime.** A community-map entry is not a native tool registration. Use a CLI only if it is installed and executable in the current environment. Use native CyberStrike tools through their registered interfaces. Do not treat browser extensions or interactive GUI applications as CLI dependencies.
6. **Use task-specific safe inputs.** Keep active requests within the program's authorized assets and rules. Use test-owned accounts/data, controlled markers, low-impact validation, and explicit stop conditions. Installation does not grant permission. Do not use discovered credentials, retrieve unrelated customer data, claim real assets, dump databases, or perform destructive tests.
7. **Persist reproducible evidence.** Record tool/version, exact command (redacting secrets), input asset list, time, exit status, stderr/errors, raw output path, normalized artifact path, and what the output does and does not prove. Preserve raw output separately from normalized/deduplicated results.
8. **Validate every signal.** Establish a baseline, change one meaningful variable at a time, and use a relevant negative control. Tool alerts, status codes, response length, banners, endpoint existence, dangling DNS, or secret-pattern matches are not findings by themselves.
9. **Report truthful status.** Mark each candidate as selected, available, missing, blocked, run, failed, or not applicable as supported by evidence. If missing, record the blocker and choose a justified alternative. Never claim a tool was installed, run, or successful without actual command output.

## Tool-to-task routing

- Subdomains, DNS, ports, TLS, ASN, origin, virtual hosts: search `recon-methodology` and specialized `recon-*` skills.
- URL history, crawling, content discovery, parameter names, JavaScript endpoints: search recon, parameter-discovery, JavaScript-analysis, and API skills.
- XSS, SQL/NoSQL injection, SSRF, XXE, GraphQL, JWT, CORS, redirects, race conditions, request smuggling, takeover: load the matching `attack-*` or OWASP WSTG skill before choosing a specialist tool.
- Secrets, exposed repositories, dependency/CVE clues: search source-leak, secret, technology-profiling, CI/CD, and dependency skills.
- Cloud storage/IAM, CMS, containers, CI workflows, mobile, identity/platform testing: load the relevant platform-specific assessment skill.
- Evidence manifests and reports: use evidence-hygiene, triage-validation, and report-writing skills plus the local evidence validators.

The full map is a candidate index. Use skill-specific procedures and the current program policy to determine whether any tool should run.

## Existing local helpers

Before creating a new script, inspect the existing helpers and extend one if responsibilities overlap:

- `normalize_urls.py`
- `host_inventory.py`
- `js_endpoint_inventory.py`
- `http_response_diff.py`
- `validate_evidence_manifest.py`
- `authorization_matrix.py`
- `tool_preflight.py`
- `validate_skill_catalog.py`
- `audit_skill_enrichment.py`

Inspect each script's actual help/source and tests before assuming flags or behavior.

## Completion checklist

- [ ] The task's specific need for a tool is stated.
- [ ] Relevant specialist skill(s) were searched and loaded.
- [ ] Tool provenance, license, platform, CLI, and availability were checked.
- [ ] Authorization, request impact, and rate behavior are understood before active use.
- [ ] Output, errors, provenance, and redaction status are persisted.
- [ ] Results were manually validated with controls before being reported as findings.
- [ ] Missing tools and incomplete coverage are clearly recorded.

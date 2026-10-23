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

## Canonical reference

- `TOOLING_CATALOG.md`: the single source of truth for phase routing, tool candidates, official links, preflight/install guidance, and reusable helpers. Do not maintain separate tool/source inventories.

## Procedure

1. **Identify the actual subtask.** Search the skill catalog for the specific phase, technology, and vulnerability class. Use the community map only to discover candidates that fill a real gap.
2. **Choose adaptively, not by a fixed count.** Start with a strong primary method and add as many independent complementary methods as needed when they provide distinct coverage, corroborate evidence, or recover a failed/missing source. There is no arbitrary tool-count ceiling, and useful scripts/code are valid methods. Do not run every listed tool indiscriminately or repeat equivalent work merely to increase counts.
3. **Preflight local availability once per runtime/version.** Before first use of a relevant CLI candidate, run:
   ```bash
   python3 .cyberstrike/skill/scripts/tool_preflight.py --json <tool-name> [another-tool]
   ```
   This is a local executable/version check, not an installation check or target scan. Retain successful preflight evidence for the same runtime/version and do not repeat identical checks every phase. Recheck only when the runtime/binary changes or the previous check failed. If a tool uses a nonstandard version flag, verify its help and rerun with the correct `--version-arg`.
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

The catalog is a candidate index. Use skill-specific procedures and current program policy to determine whether any tool should run.

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
- [ ] Relevant specialist skill(s) were loaded when they became useful and their returned content was actually available to the agent.
- [ ] Each selected external tool's provenance, license, platform, CLI, and availability were checked once before use, with evidence reused for unchanged binaries.
- [ ] Authorization, request impact, and rate behavior are understood before active use.
- [ ] Output, errors, provenance, and redaction status are persisted.
- [ ] Results were manually validated with controls before being reported as findings.
- [ ] Missing tools and incomplete coverage are clearly recorded.

## Agent-executable CLI tooling, resources, and helper scripts

Use command-line utilities and local Python helpers; interactive browsers and GUI proxy applications are not prerequisites for this skill.

### Preflight and provenance
- Check whether a command exists before relying on it: `command -v <tool>` on Linux/macOS or `Get-Command <tool> -ErrorAction SilentlyContinue` in PowerShell.
- Verify a chosen tool's version and syntax using its documented flag, for example `jq --version`, `rg --version`, `python3 --version`, or `tool --help`. For multiple executable names, use `python3 .cyberstrike/skill/scripts/tool_preflight.py --json <tool-name> [another-tool]`.
- Prefer first-party installation and release instructions. Verify license, platform support, package provenance, maintenance status, required privileges, default network behavior, and whether the chosen tool can send active traffic before installing or running it.
- Keep installs explicit and reproducible. Record the package/release version and installation source; do not run one-line remote shell installers or copy commands from untrusted write-ups without review.

### Local helper scripts
- `python3 .cyberstrike/skill/scripts/tool_preflight.py --json <tool-name>`: checks PATH availability and version output; it does not install tools or contact targets.
- `python3 .cyberstrike/skill/scripts/validate_skill_catalog.py --self-test`: checks the catalog validator's parser fixtures.
- `python3 .cyberstrike/skill/scripts/audit_skill_enrichment.py --json`: audits CLI-tooling guidance in direct community skills.
- `python3 .cyberstrike/skill/scripts/normalize_urls.py --help`, `host_inventory.py --help`, or `js_endpoint_inventory.py --help`: inspect exact supported inputs before use; do not assume options not shown by their help/source.

### Official references
- Python command-line and standard library docs: https://docs.python.org/3/
- ripgrep documentation and releases: https://github.com/BurntSushi/ripgrep
- jq manual and releases: https://jqlang.org/
- Project-maintained CLI tool candidates: https://github.com/vavkamil/awesome-bugbounty-tools

Only use a command that is actually available and verified in the current runtime. If an appropriate tool is missing, record that limitation and choose a justified alternative. Tool selection never authorizes active probing: target scope, program policy, impact, rate, and evidence requirements remain controlling.


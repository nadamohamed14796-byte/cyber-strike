---
name: attack-finding-correlation
description: "Correlate recon assets, endpoint observations, vulnerability candidates, evidence, and skill handoffs into one deduplicated, provenance-preserving graph."
category: "triage"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [correlation, aggregation, deduplication, evidence-graph, chaining, triage]
prerequisites:
  - "A saved target workspace and its authoritative scope manifest"
  - "At least one persisted observation, candidate, endpoint, asset, or finding"
chains_with:
  - attack-web-recon
  - attack-javascript-analysis
  - attack-variant-analysis
  - attack-triage-validation
  - attack-bb-methodology
  - attack-report-writing
---

# Evidence Correlation, Finding Aggregation, and Skill Chaining

## Goal

Build one coherent, incremental view from all available target evidence. Connect assets → pages/scripts → endpoints/parameters → observations → hypotheses → validation results → findings → reports. Keep raw evidence and provenance available while presenting one canonical record per meaningful identity. Recommend the next specialist skill from observed signals, not keyword similarity.

This skill organizes and prioritizes evidence; it does not itself prove a vulnerability, expand scope, or authorize active testing.

## 1. Load and normalize inputs

Read the existing workspace manifest, scope decision, asset/host inventory, URL and endpoint inventories, JavaScript manifest, captured request/response references, scan outputs, hypothesis/triage ledger, validation evidence, and prior findings. Reuse existing canonical artifacts; do not create a parallel inventory when a current source-of-truth artifact already exists.

For every imported record retain:
- stable source record ID and source/tool name/version;
- observation time and run ID;
- asset, origin, route template, HTTP method, parameter location/name, content hash, identity/role/tenant context when known;
- evidence path or request/response ID, redaction state, and source lineage;
- status (observed, inferred, candidate, confirmed, refuted, inconclusive, blocked, not_run);
- confidence plus the reason for it.

Normalize host case, default ports, URL fragments, path templates, parameter names/locations, and equivalent representations only where semantics are preserved. Never erase method, origin, API version, auth context, tenant/object boundary, content type, or meaningful state differences merely to increase deduplication.

## 2. Canonical aggregation rules

| Record kind | Candidate identity key | Must remain separate when |
|---|---|---|
| Asset | normalized hostname + asset type | ownership, scope decision, or service boundary differs |
| Endpoint | origin + method + normalized route template + API version | method, auth boundary, tenant, content type, or operation semantics differ |
| Parameter observation | endpoint ID + parameter name + location + source context | query/body/header/path/cookie locations differ |
| JS asset | canonical final URL + content hash | bytes differ; preserve aliases and all discovery sources |
| Hypothesis | root-cause fingerprint + affected boundary + operation | tested principal/object/tenant/state or violated invariant differs |
| Finding | root-cause fingerprint + affected control + demonstrated impact boundary | remediation, security boundary, or material impact differs |
| Evidence | immutable evidence ID/hash + capture context | time, identity, request variation, or control differs |

Treat these as starting keys, not automatic merge commands. When records collide, compare semantic fields and preserve conflicting observations as linked variants. Merge source lists and parameter observations into the canonical endpoint record instead of creating duplicate endpoint rows for every parameter or discovery tool.

One underlying root cause affecting many routes should normally be one grouped finding with a route/instance list if remediation and impact are the same. Split findings only when the control, remediation, or material impact genuinely differs. Never merge merely because titles, response codes, or paths look alike.

## 3. Build an evidence graph

Represent records as nodes and only evidence-supported relationships as edges:
- discovered_from: script, page, source map, passive source, or tool output led to an asset/route;
- observed_in: route/parameter appears in a specific request, response, or source location;
- supports / contradicts: evidence bears on a hypothesis;
- same_root_cause_candidate: records may share a root cause but need comparison;
- validated_as / refuted_by: controlled validation result changes a hypothesis state;
- triggers_skill: an observed signal meets a specialist skill's entry condition;
- instance_of: a confirmed sibling shares the same demonstrated root cause;
- reported_in: canonical finding is represented in a report.

Every edge must have provenance and a rationale. Label inferred relationships as candidate; do not promote them to confirmed because two records share a word, endpoint, tool alert, framework, or time window. Preserve contradictory evidence rather than overwriting it.

## 4. Evidence-driven chaining algorithm

For each unresolved, decision-relevant observation:

1. Identify the exact signal and evidence reference. Separate direct observation from interpretation.
2. Match that signal to specialist skills' declared chains_with, prerequisites, descriptions, and explicit trigger tables. Treat metadata as candidate routing hints, not proof that a skill applies.
3. Check prerequisites: current scope authorization, asset identity, test permission, required test-owned account/fixture, and the evidence needed to isolate the relevant security boundary.
4. Score candidate handoffs qualitatively by signal strength, prerequisite readiness, likely impact, novelty versus work already done, and cost/risk. Explain why the next skill is useful; do not use a hidden arbitrary cap on meaningful hypotheses.
5. Choose the smallest safe test or source review that can distinguish the leading explanations. Freeze other variables, keep baseline and negative control, and prefer read-only/reversible fixtures.
6. Run the specialist skill only if its trigger is present and authorization permits it. If a prerequisite is absent, record blocked with the missing item and resume condition; do not label it false positive.
7. Feed its evidence/result back into the same graph and canonical ledger. Recompute the next handoff only when new evidence changes the state.
8. Stop a branch when confirmed/refuted, no distinct decision-relevant test remains, a required prerequisite is unavailable, program limits bind, or safety requires stopping.

Do not execute every skill in a metadata chain automatically. Cycles are allowed as relationships but must not cause repeated execution: store skill + hypothesis + evidence-version as the handoff key, and reopen only when new evidence or changed prerequisites justify it.

## 5. Evidence and verdict discipline

Use independent states:
- Observed: directly captured, source-linked fact.
- Candidate: plausible interpretation needing validation.
- Confirmed: required preconditions and security-control failure demonstrated with reproducible evidence and relevant controls.
- Refuted: a relevant test/control disproves this specific hypothesis.
- Inconclusive: evidence is ambiguous or noisy.
- Blocked: permission, credentials, fixture, tool, or other prerequisite is missing.
- Not run: deliberately deferred, including recon-only runs.

HTTP 200, a scanner alert, a version banner, a secret-like string, a missing frontend control, or an endpoint existing is not sufficient confirmation. A chain is confirmed only when each necessary link has its own evidence. A hypothetical downstream step must not inflate the severity of a confirmed precursor. Severity and confidence belong to the demonstrated impact, not the number of correlated records or links.

Persist rejected hypotheses with root-cause fingerprint, tested boundary, baseline/control, evidence references, reason, confidence, timestamp, and reopen condition. A new operation, role, tenant, version, field, state, or contradictory signal may justify reopening.

## 6. Incremental update and resumability

On each new run:
- ingest only new or changed observations, using stable IDs and content hashes;
- merge new provenance into existing canonical records;
- compare new evidence against prior candidates, confirmed findings, and rejected-lead memory;
- avoid repeating unchanged collection or validation;
- resume blocked and inconclusive items only when their stated prerequisite or evidence changes;
- retain partial results when a tool/source fails;
- verify all referenced artifact paths before reporting.

Do not create one output file per tool or skill. Update the existing canonical target-local inventories and ledger. Keep raw captures only where they add reproducibility or unique evidence; otherwise link to them.

## 7. Required output

Update the existing canonical report/ledger with:
- canonical assets and endpoints plus merged source/parameter/auth observations;
- unique root-cause groups and their affected instances;
- each hypothesis's status, confidence, tested boundary, controls, and evidence links;
- confirmed findings separated from candidates and untested chain links;
- duplicate groups merged and the reason for each merge/split;
- next skill, observed trigger, prerequisites, and smallest safe next step;
- blocked/inconclusive/not-run counts and exact reasons;
- source/tool coverage, failures, missing artifacts, redaction, and cleanup status;
- an explicit resume point.

Before finalizing, verify counts against the saved ledgers, check links and scope references, and ensure no secret values or unrelated personal data leaked into summaries. If no canonical artifact exists, add the smallest target-local artifact needed rather than a new nested workspace.

## Safety boundary

Apply persisted request-level scope checks to every active request and redirect. Recon evidence never authorizes a new target or a higher-impact test. Do not use discovered credentials, access real users' data, perform destructive/business-impacting actions, or execute untrusted scripts. Use approved test identities, synthetic markers, reversible fixtures, and minimum sufficient proof.


## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and existing local helpers the agent can invoke directly. Browser UI, browser extensions, and interactive proxy GUIs are not required dependencies. Check availability/version with the shared tool preflight helper or direct local checks before depending on an executable; do not install automatically.

### Recommended tools
- Python 3 standard library — deterministic normalization, JSON/JSONL parsing, stable fingerprints, and graph integrity checks
- jq — inspect and merge JSON/JSONL ledgers when the local schema is known
- ripgrep (rg) — locate canonical manifests, evidence IDs, and repeated root-cause patterns
- Git — compare saved runs and confirm the precise changed artifacts

### Agent-executable commands

Run from the repository root or the explicitly identified target workspace; never guess the workspace path.

```bash
command -v python3 && python3 --version
command -v jq && jq --version
command -v rg && rg --version
```

For an existing JSONL ledger, validate parseability without rewriting source evidence:

```bash
python3 - <<'PY'
import json
from pathlib import Path
path = Path("findings.jsonl")  # Replace with the verified existing ledger path.
for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    if line.strip():
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON on line {number}: {exc}")
print("JSONL parse check passed")
PY
```

Use the repository's existing manifest/ledger format and helpers if available. Do not create a second ledger merely to run this example; adapt the path only after verifying the actual canonical artifact.

### Installation and verification
- Prefer tools already installed and existing repository helpers.
- If a tool is missing, record the capability gap and use a suitable available alternative; do not install dependencies automatically.
- Review official documentation and supported output formats before adding a dependency.
- Record tool version, input artifact, exit status, and output path when a check changes triage or reporting decisions.

### Official resources
- Python JSON documentation: https://docs.python.org/3/library/json.html
- jq manual: https://jqlang.org/manual/
- ripgrep guide: https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md
- Git documentation: https://git-scm.com/docs

---
name: attack-variant-analysis
description: "Turn a verified security root cause into a deduplicated, evidence-led search for sibling defects across authorized source code and routes."
category: "source-code-review"
version: "1.0.0"
tags: [variant-analysis, source-review, codeql, semgrep, root-cause, regression]
tech_stack: [javascript, typescript, python, java, go, php, csharp]
prerequisites: ["A concrete known root cause or a well-supported code pattern", "Authorized source tree or approved code-search access"]
chains_with: [attack-bb-methodology, attack-triage-validation, attack-report-writing, attack-evidence-hygiene]
---

# Root-Cause Variant Analysis

## Goal
Use one verified defect to find structurally similar code paths that may share the same root cause. A text match is only a candidate; every sibling requires independent reachability and impact review.

## Workflow
1. **Write the root-cause statement:** identify source, transformation, sink/control, violated invariant, affected framework/version, and exact evidence. Do not start from a vague vulnerability label.
2. **Extract a reusable pattern:** list semantic features that matter (data source, missing guard, unsafe merge, route registration, object lookup, serialization boundary) separately from incidental names/formatting.
3. **Map the code family:** identify shared helpers, framework conventions, copied handlers, alternate API versions, batch paths, background jobs, and transport variants.
4. **Search broadly, triage narrowly:** use code search, AST-aware rules, CodeQL, or Semgrep where available. Search is discovery only; inspect surrounding call sites, wrappers, tests, and effective middleware.
5. **Rank candidates by evidence:** reachable input, same trust boundary, missing control, real sink, test coverage, and whether a compensating control exists. Do not rank solely by number of matches.
6. **Validate each candidate independently:** state the expected invariant, use the least-impact controlled fixture, and preserve a positive/negative control. Never assume the first finding proves every sibling vulnerable.
7. **Deduplicate and hand off:** group candidates by root cause but retain distinct impact and route evidence. Create regression tests that cover the original defect and confirmed sibling paths.

## Pattern worksheet
- Original finding/evidence reference
- Source → transformation → sink/control
- Required preconditions and attacker-controlled fields
- Framework/runtime/library version evidence
- Semantic pattern and exclusions
- Candidate file/function/route and reachability
- Existing guard/validation/compensating control
- Safe reproduction and independent controls
- Result: confirmed, disproven, inconclusive, blocked, or not run
- Regression test and remediation owner

## Search helper
For an authorized local checkout, start with narrow semantic terms and file types. Replace the example tokens with the exact source/control identified in the original finding.

```bash
rg -n --glob '*.{js,ts,tsx,py,java,go,php,cs}' 'KNOWN_SOURCE|KNOWN_SINK|MISSING_GUARD_PATTERN' .
```

Then refine to AST/data-flow rules when available. Do not treat a regex match, similar function name, or shared dependency as confirmation.

## Candidate decision matrix

| Signal | Next review | Confirmation bar |
|---|---|---|
| Same helper called by multiple routes | Trace caller-specific authorization and input shape | One sibling has a distinct verified control failure |
| Same unsafe API in multiple files | Follow data flow and wrapper semantics | Attacker-controlled input reaches the sink unsafely |
| Missing decorator/guard in source | Trace global/inherited middleware and router setup | Effective server-side policy is absent on that route |
| Similar old API version | Compare runtime policy and handler implementation | Version drift causes a specific security invariant failure |
| Test exists but does not cover boundary | Add a focused regression test | Test gap alone is not a vulnerability |
| Match exists only in dead/unreachable code | Confirm build/runtime reachability | If unreachable, document as not confirmed |

## False-positive controls
- Shared helper is safe when called with validated arguments or behind a guard.
- Framework-wide middleware or resource policy supplies the control.
- Candidate code is dead, test-only, generated, or not deployed.
- Similar code has a different trust boundary or business contract.
- One root cause creates many routes but a single canonical finding better represents the impact.

## Output and chaining
Return the root-cause pattern, candidate inventory, deduplication key, evidence per candidate, excluded matches with reason, confirmed sibling count, blocked/inconclusive count, regression tests, and next action. Route authorization defects to BOLA/BFLA/property authorization; source-to-sink injection to the matching injection skill; dependency-wide issues to supply-chain/variant review.

## References
- https://codeql.github.com/docs/
- https://semgrep.dev/docs/writing-rules/overview/
- https://github.com/trailofbits/skills/tree/main/plugins/variant-analysis
- https://owasp.org/www-project-web-security-testing-guide/


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
For authorized source/code review, use Semgrep for targeted static patterns and CodeQL when its supported build/language setup fits. For black-box testing, use Burp to compare related endpoints and identify whether a confirmed control failure has adjacent variants; do not brute-force unrelated routes.

### Installation and setup
- [Semgrep](https://semgrep.dev/docs/getting-started/) — official install and rules.
- [CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli) — official supported installation/analysis workflow.
- [Burp Suite](https://portswigger.net/burp) — manual runtime verification.
Source scanners can require a built database and are not universally applicable to every language. Run on an authorized source checkout or controlled lab; do not use variant testing as permission to broaden the target scope or request rate.

### Primary resources
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — testing context and impact.
- [Semgrep rules](https://semgrep.dev/r) — language-specific patterns.
- [CodeQL documentation](https://codeql.github.com/docs/) — query/database semantics.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt to compare sanitized variants offline.

### Result handling
Record the original confirmed primitive, what adjacent variant was tested, the control expectation, evidence, and result. Do not call sibling variants vulnerable until independently reproduced.

## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts the agent can invoke directly. Browser UI, browser extensions, and interactive intercepting proxies are not required dependencies. Check availability/version with tool_preflight.py before depending on an executable; do not install automatically.

### Recommended tools
- Semgrep — source pattern matching when source is available
- nuclei with reviewed templates for known variants
- Python/jq — normalize variant records and compare observed behavior
- http_response_diff.py — baseline/variant response comparison

### Resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/projectdiscovery/nuclei
- https://semgrep.dev/docs/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; use official documentation for current behavior and limitations.

### Helper-script contract
Track each variant by root cause, precondition, code path/endpoint, control, result, and evidence pointer. Avoid treating payload permutations as distinct hypotheses unless they test a different behavior.

Preserve original evidence separately from normalized outputs. Record tool/version, timestamps, source, confidence, errors, redaction, and stable artifact paths. Use structured output and local fixtures; never overwrite evidence silently.

### Handoff
Return actual commands and versions, evidence paths, passed/failed/inconclusive checks, false-positive reason where applicable, confidence, limitations, and next skill.

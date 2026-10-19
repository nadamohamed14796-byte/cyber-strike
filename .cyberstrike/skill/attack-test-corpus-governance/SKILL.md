---
name: attack-test-corpus-governance
description: "Evaluate provenance, licensing, safety, context, deduplication, and reproducibility of wordlists, payload samples, signatures, and test corpora used by security workflows."
category: "research-governance"
version: "1.0.0"
tags: [corpus, provenance, licensing, deduplication, test-data, safety]
tech_stack: [text, json, yaml, csv, regex, git]
prerequisites: ["An identified corpus or source repository", "Read-only review before adoption"]
chains_with: [skill-supply-chain-audit, attack-evidence-hygiene, attack-bb-methodology, attack-triage-validation]
---

# Security Test-Corpus Governance

## Goal
Make test corpora useful, traceable, and safe to reuse without blindly importing unlicensed, context-free, destructive, secret-bearing, or duplicated content. This skill governs test data; it does not execute corpus entries.

## Intake and provenance
For each corpus/file, record upstream URL, exact commit/release, retrieval time, declared license, author attribution, content hash, file size, format, intended use, and review status. If the license or provenance cannot be verified, keep it reference-only and do not redistribute it. Do not infer a repository's license from a neighboring project or a website's footer.

## Content review
1. Identify the corpus purpose: route discovery, benign validation, protocol fixtures, detection rules, or documentation examples.
2. Review sample types and context. A string useful for one parser can be destructive or misleading in another.
3. Detect duplicate/near-duplicate entries and preserve a stable canonical identifier.
4. Separate harmless fixtures from content that could cause data changes, load, outbound requests, credential attempts, persistence, or code execution.
5. Inspect for accidentally embedded credentials, personal data, internal hostnames, proprietary samples, or copied customer requests.
6. Keep a local, read-only sample for review; do not run imported scripts or send corpus entries to targets during intake.
7. Record exclusions and why they were excluded. Do not silently remove entries if their absence affects coverage claims.

## Safe classification

| Class | Examples of intended use | Handling |
|---|---|---|
| Documentation/metadata | References, schemas, version maps | Safe to index after provenance and license review |
| Benign test fixture | Synthetic IDs, harmless markers, malformed-but-small samples | Use only in matching approved test context |
| Active validation pattern | Context-dependent request shape or parser probe | Require a documented prerequisite, safe proof, and target authorization |
| High-impact/destructive | Samples intended to alter state, exhaust resources, execute code, or access private data | Do not run by default; quarantine and require explicit lab-only handling |
| Secret-bearing/private | Tokens, cookies, personal records, private captures | Exclude from shared corpus; redact and follow incident/retention policy |

## Normalization and deduplication
- Normalize line endings, encoding, whitespace, and known irrelevant case differences only when semantics are unchanged.
- Keep protocol, content type, encoding, parser context, auth state, and parameter location as part of the test identity when they affect behavior.
- Use semantic deduplication in addition to hashes: two syntactically different samples may test the same invariant, while near-identical samples may differ meaningfully by context.
- Never normalize away a security-relevant boundary such as method, tenant, origin, content type, or parser mode.
- Preserve original hash and source reference even when creating a normalized derivative.

## Reproducibility and quality
Every reusable entry should include a short purpose, required context, expected secure behavior, possible false positives, safe execution boundary, source attribution, and last-reviewed date. Avoid giant unannotated payload dumps. Prefer a small representative corpus with measurable coverage over a large opaque list.

## Validation without execution
- Parse formats with safe parsers and size limits.
- Check links and file references only when the network review is permitted; otherwise record them for later verification.
- Scan text for secret-like values without printing full matches.
- Test normalization/dedup logic on synthetic fixtures.
- Review licenses manually and preserve required notices.
- Never use a corpus entry against a live target merely because it appears in a public writeup.

## Output contract
Return corpus ID, source/commit, license status, hash, entry count, normalized/deduplicated count, excluded count by reason, secret/privacy review, context metadata, intended workflow, safe handling class, known limitations, and review date. Do not claim the corpus is complete unless the source and all files were actually inspected.

## References
- https://choosealicense.com/
- https://spdx.org/licenses/
- https://github.com/danielmiessler/SecLists
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/dkleptsov/skill-security-review


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use JSON Schema validation and deterministic tests to keep test cases reproducible, sanitized, and deduplicated. Python's standard library is sufficient for basic checks; pytest and jsonschema help when the corpus has formal fixtures and schemas.

### Installation and setup
- [pytest installation](https://docs.pytest.org/en/stable/getting-started.html) — official project docs; add it to a development/test environment rather than the global interpreter.
- [jsonschema](https://python-jsonschema.readthedocs.io/en/stable/) — official Python package documentation.
- [pre-commit](https://pre-commit.com/) — optional local validation hooks.
Use a venv and pinned test dependencies. Do not include live secrets, customer payloads, private target URLs, or unredacted reports in the corpus. Validate licenses/provenance and keep a safe synthetic replacement when examples contain sensitive content.

### Primary resources
- [JSON Schema](https://json-schema.org/) — schema specification.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — test scenario design.
- [CyberStrike Skill Guide](https://github.com/nadamohamed14796-byte/cyber-strike/blob/main/.cyberstrike/skill/SKILL_GUIDE.md) — repo conventions.

### Reusable helpers
- Run python3 .cyberstrike/skill/scripts/validate_skill_catalog.py --strict-links to check local skill structure and references.
- Run python3 .cyberstrike/skill/scripts/audit_skill_enrichment.py --json to inspect the corpus/skill tooling coverage.

### Result handling
Store source, license, capture date, sanitization decision, schema version, and change rationale. A passing schema test proves structural validity only—not safety, authenticity, coverage, or exploitability.

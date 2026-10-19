---
name: attack-evidence-hygiene
description: "Capture reproducible security evidence while minimizing secrets and unnecessary target artifacts"
category: "reporting"
version: "1.0.0"
author: "CyberStrike contributors; adapted with upstream attribution"
tags: [evidence, redaction, privacy, reproducibility]
prerequisites:
  - "A confirmed or actively validated candidate finding"
  - "A local evidence directory with restricted access"
chains_with: [attack-triage-validation, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/evidence-hygiene/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Evidence Hygiene

## 1. Objective

Make evidence reproducible and persuasive without collecting or exposing more data than necessary. Evidence should prove the security boundary and impact, not merely show that a request succeeded.

## 2. Capture the minimum necessary

Preserve timestamp and test context, sanitized request/response, test role and controlled object identifiers, baseline comparison, a short explanation of what each artifact proves, and tool details only when they affect reproducibility.

Prefer test accounts and synthetic marker values. Do not bulk-download records when a minimal sample establishes the issue.

## 3. Secrets and personal data

Keep two explicit copies when needed: a private target-local original for authorized reproduction, and a separately redacted copy for sharing, committing, attaching to public reports, or sending to external services. Do not silently redact the private local original when its exact value is material to the operator's investigation.

Use stable placeholders such as [REDACTED_ACCESS_TOKEN]. Keep original artifacts only in a restricted local location when retention is authorized and necessary. For detected secret-like strings, record the exact value, source file/URL, line or location, and confidence as a candidate; never describe a static match as a verified credential or vulnerability. Never put live credentials in skill files, Git history, issue comments, public reports, or command examples.

## 4. Reproducibility

A useful evidence package contains:
1. prerequisites and minimum test setup;
2. HTTP method, path, relevant headers, and body;
3. values to replace and where to obtain them;
4. expected secure result;
5. actual observed result;
6. response excerpt or controlled state proof;
7. limitations and manual steps.

Do not include unrelated traffic or screenshots exposing proxy history, browser panels, address bars, or notifications.

## 5. Screenshots, HARs, and logs

- Review the full screenshot before sharing; crop only if material context remains clear.
- Inspect HAR exports for cookies, authorization headers, query tokens, personal data, and unrelated requests.
- Use local environment variables or a secret manager for private test values.
- Remove session identifiers and sensitive response fields from logs.
- Avoid database dumps, base64 blobs, and unrelated files.
- Check filenames and metadata for confidential target/client details.

## 6. Integrity and retention

For formal engagements, record who collected an artifact, when, from which authorized context, and whether it was modified or redacted. Keep original and redacted versions distinct and access-controlled. A hash can support integrity tracking but does not prove an artifact's truth.

## 7. Verification checklist

- [ ] The artifact directly supports a stated claim.
- [ ] It came from an authorized in-scope test.
- [ ] Tokens, secrets, and unrelated personal data are removed.
- [ ] The request can be reproduced with documented placeholders.
- [ ] Expected and observed outcomes are explicit.
- [ ] No unnecessary bulk data is included.
- [ ] Filename and metadata are safe to disclose.
- [ ] The report references the exact reviewed artifact.

## 8. CyberStrike integration contract

Verify the actual evidence-storage API, redaction implementation, retention policy, and attachment flow before automation. Do not assume a sanitizer exists because this skill describes one. If redaction fails or is unavailable, do not publish or attach the raw artifact automatically.

## References

- Claude-BugHunter evidence hygiene: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/evidence-hygiene/SKILL.md
- Recon Skills: https://github.com/uphiago/recon-skills


## Targeted quality-loop enrichment (2026-10-19)

### Artifact lifecycle and independent replay
Every evidence item must have a stable artifact ID, originating request/session, timestamp, target-local path, redaction state, hash where practical, and a short statement of what it proves. Keep raw captures private and target-local; create a redacted derivative for model context and submissions. Scrub cookies, Authorization, query tokens, reset links, private response fields, user identifiers, and secret-bearing JavaScript before output. Verify replay uses tester-owned identities and the same preconditions. When redaction makes a finding impossible to reproduce, preserve a local private raw artifact and refer to its hash; do not copy the raw value into global notes, public research, commits, or reports.


## Artifact manifest and redaction validation

Keep one manifest entry per artifact. The manifest itself must not contain the secret it describes.

```json
{
  "artifact_id": "EV-LOCAL-0001",
  "kind": "http-request-response",
  "target_asset": "in-scope.example",
  "captured_at": "2026-10-19T10:00:00Z",
  "test_context": "tester-owned-account-A",
  "private_original_path": "evidence/private/EV-LOCAL-0001.bin",
  "shareable_derivative_path": "evidence/redacted/EV-LOCAL-0001.txt",
  "sha256_private_original": "<locally-calculated-hash>",
  "sha256_redacted_derivative": "<locally-calculated-hash>",
  "redaction_review": {
    "authorization": "reviewed",
    "cookies": "reviewed",
    "query_tokens": "reviewed",
    "personal_data": "reviewed",
    "unrelated_requests": "reviewed"
  },
  "claim_supported": "The controlled test account can read its own synthetic marker",
  "reviewer": "local-operator",
  "retention_basis": "authorized assessment"
}
```

Example values are illustrative. Use timestamps in the actual capture timezone and retain the original only when authorization and retention policy permit it.

### Redaction review must be semantic

Search for common secret-bearing locations, but do not rely on a single regex as proof of sanitization. Inspect headers, URL query/fragment, form fields, JSON/XML bodies, cookies, JWT-like values, reset links, source maps, screenshots, HAR metadata, filenames, and embedded logs. Redact values while preserving enough structure to reproduce the issue.

### Safe evidence persistence

- Do not put raw request/response bodies into a global research or learning database by default.
- Store a minimal redacted excerpt plus a local artifact reference and hash.
- Keep private originals out of Git and cloud-shared folders unless specifically authorized.
- If a secret is accidentally committed or transmitted, treat it as exposed: revoke/rotate it through the authorized owner and remove the artifact where possible; deleting a later copy does not erase Git history.
- Do not describe a hash as proof of integrity unless the manifest and collection process are also controlled.


## Agent-executable CLI tooling, resources, and helper scripts

### Tools and purpose
- `python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json` — check manifest structure before sharing evidence; review findings and actual artifacts manually.
- `sha256sum` or Python `hashlib` — identify artifact versions and detect accidental changes.
- `jq` and `rg` — inspect structured metadata and locate likely secrets in local evidence for manual redaction review.
- `file` and `exiftool` — inspect file type and metadata where available; metadata inspection does not guarantee sanitization.
- Python standard library — build a manifest and compare raw/derived artifact paths without extra dependencies.

### Install and verify
Verify with `python3 --version`, `jq --version`, `rg --version`, `sha256sum --version`, and `exiftool -ver` when installed. Prefer OS packages or official upstream releases. If optional tools are unavailable, use Python and manual review; record the gap instead of claiming the artifacts are sanitized.

### Resources
- https://csrc.nist.gov/pubs/sp/800/115/final
- https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/
- https://owasp.org/www-project-web-security-testing-guide/
- https://exiftool.org/

### Evidence handling
Keep original captures private and target-local. Review headers, query strings, form/JSON bodies, cookies, HAR files, screenshots, filenames, logs, source maps, and metadata. A regex scan or manifest validation cannot certify sanitization. Keep one manifest entry per artifact with sanitized path, time, hash, test context, redaction review, and the claim supported. Never store raw secrets or unrelated personal data in Git or global research.

---
name: evidence-hygiene
description: "Prepare reproducible pentest and bug-bounty evidence while redacting session secrets, personal data, and sensitive operational details."
category: "process"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - evidence
  - redaction
  - reporting
  - privacy
  - har
  - screenshots
tech_stack:
  - burp-suite
  - browser-devtools
  - har
  - curl
  - jq
chains_with:
  - triage-validation
  - report-writing
prerequisites: []
severity_boost:
  triage-validation: "Triage-quality evidence distinguishes a reproducible boundary failure from a misleading response or false positive."
---

# Evidence Hygiene and Redaction Discipline

## Objective

Produce concise, reproducible evidence a reviewer can validate without disclosing live credentials, customer information, or unrelated infrastructure details. Capture the minimum proof needed for the claim; do not collect data merely because it is reachable.

## Methodology

### Phase 1: Plan proof before capture

For each claim, list the minimum request, response, role, timestamp, expected result, actual result, and cleanup. Prefer synthetic records and owned accounts; decide which fields must be redacted before generating a screenshot or HAR.

### Phase 2: Redact secrets by default

Mask Cookie, Set-Cookie, Authorization, CSRF/session tokens, API keys, passwords, reset links, signed URL credentials, private keys, and environment secrets. Never leave a live test password/token visible on the assumption it can be rotated later. Preserve trace/request IDs and harmless field names only when they aid reproduction.

### Phase 3: Minimize personal and customer data

If a boundary issue is demonstrated accidentally with a real response, stop further access and retain only the smallest necessary sanitized field/shape. Mask names, emails, phone numbers, addresses, profile images, account identifiers, and record contents. Do not download more records to strengthen a screenshot.

### Phase 4: Sanitize HAR and raw artifacts

Before attaching a HAR, redact auth headers and cookie collections in both request and response; scan query strings, post data, response bodies, and URL fragments for secrets too. Verify the sanitized file with a second search/parser. Header-only redaction is incomplete if tokens live in URLs or JSON bodies.

### Phase 5: Capture request/response context

Use Burp Repeater or equivalent to show the exact request and minimal response. Preserve status and content type, include a negative control, and label each step. Do not falsify evidence, crop away contradictory results, or treat status code alone as impact proof.

### Phase 6: Name and protect artifacts

Use a stable convention such as finding-id_step-number_purpose.ext. For authorized state changes, capture baseline, controlled action, resulting state, and cleanup. Keep any required original encrypted and access-limited; share redacted evidence only through the approved private disclosure platform.

### Phase 7: Run a final leak scan

Inspect screenshots at full resolution and scan report/attachment copies for token fragments, internal hostnames/IPs, personal data, and unrelated program details. Remove test content and revoke test tokens if policy calls for it. Do not keep raw user data beyond the authorized purpose.

## What This Produces

- **Evidence lead:** an alert, screenshot, request, or scanner export exists but may omit role, baseline, state, or sensitive-data handling.
- **Ready-to-submit evidence:** shows the exact in-scope request, account context, expected-versus-actual behavior, and minimum consequence; secrets and unnecessary personal data are redacted.
- **Not acceptable:** evidence containing live credentials, reusable tokens, unnecessary victim PII, public target-identifying disclosures, fabricated responses, or data collected outside scope.

## Evidence Requirements

- Exact route/method, timestamp, environment, test identity/role, and baseline/control outcome.
- Sanitized request/response or screenshot with relevant headers and content shape preserved.
- Before/after state for any approved mutation and confirmation of cleanup.
- A note explaining material redactions and the sanitized artifact name.
- Keep raw artifacts encrypted and access-limited; do not attach them publicly or send them via ordinary email.

## Tools

- `jq` / Python JSON parser: redact auth headers, cookie arrays, and sensitive response fields in local JSON/HAR exports.
- `rg`: find likely credential/PII markers in local artifacts before sharing.
- `exiftool`: inspect image/document metadata in local evidence.
- `python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json`: validate required evidence metadata.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved responses offline.
- ImageMagick convert/magick: apply opaque redaction to image copies where needed; preserve private originals separately.

Verify `jq --version`, `exiftool -ver`, and the selected image tool's version. Official docs: https://jqlang.org/, https://exiftool.org/, https://imagemagick.org/.

## Evidence Redaction and Reproducibility Matrix

| Evidence type | Redact | Preserve |
|---|---|---|
| HTTP request/response | Cookie values, bearer tokens, passwords, CSRF values, reset tokens | Method, route, parameter names, status, content type, harmless canary |
| HAR | Auth headers, cookie values/arrays, tokens in URLs/bodies, unrelated PII | Timing, route, response shape, necessary controls |
| Screenshots | URL tokens, secret panels, real user identifiers/PII | Browser context, labelled result, synthetic role |
| IDOR/access control | Real victim fields and unrelated records | Field names/types, synthetic marker, owner/non-owner roles |
| Secret exposure | Full value, private key, connection string | Secret type/key name, source location, minimum truncated fragment if necessary |
| State-changing PoC | Real credentials and customer state | Disposable test object and before/action/after/cleanup sequence |
| Public write-up | Target identity and engagement details | Generalized vulnerability class and sanitized pattern |

**Practice:** redact before export, run a second-pass scan, and ensure evidence generation does not itself expose extra data.

## Verification and False Positives

- Redacting only the visible page can miss query strings, browser storage, HAR post data, Set-Cookie, and response-body tokens.
- Blur/pixelation may be reversible; use opaque redaction and verify the exported file.
- A 200 status or scanner screenshot may not show impact; preserve a matched negative control.
- Do not publish a target/finding identity until the program explicitly permits disclosure.
- If unintended access exposes sensitive data, stop and minimize; do not browse further to improve proof.

## References

- [uphiago/recon-skills — evidence-hygiene](https://github.com/uphiago/recon-skills/tree/main/redteam/evidence-hygiene)
- [Claude-BugHunter — evidence-hygiene](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/evidence-hygiene)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Evidence integrity and redaction regression
For each artifact, retain a stable reference, target-local path, timestamp, request/response identity, sanitized status, hash when practical, and claim it supports. Keep immutable raw evidence separate from redacted derivatives. Before each handoff, scan for cookies, Authorization headers, reset links, private identifiers, source secrets, and unrelated customer content. Verify that redaction preserves the request semantics needed for reproduction; if not, keep a private raw artifact and refer to its hash rather than exposing its values. Re-open the redacted artifact before submission and confirm cleanup/revocation state is recorded.


## Agent-executable CLI tooling, resources, and helper scripts

- `python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json` — validate required evidence metadata before sharing.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` — compare saved redacted response artifacts offline.
- `jq` and `rg` — inspect local JSON and search artifact metadata.
- Verify available commands with `command -v TOOL` and `TOOL --help`; use official documentation and record unavailable dependencies.
- Resources: https://owasp.org/www-project-web-security-testing-guide/ and https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html.
- Preserve private originals separately from redacted derivatives. Helpers do not guarantee complete sanitization; inspect output before sharing.

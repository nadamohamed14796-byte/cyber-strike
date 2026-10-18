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

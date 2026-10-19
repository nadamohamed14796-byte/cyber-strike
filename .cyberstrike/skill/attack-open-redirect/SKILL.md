---
name: attack-open-redirect
description: "Validate untrusted redirects, URL parser discrepancies, and security-relevant OAuth or login-flow impact"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [open-redirect, web, oauth, url-validation, authentication]
tech_stack: [http, browser, url, oauth]
cwe_ids: [CWE-601]
chains_with: [attack-cors, attack-jwt, attack-idor-automation, attack-triage-validation]
prerequisites:
  - "Authorized in-scope endpoint and controlled test identity"
  - "A safe destination under your control or a local browser proof"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-open-redirect/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/kb/issues/00500100_open-redirection-reflected"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
---

# Open Redirect Assessment

## Objective

Determine whether attacker-controlled input can navigate a browser or server-side workflow to an untrusted destination, and whether that behavior creates meaningful security impact. A generic redirect is often low impact; any claimed escalation must be independently demonstrated.

## Scope and safety

Use only in-scope URLs and a harmless destination you control. Do not collect credentials, authorization codes, tokens, or session data. Do not send phishing messages or expose real users to a redirect. Avoid payloads intended to execute script or inject response headers unless those exact tests are explicitly authorized.

## Procedure

### 1. Discover redirect sinks

Review in-scope browser traffic, route parameters, form submissions, login/logout flows, email verification, OAuth/OIDC callbacks, and server responses containing `Location`. Common parameter names include `next`, `url`, `returnTo`, `redirect`, `continue`, `callback`, `target`, and `destination`; names alone are not proof.

### 2. Capture baseline behavior

Record the original request, status, `Location` header, browser destination, and expected allowed destinations. Follow redirects only when safe and within scope; first inspect the response without automatically following it.

### 3. Test URL validation

With a benign external destination, test one representation at a time: absolute URL, protocol-relative URL, encoded value, and a controlled lookalike host. If the application uses allowlists, check whether validation parses the canonical hostname and scheme rather than relying on substring/prefix matching. Avoid CRLF, script schemes, data URLs, and other injection classes unless separately authorized and necessary.

### 4. Check nested and indirect flows

Inspect whether redirects occur after login, logout, password recovery, email verification, or OAuth/OIDC authorization. For OAuth, confirm the identity provider's exact redirect URI validation and the final callback behavior using only a test client and account. Do not attempt to capture a real user's authorization code or token.

### 5. Validate chained impact independently

- **OAuth/token exposure:** only claim it when a controlled flow demonstrates that a credential or code crosses an unintended trust boundary, without collecting real-user secrets.
- **CORS:** route browser cross-origin read questions to `attack-cors`.
- **SSRF:** a server-followed URL is a separate hypothesis and belongs in `attack-ssrf`.
- **XSS:** a script URL or HTML injection is a separate vulnerability class and must be validated separately.
- **Account takeover:** do not claim ATO from an open redirect alone.

### 6. Confirm and stop

Verify the final browser destination and whether an external host is actually reached. If the app normalizes or rejects the URL, record the rejection. Stop if the flow could expose a real credential or affect a real user.

## Common false positives

- Redirecting to a relative path or allowlisted destination.
- A reflected URL that never controls navigation.
- A trusted hostname that is only a string prefix of an untrusted hostname.
- A generic redirect described as token theft without proof of a token-bearing flow.
- A redirect chain whose final destination is still validated by the browser or identity provider.

## Evidence and output

Capture the redacted request, response status, `Location` value, final destination, validation rule, test identity, and impact chain if one is demonstrated. Return `endpoint`, `parameter`, `destination_class`, `redirect_behavior`, `auth_flow`, `chain_evidence`, `impact`, `confidence`, and evidence references.

## Related skills

- `attack-jwt` and `attack-oauth` — token validation and OAuth flow boundaries.
- `attack-cors` — cross-origin readable response.
- `attack-ssrf` — server-side URL fetching.
- `attack-triage-validation` — severity and false-positive checks.


## Targeted quality-loop enrichment (2026-10-19)

### Redirect destination and chain proof
Inventory observed redirect parameters and capture the default destination, then test allowlist boundary cases in a controlled browser without asking real users to follow the link. Record whether validation is based on exact origin, hostname suffix, scheme, path, encoded authority, or nested redirect—not just whether a Location header changes. An external redirect is often low impact by itself; check whether a specific OAuth/OIDC or password-recovery flow trusts it and whether an authorization code/token becomes bound to the wrong destination, using only owned accounts. Chain to ATO only after identity takeover is proven; otherwise report the redirect impact accurately. Compare a canonical safe destination as a negative control.

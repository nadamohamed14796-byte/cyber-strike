---
name: attack-401-403-bypass
description: "Analyze 401/403 responses for authorization defects and request-normalization differentials across proxies, gateways, servers, and application routers."
category: "web-security"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - authorization
  - access-control
  - path-normalization
  - method-handling
  - reverse-proxy
tech_stack:
  - HTTP
  - CDN
  - reverse-proxy
  - IIS
  - Apache
  - Nginx
  - Tomcat
cwe_ids:
  - CWE-284
  - CWE-285
  - CWE-863
chains_with:
  - attack-auth-bypass
  - attack-bfla
  - attack-idor-automation
  - attack-host-header
  - attack-request-smuggling
prerequisites:
  - "A known route and a reproducible denied baseline"
  - "An authorized test identity when the route requires authentication"
severity_boost:
  high: "A protected operation or sensitive response is demonstrably reachable by an unauthorized principal."
---

# HTTP 401/403 Bypass Analysis

## Objective

Determine whether a denial is consistently enforced by every layer and for every equivalent request representation. A status-code change is only a lead: the security signal is access to the protected resource or operation that the baseline denies.

## Testing Methodology

### 1. Establish a controlled baseline

Capture the exact method, URL, headers, body, authentication state, status, redirect chain, response length, content type, and a stable body marker. Repeat with a random nonexistent path on the same host to identify soft-404s and catch-all responses. Use two controlled identities where authorization—not authentication—is being evaluated.

### 2. Map the enforcement path

Identify CDN/WAF, reverse proxy, API gateway, web server, framework router, and application middleware when observable. Record which layer appears to issue the denial. Compare the same request through supported HTTP versions and ordinary versus raw-path-preserving clients; do not infer backend behavior from a single edge response.

### 3. Test request equivalence classes

Change one dimension at a time and retain a baseline/candidate pair:

- Path normalization: trailing slash, repeated slash, dot segments, percent-encoding of unreserved characters, encoded separators, case variation, semicolon path parameters, backslashes, and framework-specific path canonicalization.
- Authority/routing: canonical host, explicit default port, trailing dot, IDNA representation, and forwarded-host behavior; use the dedicated host-header skill for deeper analysis.
- Method handling: GET/POST and other methods only when relevant to the route; HEAD and OPTIONS are weak signals and do not prove body or operation access. Check whether a framework honors method-override headers or body fields.
- Header trust: compare proxy-generated identity/forwarding headers with ordinary client input. A header is meaningful only if the application trusts it and a real access-control decision changes.
- Route aliases: version prefixes, alternate content suffixes, API gateway rewrites, and documented legacy endpoints.
- Protocol translation: compare HTTP/2 and HTTP/1.1 only where the stack supports both and where the request remains well-formed; protocol differential analysis belongs with request-smuggling coverage when framing is involved.

### 4. Validate the actual authorization boundary

Use a controlled test account with the least privilege expected to be denied. For an authenticated route, compare anonymous, low-privilege, and authorized access. For a privileged operation, use a non-destructive read or a disposable synthetic object if a write is explicitly permitted. Do not use unrelated users' records as a test oracle.

### 5. Localize the defect

Repeat the smallest successful variant several times with a fresh connection where appropriate. Compare response body markers, resource identifiers, side effects, and application-visible state. Determine whether the defect is path ACL mismatch, method policy mismatch, trusted-header misuse, inconsistent normalization, or a missing application-level authorization check.

## What Constitutes a Finding

- A request variant reaches a protected resource or performs a restricted operation that the baseline denies.
- The effect is repeatable and attributable to an authorization decision, not merely a redirect, generic 200 page, OPTIONS response, or different error template.
- The security boundary and required attacker privileges are clear.
- A 401-to-403 change alone, a different response length, or a framework banner is not sufficient.

## Evidence Requirements

- Sanitized baseline and successful request/response pairs.
- Authentication and role context for each controlled test identity.
- Exact path encoding, method, relevant headers, protocol version, and redirect chain.
- A stable protected-content marker or minimal synthetic side effect.
- Soft-404 control, repetition result, and explanation of the enforcing layer when known.
- Redact cookies, bearer tokens, private data, and secrets.

## Tools

- Burp Suite Repeater/Comparer for controlled request diffs.
- curl with path-preserving options for simple HTTP comparisons.
- Browser DevTools for application routing and redirect context.
- Server/proxy logs when available to confirm which layer handled the request.
- Small scripts for response fingerprints; keep concurrency low and avoid broad fuzzing when targeted comparison answers the question.

## Authorization Differential Matrix

| Dimension | Candidate comparison | Strong evidence | Common false positive |
|---|---|---|---|
| Path canonicalization | Slash, dot segment, percent-encoding, case, semicolon | Protected route content or operation becomes reachable | SPA catch-all returns 200 |
| HTTP method | Same path with method relevant to route | Restricted method performs a meaningful protected action | OPTIONS advertises methods only |
| Method override | Ordinary method vs supported override behavior | Backend executes restricted operation while gateway policy is bypassed | Header is ignored or rejected |
| Forwarding headers | Client-supplied vs trusted proxy-generated value | Identity/routing decision changes and is confirmed server-side | Header merely appears in response |
| Route alias/version | Legacy or alternate path vs canonical path | Same protected resource bypasses policy on alias | Public health/version endpoint |
| Protocol handling | Supported HTTP versions through same path | Reproducible enforcement mismatch, not framing artifact | CDN variation or connection error |

## Verification and False Positives

- Compare against a random-path control on the same host to detect soft-404s.
- Confirm content semantics; a generic dashboard shell is not proof that its API data is accessible.
- Follow redirects and evaluate the final resource, not only the first status.
- Repeat with a clean session to rule out stale cache and client-side state.
- Distinguish authentication failure from authorization failure.
- Stop when a test risks changing real records or affecting other users; obtain explicit permission for state-changing validation.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

1. Capture three baselines for the same in-scope route: no credentials, an allowed test identity, and a denied test identity. Record response semantics, redirects, and server-side effects—not just the status code.
2. Compare only documented or observed route variants (for example, API version, trailing slash, or equivalent controller route); change one route dimension at a time and retain a known-invalid route as a negative control.
3. Vary one authentication context at a time: absent, expired/revoked, valid low-privilege, and valid authorized session. Do not treat alternate header spelling or a 200 response as proof without a protected-resource consequence.
4. If method-level behavior differs, check only methods supported by the application contract and use a disposable record for state-changing methods. Confirm the authorization decision is inconsistent with the expected policy.
5. Repeat the strongest differential once with a fresh controlled session and compare with the control route. Stop when the boundary failure is decisive or contradictory evidence explains the behavior.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** multiple independent signals support the hypothesis, but the security consequence or root cause is not yet established.
- **Unconfirmed:** evidence is incomplete, ambiguous, cached, or indistinguishable from a generic response.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record what was tested; do not claim that every theoretical variant was exhausted.
- A status code, banner, stack trace, response-length difference, endpoint existence, tool alert, or visible frontend state is never sufficient on its own.

### Stop and cleanup rules

Stop immediately on an out-of-scope boundary, unexpected real-user data, production side effects, rate-limit/availability degradation, credential exposure, or a request to perform a prohibited action. Do not continue merely to spend the budget. Restore disposable test state, revoke temporary sessions/tokens where possible, and record cleanup status.

### Agent handoff record

Return: skill, target asset, in-scope evidence, baseline, candidate hypothesis, attempts used, observed impact, negative controls, confidence/verdict, related-skill signal, sanitized evidence references, and cleanup status. Invoke a chained skill only when the stated signal is independently observed; do not chain from name similarity alone.

## References

- Source merged: [uphiago/recon-skills — recon/401-403-bypass/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/401-403-bypass/SKILL.md)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [PortSwigger: Access control vulnerabilities](https://portswigger.net/web-security/access-control)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)


## Hands-on field pattern: compare policy, not status codes
Use a known in-scope read-only endpoint and controlled identities. Keep the method, path, and object constant; change one auth condition at a time.

```bash
: "Set TARGET_URL and tokens for two authorized test principals in your shell environment"
curl -sS -D role-a.headers -o role-a.body -H "Authorization: Bearer $TOKEN_A" "$TARGET_URL"
curl -sS -D role-b.headers -o role-b.body -H "Authorization: Bearer $TOKEN_B" "$TARGET_URL"
curl -sS -D anonymous.headers -o anonymous.body "$TARGET_URL"
```

Compare semantic response content and the controlled object's owner/tenant, not just 401/403/200. Redact bodies before attaching evidence. A missing denial on one route only becomes a finding when a forbidden operation or protected data access is demonstrated. Correlate confirmed signals with `attack-bfla`, `attack-idor-automation`, `attack-auth-bypass`, or `attack-triage-validation` as appropriate.


## Targeted quality-loop enrichment (2026-10-19)

### Evidence-led branches
Use a controlled request pair for each boundary: canonical path versus an observed equivalent representation; allowed role versus denied role; supported method versus a known denied method; normal authority versus a documented proxy-derived authority. Preserve method, body, credentials, and content type unless that is the one variable being tested. A changed status is only a clue—confirm that the protected resource or operation became available. Compare against a random non-existent route and a legitimate denied baseline to catch soft-404s, routing fallbacks, and edge-generated responses. Chain to BOLA/BFLA only when the reachable resource or function exposes a distinct authorization gap; chain to request-smuggling review only when evidence actually indicates parser disagreement across HTTP layers.


## Normalization differential record

Use only a route and variants already observed in the application, and begin with a read-only resource. Keep a control request and change one normalization dimension at a time; do not fuzz a large path dictionary.

```bash
# Example structure only: replace with the canonical route and one permitted variant.
curl --path-as-is -sS -D canonical.headers -o canonical.body "$BASE_URL/observed/protected-route"
curl --path-as-is -sS -D variant.headers -o variant.body "$BASE_URL/observed/PROTECTED-ROUTE"
sha256sum canonical.body variant.body
```

A body hash is a triage aid, not proof. Compare stable protected markers, redirect destinations, content type, and server-side authorization outcome. Use the exact normalization behavior documented or observed for the target framework; do not assume case sensitivity, separator handling, or percent-decoding rules.

### Layer-attribution fields

Record client_protocol, edge_status, final_status, redirect_chain, canonical_route, variant_dimension, response_marker, auth_principal, expected_policy, observed_policy, layer_attribution_confidence, negative_control, and cleanup_status. If edge and origin logs are unavailable, describe the layer as unknown rather than naming a proxy from headers alone.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools Network/Application, Burp Proxy/Repeater/Comparer, and curl for replaying one observed request. Use only tool integrations that the current CyberStrike runtime actually exposes; optional CLI programs must be verified with command -v first.
- Before treating an optional CLI command as runnable, verify its presence and version locally. Do not claim integrations or tools that the current runtime has not exposed.
- Start with passive/read-only observation. Only active tests against authorized assets; state-changing tests require an approved disposable fixture and explicit program permission.

### Primary resources
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — test procedures and evidence criteria.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs and differential testing.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/) — remediation-oriented guidance.

### Small, reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
This compares local artifacts offline and heuristically redacts common secrets before displaying differences. It sends no requests and does not prove complete sanitization.

### Evidence and hand-off
- Save a sanitized artifact reference and the exact claim it supports. Keep credentials, full cookies, reset links, private user data, and raw secrets out of notes, global research storage, and commits.
- Mark the result confirmed, disproven, or still a hypothesis. If the key check cannot be run safely or the expected control is missing, record the gap rather than inventing a conclusion.

Validation note: use a known-good baseline and a control case, change one meaningful variable at a time, record the alternative explanation, and route a lead onward only when the evidence meets this skill's proof criteria.

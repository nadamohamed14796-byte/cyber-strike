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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis up to a maximum of 20; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Never count the same request with cosmetic encoding changes as separate attempts.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

Use the matrix and acceptance criteria already defined in this skill to choose the next distinct, low-impact hypothesis; do not repeat equivalent probes.

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

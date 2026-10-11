---
name: attack-ssrf
description: "Validate server-side URL fetching, internal destination access, and SSRF impact using bounded, authorized probes"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - ssrf
  - web
  - injection
  - cloud
  - attack
tech_stack:
  - web
  - aws
  - gcp
  - azure
cwe_ids:
  - CWE-918
chains_with:
  - attack-xxe
  - attack-ssti
prerequisites: []
severity_boost:
  attack-xxe: "SSRF via XXE parser = file read + internal network scanning"
  attack-ssti: "SSRF from SSTI = full RCE chain"
---

# Server-Side Request Forgery (SSRF)

## Objective

Force the server to make requests to internal resources, cloud metadata endpoints, or attacker-controlled servers.

## Testing Methodology

### Phase 1: Identify URL Input Points

Look for parameters that accept URLs:
- Webhook URLs, callback URLs
- File import/export (URL-based)
- PDF/image generation from URL
- URL preview/unfurling
- Proxy/redirect endpoints

### Phase 2: Confirm a Server-Side Request

Use a callback endpoint that you control and a unique marker. Confirm that the application makes the request from the server side. If out-of-band testing is not allowed, use a harmless, in-scope endpoint approved by the program.

```bash
# Set CALLBACK_URL to a unique URL on infrastructure you control
curl --max-time 15 --connect-timeout 5 --get \
  --data-urlencode 'url=https://CALLBACK_HOST/ssrf-test-UNIQUE_VALUE' \
  'https://TARGET/api/fetch'
```

A callback proves a server-side request occurred; it does not prove access to internal data. Check for redirects, DNS-only callbacks, and application-side requests as alternative explanations.

### Phase 3: Internal Destination Checks (Only When Explicitly Allowed)

Do not probe cloud metadata, credential endpoints, or internal ports unless the program explicitly permits those tests. Start with one harmless health endpoint in a designated test environment; do not enumerate a production network.

```bash
# Use only a program-approved, non-sensitive internal health endpoint
curl --max-time 10 --connect-timeout 5 --get \
  --data-urlencode 'url=http://127.0.0.1:8080/health' \
  'https://TARGET/api/fetch'
```

If metadata testing is expressly permitted, stop at a non-sensitive metadata root and do not request credential-bearing paths, tokens, or service-account keys. Prefer a lab with synthetic credentials for impact validation.

### Phase 4: Input Normalization Checks

Test one representation at a time, with a unique marker and low request rate. Use only when the program permits bypass testing; stop if the endpoint reaches an unintended sensitive service.

```bash
# Examples for a test endpoint; replace only with a program-approved URL parameter
curl --max-time 10 --connect-timeout 5 --get --data-urlencode 'url=http://127.0.0.1/' 'https://TARGET/api/fetch'
curl --max-time 10 --connect-timeout 5 --get --data-urlencode 'url=http://[::1]/' 'https://TARGET/api/fetch'
```

Do not use DNS rebinding, protocol-smuggling schemes, or redirect chains against production unless they are specifically authorized and isolated. Avoid `file://`, `gopher://`, and other non-HTTP protocols unless the scope explicitly permits them and a safe lab endpoint is available.

### Phase 5: Bounded Confirmation

Use a single approved probe at a time. Do not run a loop over common ports or automate broad internal scanning. If the first request confirms an unexpected internal destination, stop and preserve the minimum sanitized evidence needed to show the boundary crossing.

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Demonstrated access to sensitive cloud metadata or credentials in an authorized test environment | Severity depends on the actual credential/data exposure and reachable permissions |
| Confirmed access to a sensitive internal service or data | Severity depends on the service and demonstrated impact |
| Out-of-band callback confirms a server-side request, but no sensitive access is demonstrated | Usually needs further impact validation; severity is program-dependent |
| Timing-only behavior without corroborating evidence | Unconfirmed until alternative causes are excluded |
| File read via file:// protocol | Critical (P1) |
| gopher:// protocol access | High (P2) |

## Evidence Requirements

- URL parameter with SSRF payload
- Response containing internal data or metadata
- For blind SSRF: OOB callback evidence from infrastructure you control; a DNS-only callback is not proof of HTTP response access
- The exact server-side destination reached and the minimum sanitized evidence required to demonstrate it; do not enumerate or expose internal topology beyond scope

## Tools

- `attack_script ssrf_listener` — OOB callback listener
- `curl` — manual SSRF testing

## Blind SSRF Confirmation Gate

- For blind SSRF, require an out-of-band DNS or HTTP interaction containing a unique per-test marker before claiming that the server made an outbound request. A reflected URL, a formatted error, or a timing difference alone is not confirmation.
- If the callback does not arrive, do not label the result confirmed SSRF. Check whether the callback service is healthy, whether the endpoint is asynchronous, and whether the test is in scope; report the result as unconfirmed and state what was not observed.
- A DNS-only callback proves a name lookup, not that the server fetched the HTTP response or reached an internal service. Separate DNS resolution, HTTP fetch, response disclosure, and privileged internal access into distinct evidence claims.
- When testing redirects, verify that the application follows the redirect from its server-side fetch path. Use a controlled redirector and a harmless destination; do not redirect to credential-bearing metadata paths or sensitive internal services.

## Verification and Safe-Testing Gate

- Establish the exact in-scope endpoint and permitted request rate before testing. Start with one low-impact request and use bounded timeouts; do not launch parallel port-scan loops against production.
- Prefer an out-of-band callback domain you control and a unique per-test token. A callback confirms a server-side request, but does not by itself prove internal data access or high severity.
- Do not retrieve, print, store, or submit real cloud credentials. If metadata access is in scope, use the least intrusive request that demonstrates reachability and stop before requesting credential-bearing paths; use a program-approved test environment for credential-impact validation.
- For internal service tests, use a harmless health or banner endpoint where allowed. Avoid state-changing protocols, write commands, or requests that could alter services.
- For file-protocol tests, use only an approved, non-sensitive canary file in a controlled environment. Do not read system secrets or user data to prove impact.
- Confirm the behavior is server-side and not a client-side redirect, browser fetch, or unrelated DNS/HTTP interaction. Compare baseline and test requests and preserve sanitized evidence.
- A blocked request, timing difference, or generic error is not enough on its own. State what was reached, what data/action was demonstrated, and what remains unverified.

## References

- [uphiago/recon-skills — SSRF hunting and OOB validation](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-ssrf/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — SSRF hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ssrf/SKILL.md) (external research reference; not a local Cyber Strike skill path).

- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP: SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)

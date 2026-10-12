---
name: attack-request-smuggling
description: "Assess HTTP request-boundary parsing differences with lab-first validation, isolated connections, harmless canaries, and strict stop conditions."
category: "web-application"
version: "1.3.0"
author: "cyberstrike-official"
tags:
  - request-smuggling
  - http-desync
  - http1
  - http2
  - reverse-proxy
tech_stack:
  - http
  - http2
  - reverse-proxy
  - cdn
cwe_ids:
  - CWE-444
  - CWE-436
chains_with:
  - attack-cache-poison
  - attack-host-header
  - attack-open-redirect
prerequisites: []
severity_boost:
  attack-cache-poison: "A parsing discrepancy raises cache impact only when an authorized isolated test shows that a harmless altered response is shared with a clean test client."
---

# HTTP Request Smuggling and Desynchronization Assessment

## Objective

Determine whether a front-end proxy/CDN and a back-end server disagree about HTTP message boundaries, protocol conversion, or connection reuse. Request smuggling can contaminate shared connection queues and affect unrelated users; start in a lab and do not attempt to capture other users' requests or bypass controls on production systems.

Authorization is governed by the engagement scope and the library's central scope policy. Select a dedicated endpoint/connection and a test pattern allowed by the engagement. Do not use unrelated users' requests or sensitive data as a test oracle.

## Testing Methodology

### Phase 1: Map the HTTP path and parser chain

Identify the client-facing layer, origin/reverse proxy, protocol versions, connection reuse, TLS termination, and whether HTTP/2 is translated to HTTP/1.1. Record known infrastructure/configuration where available. A CDN header or an HTTP/2 response alone does not identify how the origin parses requests.

Review vendor documentation and configuration. Map each hop's protocol, normalization rules, request queueing, connection reuse, and error handling. Check whether edge and origin disagree on Content-Length, Transfer-Encoding, duplicate-header normalization, chunk extensions, whitespace handling, HTTP/2 pseudo-headers, and downgrade behavior.

### Phase 2: Establish normal baseline behavior

Use a dedicated test endpoint that returns a harmless fixed marker and request identifier. Record method, path, request headers, declared body length, negotiated protocol, connection behavior, response status/body hash, and timing. Send normal sequential requests over both fresh and reused connections where the test harness permits.

Use a second harmless endpoint as a control so a timing difference or generic error can be distinguished from normal application behavior. Keep test requests serial unless an isolated harness requires controlled concurrency.

### Phase 3: Identify the parsing class and variant

Test one framing hypothesis at a time against the mapped front-end/origin pair. Prefer two benign endpoints with distinct static markers so boundary discrepancies are observable without invoking privileged functions or touching private data. If production validation is expressly authorized, use a dedicated route/connection and stop at the first reproducible low-impact differential.

Classify the observed hypothesis rather than presuming exploitability:
- **CL.TE:** front end and origin differ in handling Content-Length versus Transfer-Encoding.
- **TE.CL:** the reverse ordering of parser preference or interpretation.
- **TE.TE:** intermediary differences in how transfer-encoding headers are normalized/recognized.
- **H2.CL / H2.TE:** HTTP/2-to-HTTP/1 conversion creates an inconsistent message boundary.
- **H2 request splitting / downgrade issue:** protocol conversion or stream framing produces unexpected downstream requests.

Malformed requests may be rejected at the CDN or proxy and never reach the origin. A timeout, 400/403, closed connection, or different latency alone does not confirm desynchronization. Compare edge and origin logs/request IDs, normalized headers, body lengths, and response queue order to locate the hop where parsing diverges.

### Phase 4: Confirm and localize the differential

Verify that the two layers parse the same byte stream differently and that the discrepancy causes a predictable marker, request-boundary, or response-order change. Repeat only enough to rule out network jitter and application behavior. Keep bodies minimal, use a dedicated connection, and close/reset it after each test. Correlate edge/origin logs where available. Never use another user's request as the queued follow-up or evidence source.

### Phase 5: Evaluate reachable impact and chain potential

A confirmed parser discrepancy is not automatically proof of request capture, authentication bypass, or cache poisoning. On a synthetic route or specifically authorized test path, assess whether the discrepancy could:
- produce an unexpected route/response boundary;
- alter a synthetic request/response marker;
- affect cache key or response association; or
- bypass a test-only route guard.

Do not use real users' requests, retrieve private data, invoke privileged state changes, or poison shared production assets as proof. Link to attack-cache-poison only when a separate controlled clean-client test demonstrates harmless shared-cache persistence.

### Phase 6: Verify cleanup and regression

Close dedicated connections, reset the lab/proxy, clear synthetic cache entries, and confirm ordinary sequential requests return expected markers. Preserve the front-end/origin versions, config snippets, response ordering, and the smallest sanitized test case. Recommend consistent parser behavior, disabling ambiguous framing, patching intermediaries, and safe protocol downgrade configuration.

## What Constitutes a Finding

- **Candidate / lead:** HTTP/2 downgrade, duplicate framing headers, a timeout, or a malformed-request error suggests possible parser inconsistency.
- **Confirmed desynchronization:** an isolated controlled test reproducibly shows the front-end and origin interpreting message boundaries differently, with a harmless marker proving the discrepancy.
- **Impact-qualified finding:** a separately authorized test demonstrates the exact security effect. Do not claim request capture, admin bypass, cross-user impact, or cache poisoning from parser divergence alone.
- **Not a finding:** a malformed request rejected consistently, a single timing spike, a proxy-generated 400/403, or a scanner alert without an origin-side differential.

## Evidence Requirements

- Exact in-scope host/path, client/front-end/origin protocol, and timestamp.
- Sanitized normal baseline and controlled lab differential; remove any authentication headers, tokens, or sensitive body content.
- Evidence of which layer interpreted the message boundary and how the harmless marker changed.
- Connection isolation details, repeat count, response order/body hashes, and stop/cleanup result.
- Clearly label lab-only, staging, or production confirmation and separate parser discrepancy from any independently demonstrated impact.

## Tools

- **Burp Suite with HTTP/2 support:** inspect protocol and request normalization; use extensions only under the engagement's explicit testing rules.
- **curl / OpenSSL:** establish protocol negotiation and ordinary baselines, not as proof of a desync by themselves.
- **Local proxy/origin harness:** preferred place to study CL.TE, TE.CL, TE.TE, and HTTP/2 downgrade differences.
- **Reverse-proxy configuration review:** compare framing normalization and backend protocol settings.
- **Logs from the test harness:** correlate request IDs and response ordering without collecting unrelated traffic.

## Request-Smuggling Classification and Coverage Matrix

| Class | Potential mismatch | Safe validation target |
|---|---|---|
| CL.TE | Content-Length versus chunked transfer interpretation | Isolated front-end/origin with static canary endpoints |
| TE.CL | Reverse parser preference | Isolated harness only |
| TE.TE | Different normalization of transfer-encoding headers | Local/version-matched proxy stack |
| H2.CL | HTTP/2 downgrade combined with Content-Length handling | Dedicated test route and isolated backend |
| H2.TE | HTTP/2 to HTTP/1 conversion and transfer-encoding | Vendor-approved lab fixture |
| Connection reuse | Response/request association diverges on a reused connection | Serial synthetic requests, then verify normal behavior |
| Header normalization | Edge and origin disagree on duplicate/combined header interpretation | Compare per-hop normalized headers and request IDs |
| HTTP/2 downgrade | Pseudo-header or framing translation differs across hops | Compare negotiated protocol and downstream HTTP/1 representation |
| Error handling | One hop rejects while another forwards/queues a partial request | Correlate edge and origin logs; errors alone are insufficient |
| Cache interaction | Parser boundary change affects cached response association | Separate cache skill and approved isolated test cache |

**Mitigation:** keep proxy/origin parsing consistent, remove ambiguous framing before forwarding, update edge/origin components, configure HTTP/2 downgrade safely, avoid unsafe connection reuse, and regression-test the complete deployed request path.

## Verification and False Positives

- A timeout can be caused by an incorrect body length, network delay, or a server waiting on a normal incomplete request.
- Front ends often normalize or strip malformed headers; a client-side request does not prove the origin received the same bytes.
- HTTP/2 support does not itself imply H2 desynchronization.
- Scanner output must be confirmed against the exact proxy/origin stack and version.
- A parsing difference is not equivalent to captured credentials, cross-user impact, RCE, or cache poisoning.
- Avoid leaving shared connections desynchronized, affecting unrelated users, changing privileged state, or exposing request contents. Use a dedicated connection and immediate cleanup for live validation; if the target cannot isolate the test path, move that variant to a faithful staging or local reproduction.

## Related Skills and Chains

- **attack-cache-poison:** use only when separate controlled evidence proves a shared cache serves the altered response to a clean test client.
- **attack-host-header:** investigate authority/forwarded-host trust independently from message-boundary parsing.
- **attack-open-redirect:** validate redirect behavior as a separate application-layer issue.
- **triage-validation:** confirm exact scope, reproduction, and severity before writing the report.
- **evidence-hygiene:** redact cookies, authorization headers, and any unrelated response data.

## References

- [PortSwigger: HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [James Kettle: HTTP Desync Attacks — Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)

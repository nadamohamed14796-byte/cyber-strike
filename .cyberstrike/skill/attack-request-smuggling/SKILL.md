---
name: attack-request-smuggling
description: "Assess HTTP message parsing discrepancies across authorized proxy and origin boundaries"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [http, request-smuggling, desync, proxy, parser-differential]
tech_stack: [http1, http2, reverse-proxy, load-balancer]
cwe_ids: [CWE-444]
chains_with: [attack-cache-poison, attack-host-header, attack-triage-validation]
prerequisites:
  - "Explicit written permission for request-smuggling tests"
  - "A dedicated low-impact endpoint and approved test window"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-http-smuggling/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/request-smuggling"
---

# HTTP Request Smuggling Assessment

## Objective

Determine whether a front-end proxy and back-end server disagree about HTTP message boundaries, potentially causing request desynchronization. This class can affect shared connections and other users, so it requires explicit permission and conservative validation.

## Safety gates

- Do not test on a production endpoint unless the program explicitly permits request-smuggling tests.
- Prefer a dedicated staging origin or an approved isolated test endpoint. Do not send ambiguous framing requests through shared production connections.
- Never attempt to access other users' requests, sessions, or data as proof.
- Use the program-approved tool and request budget; stop immediately on unexpected responses, connection instability, or signs of cross-request interference.

## Procedure

### 1. Map the HTTP path

Record client protocol, CDN/WAF/load balancer, reverse proxy, origin server, HTTP version negotiation, keep-alive behavior, and any documented intermediary. A suspected parser mismatch is meaningful only if the request traverses the relevant boundary.

### 2. Establish a baseline

Send normal, well-formed requests to a harmless endpoint. Record response order, connection behavior, headers, and whether the front end reuses connections. Confirm that ordinary requests are stable before any specialized test.

### 3. Review framing behavior conservatively

In an approved test environment, use a vetted request-smuggling test suite with low concurrency and benign canary paths. Examine conflicting content-length/transfer-encoding handling, HTTP/2-to-HTTP/1 translation, and normalization differences only when the tool and program policy support them. Do not improvise payloads against shared production connections.

### 4. Validate a parser differential

Require repeatable evidence that the front end and back end interpret message boundaries differently. A timeout, 400 response, or connection reset alone is insufficient. Prefer a controlled canary response in an isolated environment; never prove impact by causing another user's request to be processed incorrectly.

### 5. Assess downstream impact separately

If the confirmed desynchronization affects cache behavior, route to `attack-cache-poison`. If host-derived routing is involved, route to `attack-host-header`. Do not claim cache poisoning, credential theft, or cross-user impact unless each consequence is independently and safely established.

### 6. Stop and preserve evidence

Stop after the minimal reproducible result. Record the protocol path, test configuration, tool version, redacted request metadata, response sequence, and cleanup/rollback status. Avoid storing sensitive traffic.

## Common false positives

- WAF rejection or generic connection reset.
- HTTP/2 support without an HTTP/2-to-HTTP/1 translation boundary.
- Timing variance or load-balancer retries.
- A scanner's theoretical CL/TE classification without reproducible desynchronization.

## Output contract

Return `front_end`, `back_end`, `protocol_path`, `test_method`, `parser_differential`, `reproducibility`, `impact_confirmed`, `test_environment`, `cleanup_status`, `confidence`, and redacted evidence.


## Targeted quality-loop enrichment (2026-10-19)

### Parser-differential evidence and stop gate
Map the supported protocol path (client, CDN/WAF, reverse proxy, server) and preserve exact raw request bytes plus connection context in a controlled environment. Establish normal request framing first and use vendor-recommended safe checks or a lab harness; never attempt to desynchronize shared production users or deliver a request to another user's connection. A timeout, 400, or backend error alone does not prove smuggling. Require evidence of inconsistent parsing across layers and a contained downstream consequence. Chain to 401/403 review only where normalization changes the authorization decision; to cache review only after a safe cache differential is independently reproduced. Report ambiguity as inconclusive and stop at the minimum proof.


## Protocol-boundary evidence matrix

Treat the proxy chain as a sequence of parsers, not a single server. Fill each row from configuration, approved telemetry, or a dedicated test environment; do not infer a hop from a product banner alone.

| Boundary | What to record | Safe validation |
|---|---|---|
| Client → edge | HTTP/1.1 vs HTTP/2, ALPN, connection reuse | Capture normal requests and negotiated protocol |
| Edge → proxy/origin | Translation behavior, normalization, request buffering | Review config/logs or use a dedicated staging route |
| Message framing | How each layer handles duplicate/conflicting length metadata | Vetted tool in an isolated test environment; no improvised shared-connection payload |
| Connection reuse | Whether a single backend connection carries subsequent requests | Controlled canary request ordering with no sensitive endpoints |
| Cache layer | Whether response assignment is stable for the test connection | Cache analysis only after desynchronization itself is established |
| Authorization layer | Whether normalized path/method changes the security decision | Use harmless in-scope routes and compare the same principal |

### Evidence package

Record test_id, client_protocol, negotiated_protocol, proxy_chain_source, tool_version, exact test configuration, connection reuse mode, response sequence, parser_differential, repeatability, environment isolation, and cleanup. Store raw request bytes only in a private, access-controlled test artifact; redact cookies, authorization headers, and user traffic.

### Chain discipline

- A parser differential is the primary finding; cache poisoning, auth bypass, and cross-user effects are separate impact claims.
- If only one layer rejects a malformed request, record a defensive rejection, not a vulnerability.
- If the proxy chain cannot be established, mark the test inconclusive rather than guessing the backend behavior.
- Do not attempt to demonstrate impact by capturing, modifying, or exposing another user's request. Use a dedicated canary route and test connection.

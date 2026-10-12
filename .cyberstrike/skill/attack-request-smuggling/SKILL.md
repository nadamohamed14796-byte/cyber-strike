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

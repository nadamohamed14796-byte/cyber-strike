---
name: attack-ssrf
description: "Assess server-side URL fetching and request routing with bounded, non-sensitive proof"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [ssrf, url-fetching, webhooks, cloud, validation]
tech_stack: [http, web, api, cloud]
cwe_ids: [CWE-918]
chains_with: [attack-open-redirect, attack-host-header, attack-triage-validation]
prerequisites:
  - "Authorized in-scope endpoint and permission for SSRF validation"
  - "A controlled callback or test destination approved by the program"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ssrf/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/ssrf"
---

# Server-Side Request Forgery (SSRF) Assessment

## Objective

Determine whether an attacker-controlled URL or host value causes the server to make an unintended outbound request or access a protected network boundary. Do not access cloud metadata, internal services, or sensitive endpoints unless the rules of engagement explicitly authorize that exact validation.

## Safety gates

- Confirm the input endpoint and callback method are in scope.
- Use a program-approved, controlled callback domain or test server; keep proof to a unique marker and request metadata.
- Do not query cloud metadata endpoints, localhost admin panels, private network services, or internal credentials on production systems unless specifically approved in writing.
- Do not use redirects, DNS rebinding, alternate IP encodings, or protocol tricks to bypass controls without explicit authorization.
- Stop immediately if a response reveals secrets, internal data, or unexpected service behavior.

## Procedure

### 1. Identify URL-consuming features

Look for webhooks, image/PDF fetchers, URL previews, import-by-URL, callback validation, document conversion, feed readers, remote avatar fetching, and server-side proxy features. Record the expected allowed schemes, hosts, and business purpose.

### 2. Capture a baseline

Use a harmless, valid destination and record the application's response, asynchronous job state, and any outbound request evidence available to the tester. Determine whether the server fetches synchronously, asynchronously, or through a third-party service.

### 3. Test controlled outbound reachability

Submit a unique URL on an approved callback service and verify whether a request arrives. Record DNS/HTTP behavior, source metadata, timing, and whether redirects are followed. A callback is evidence of server-side fetching but not by itself proof of access to a protected resource.

### 4. Review validation boundaries

Check whether the application restricts schemes, validates the parsed hostname, resolves DNS safely, revalidates redirect destinations, blocks private/loopback/link-local ranges where required, and limits redirects. Test only the permitted boundary cases. Do not escalate to internal targets unless approved.

### 5. Validate response access separately

If the application returns fetched content, use a harmless test page and verify whether the response body is exposed to the caller. Out-of-band callbacks and response-based SSRF are different impact classes. Do not retrieve credentials or sensitive internal data as proof.

### 6. Consider redirects and DNS safely

Where policy permits, verify whether an approved test redirect changes the final destination and whether DNS validation is repeated. Do not use DNS rebinding or infrastructure targets as an unapproved bypass. Preserve callback logs and remove test jobs/configuration afterward.

### 7. Assess impact and remediation

Describe the exact server-side request capability, allowed scheme/host boundary, caller permissions, response visibility, and safe impact. Recommend allowlisting parsed hostnames, resolving and validating all destination IPs, revalidating redirects, restricting egress, and applying timeouts/size limits.

## Common false positives

- The browser, not the server, makes the request.
- A third-party processor makes the callback and is outside the target's trust boundary.
- A callback proves outbound fetch only, not internal-network reachability.
- The input is stored but never fetched.
- A URL preview returns an error without any server-side request.

## Output contract

Return `input_feature`, `destination_controlled`, `outbound_request_confirmed`, `redirect_behavior`, `response_body_exposed`, `network_boundary_tested`, `impact`, `cleanup_status`, `confidence`, and redacted evidence.


## Targeted quality-loop enrichment (2026-10-19)

### Server-side fetch trust boundary
Inventory the exact feature that consumes a URL, the server-side component performing the request, redirect behavior, DNS resolution time, allowed schemes/ports, and response exposure. Begin with a controlled callback host you own and inert content; compare a known-good URL to one boundary mutation at a time. Do not query cloud metadata endpoints, localhost/admin services, or internal networks on a public program unless explicitly authorized and specifically permitted. A DNS callback proves outbound resolution at most, not data access or credential theft. Route URL parsing inconsistencies to input validation, unsafe external API responses to unsafe API consumption, and secret-like source artifacts to evidence-safe triage without using them.

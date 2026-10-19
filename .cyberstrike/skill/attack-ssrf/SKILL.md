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


## Request-shape matrix and controlled callback workflow

For each feature, preserve the normal request shape and change only the URL field. The following is a template; replace the endpoint and field using an observed in-scope request, and use a callback hostname you control.

```http
POST /api/integrations/preview HTTP/1.1
Host: TARGET-HOST.example
Content-Type: application/json
Authorization: Bearer [TEST_TOKEN_REDACTED]

{"url":"https://CALLBACK-HOST-YOU-CONTROL.example/ssrf-check/UNIQUE-RUN-ID"}
```

Do not send this request to an assumed route or invent a tool schema. First capture the legitimate UI/API request and identify the actual URL-consuming field. Record the callback request metadata without collecting request bodies or credentials.

| Branch | Safe test | Evidence needed | Do not infer |
|---|---|---|---|
| Fetch existence | Controlled callback with unique path | Correlated callback timestamp/path plus matching app action | Internal-network access |
| Redirect handling | Redirect only between two callback endpoints you control, if permitted | Whether the server follows the redirect and which destination receives the request | That a private destination can be reached |
| Response-based | Return a harmless unique text marker from your controlled server | Marker appears in the application's response/job result | Access to sensitive internal content |
| Scheme validation | Inspect observed/documented accepted schemes; test benign unsupported scheme only when permitted | Server-side parser/fetcher behavior and rejection path | Code execution or local file read |
| DNS/egress policy | Review implementation/config and approved logs first | Resolved destination and enforcement decision from authorized telemetry | DNS resolution alone as HTTP reachability |
| Async jobs | Create one disposable job and inspect its status/result | Server-side fetch tied to that job ID and cleanup | A stored URL being fetched |

### Correlation fields

Persist request_ref, feature_name, controlled_destination, unique_path_marker, app_job_id, callback_timestamp, redirect_hop_count, resolved_address_class (only when legitimately observable), response_marker_seen, and cleanup_status. Do not store the callback service's private credentials or raw authorization headers.

### Chain gates

- Host-derived URL or redirect destination comes from untrusted authority metadata → host-header/open-redirect review only when that data flow is observed.
- Server fetch returns private content to the caller → demonstrate with a synthetic marker in an approved test environment; do not fetch internal secrets.
- URL fetch is delegated to a vendor/service → identify the actual trust boundary before attributing the request to the target.
- Callback alone with no sensitive response → report only the proven outbound-request behavior and its policy impact; do not inflate to cloud compromise.

Stop if the test reveals a real secret, internal response, or unexpected third-party request; preserve minimal redacted evidence and notify the program through its approved process.


## Tool installation and optional tooling (2026-10-19)

### Agent-usable tools and purpose
- `curl` — send a captured, authorized baseline request and inspect status/headers/redirects; do not invent routes or replay secrets.
- Python `httpx` or `requests` — run reproducible, low-volume request variations from a saved, redacted request template.
- ProjectDiscovery `interactsh-client` — correlate a unique DNS/HTTP callback only when an external OAST service is allowed by the program and its privacy rules.
- `jq` and `rg` — parse local JSON results and search source/configuration artifacts already collected within scope.
- Existing local helper: `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` — compare saved response samples; it does not issue network requests.

### Installation and verification
- Prefer packages from the official OS repository or each project's official installation guide; verify versions before using any tool.
- Interactsh official installation: https://github.com/projectdiscovery/interactsh. If Go is already installed, the documented client install is `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`; verify with `interactsh-client -h`. Install Go only from https://go.dev/dl/ if needed.
- Verify request tools with `curl --version`, `python3 -c "import httpx; print(httpx.__version__)"`, or `python3 -c "import requests; print(requests.__version__)"`, depending on the chosen client.
- If a dependency is missing, record it and use a safe available alternative; never imply a test ran when it did not.

### Primary resources
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf) — methodology and lab exercises.
- [ProjectDiscovery Interactsh](https://github.com/projectdiscovery/interactsh) — client usage and callback behavior.
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — defenses.
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — test planning.

Use only a unique callback URL and benign test value. Do not probe internal address ranges, cloud metadata endpoints, or retrieve internal files unless the target's written scope explicitly authorizes that exact test. Consider the privacy implications of a third-party OAST provider.

### Evidence and fallback
Correlate callbacks with a unique non-sensitive run marker and timestamp. Callback absence is inconclusive. A callback proves outbound interaction only—not internal-network access, data exfiltration, or credential access. Preserve redacted request/response artifacts and callback metadata; stop on real secrets or unexpected sensitive data.

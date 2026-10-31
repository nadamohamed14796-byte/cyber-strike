---
name: attack-javascript-analysis
description: "Turn authorized JavaScript assets and source maps into a deduplicated endpoint, parameter, auth-signal, and vulnerability-hypothesis inventory."
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [javascript, source-maps, endpoints, api, frontend-security, secrets]
tech_stack: [javascript, typescript, browser, rest, graphql, spa]
chains_with: [attack-web-recon, attack-source-leak, attack-dom-xss, attack-prototype-pollution, attack-shadow-api, attack-api-contract-testing, attack-browser-boundary-security, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
  - "https://tc39.es/ecma262/"
---

# JavaScript Attack-Surface Analysis

## Goal
Convert first-party JavaScript into validated leads for manual hunting. Do not treat a string, secret-like value, route fragment, or source-map comment as proof that an endpoint exists or a credential is usable.

## Queue and chat behavior

Treat every supplied JS URL, HTML container, local JS file, and discovered external script URL as an item in the target-local asset worklist. Deduplicate by canonical URL/content hash while preserving all source links. Process acquisition sequentially with one active asset at a time. Use the ingestion tool's live metadata title/status to show only the current asset while fetching; queued/waiting items are silent and must not create chat messages or one tool call per queued URL. The tool then runs local correlation over the saved snapshot and reports aggregate results; use the saved manifest/graph to present source-linked endpoint evidence without re-fetching each asset just to show progress. Reuse the same live tool entry for the next asset instead of appending messages per queued/completed item. Keep queue counts and detailed per-asset state in the manifest/logs, not the chat.

**Full-coverage execution contract — no user nudges and no dropped files:** inspect and process every asset individually, but do not emit one chat answer per file. The ingestion tool processes the entire supplied and dynamically discovered worklist sequentially in one invocation; it has no fixed URL-count or batch-count cap. It persists the queue before fetching and checkpoints per-item state, so an interruption can be resumed without losing earlier work. After each result, check `manifest_reconciled`, `collection_complete`, `correlation_saved`, `analysis_complete`, `worklist_pending`, `worklist_retryable_failures`, and `worklist_missing_manifest_records`. If the run was interrupted or pending/retryable/missing entries remain, immediately call `ingest_javascript_urls` again with the same `target_url` and `urls: []`; repeat automatically until the queue drains. Do not ask the user to say “continue” and do not stop at an arbitrary prefix. `manifest_reconciled=true` alone does not mean content was downloaded or analyzed. A clearly classified non-JavaScript response (for example a font or API JSON URL) may be terminally excluded from JS coverage; actual JS fetch failures, error documents served as scripts, malformed/partial maps, inventory errors, and missing source files must remain explicit gaps. Only report collection complete when every input/discovered URL has downloaded content or an explicit non-JS exclusion and no pending/retryable/missing records remain. Only report analysis complete when the complete local inventory was analyzed and no unprocessed source/inventory gaps remain. If the session tree does not contain the target, let ingestion run local-only correlation against its persisted, scope-checked downloaded assets; never substitute manual `curl` loops or import unrelated session traffic. Use the empty-URL resume call only to recover pending work or rerun incomplete correlation, without downloading unchanged files again.

The final response should be an aggregate, navigable inventory—not a wall of per-file chat messages. Preserve a source-file-level record for every analyzed file in the saved graph and link each request/risk candidate to the exact file and line. For each source file, retain its content hash, functions, structured requests/endpoints, parameter locations, auth/cookie signals, secret fingerprints, application/feature hints, risk-sink candidates, and any corresponding captured request IDs. Preserve explicit function → request candidate → normalized endpoint → captured request/response links where supported; mark static-only links as candidates and direct database/capture links as direct evidence. The tester survey is a persisted scenario plan, not a claim that those checks ran. For each structured request include its method (GET/POST/etc. or UNKNOWN), origin/path template, path/query/body parameter names, headers, auth/cookie/CSRF clues, calling function and parameters, source line/hash, matching captured-request IDs, and confidence. Summarize static sinks and likely review classes such as DOM XSS and CSRF as **candidates**, never as confirmed vulnerabilities. Group one canonical endpoint by normalized origin + route template + API version; nest distinct HTTP methods as operations. Keep each operation's path/query/body parameters, headers, authentication/cookie clues, content types, sources, captured request IDs, and confidence separate. Methods found only in captured traffic are traffic-only operations, never JavaScript-declared methods. Keep methodless route clues in endpoint-level unattributed evidence; never copy them into every known method. Keep failed, skipped, out-of-scope, missing, truncated, and incomplete source maps visible as separate coverage statuses; never silently drop them or claim full coverage when any URL is unresolved.


### Additional scenario inventory and agent handoff

The correlation graph, endpoint inventory JSON, and persisted tester survey contain additionalScenarios. Treat these as **candidate review plans**, not findings and not proof of reachability. Each record retains a stable scenario ID, category, hypothesis, source file + SHA-256 + line(s), signal kinds, related endpoint IDs, request-candidate IDs, observed request IDs, risk-signal IDs, prerequisites, and safe review steps. Scenarios are grouped by source/function/category so repeated markers do not produce duplicate tasks.

Generate and retain scenarios from identity/recovery/MFA, token lifecycle, data-layer clues, email workflows, file upload/download/import/export, transactional/business operations, roles/tenant/workspace boundaries, feature/debug flags, GraphQL/RPC/realtime messaging, browser storage, service workers, secret-like assignments, sensitive data-field and embedded-contact indicators, and static sink signals (DOM XSS, dynamic code, redirects, postMessage, CSRF, regex, prototype mutation). Keep secret values out of the graph: secret scenarios may include only the candidate kind, source location, and SHA-256 fingerprint. State what evidence is missing (live request, server handler, role control, source-to-sink reachability, owned fixture, or test authorization) rather than assuming it exists.

When a user explicitly requests testing, use the scenario as one routing input to attack-finding-correlation and the appropriate existing specialist skill. Reconfirm persisted scope and testing prerequisites, inspect linked captures and source locally, and avoid repeating unchanged hypotheses. Recon-only collection must only persist the plan; it must not dispatch testers or send probes automatically. Results from later skills must update the same scenario/evidence lineage rather than creating unrelated duplicates.

### Exposed credential candidates

Use [streaak/keyhacks](https://github.com/streaak/keyhacks) as a reference to identify provider-specific validation expectations, not as a command list to run blindly. Distinguish intentionally public browser/client identifiers from secrets; preserve only masked values/fingerprints in findings. Validate only within explicitly authorized scope and only with low-impact, provider-approved read-only checks. Never exchange a secret for a token, enumerate permissions broadly, access private data, send messages/webhooks, mutate resources, incur charges, or test a service outside scope. If impact cannot be demonstrated safely, keep the candidate unconfirmed and explain what remains unknown.

## Workflow
1. Accept JavaScript URLs and HTML page URLs from every available source: the URL collector, crawler output, HTML/script tags, source-map references, URL inventories, other tools, and URLs explicitly supplied by the user. An HTML page URL is valid input: ingest it as inert content, analyze inline executable script blocks, and enqueue external script `src` URLs through the same scope-enforced collector. For each downloaded bundle, discover relative/absolute HTTP(S) static imports and dynamic imports, resolve them against that bundle's final URL, and enqueue them through the same scope-enforced collector. Ignore unresolved bare package specifiers; do not execute any downloaded code. Do not analyze JSON-LD/import-map/data-only script blocks as executable code, and do not require the URL to originate from hackbrowser. Merge all sources into the same persistent queue/manifest while retaining provenance.
2. Use `ingest_javascript_urls` for the supplied URL batch. It enforces the persisted scope on each URL and redirect, downloads actual response bodies into the target-local `javascript/assets/` directory, and records content hashes and status in `javascript/asset-manifest.json`. It has no fixed URL-count, per-file-byte, aggregate-byte, or batch-count cap; the entire dynamic queue is fetched sequentially in one invocation unless interrupted. Timeout, redirect-loop, and scope protections remain active, and each unresolved URL must remain visible as a coverage gap. The correlation pipeline also retains scope-checked captured JS/source-map response bodies under `javascript/captured/` and indexes them in `javascript/captured-index.json`; treat those raw files as sensitive local evidence. Never treat a URL string as a downloaded file. Reuse an existing local artifact for repeated URLs; use content hashes to deduplicate identical bytes across different URLs. Use `force_refresh` only for an intentional new fetch of cached assets or to retry a permanent failure/skip after confirming the target or response may have changed; it never overrides persisted scope enforcement.
3. Store URL, content hash, observation time, response type, and source.
4. Check for source maps and readable bundles; identify minified/vendor code versus first-party application logic. Capture eligible external `sourceMappingURL` assets through the normal scope-enforced recon/browser path, then analyze version-3 `sourcesContent` as virtual source files. Track each reference as analyzed, pending capture, out of scope, missing/partial embedded sources, malformed, or truncated; never claim unresolved maps are complete. Preserve source-to-bundle mapping when available.
5. Extract routes, API base URLs, methods, GraphQL operation names, WebSocket/EventSource endpoints, parameter names, feature/config keys, role/tenant hints, request headers, cookie names, storage keys, file-upload destinations, URL-fetching features, identity/session flows, business workflows (billing, checkout, payments, refunds, exports, imports, invitations, webhooks), frameworks and SDKs, telemetry clients, service workers, browser persistence and cross-context messaging. This broad application-intelligence pass is independent of any predefined vulnerability list; keep every useful lead with file/line and confidence, even when it does not map to a known weakness.
6. Analyze inline JavaScript in captured HTML responses and local `.html`/`.htm`/`.xhtml` files in the target workspace's `javascript/` directory. Preserve the parent HTML file/request as provenance. HTML is parsed as inert text only; never execute its scripts. Normalize endpoint templates but retain HTTP method, content type, API version, parameter shape, auth context, and discovery source. Do not collapse endpoints just because their paths look similar.
7. Search for risky client sinks and data flows: innerHTML, insertAdjacentHTML, document.write, eval-like APIs, postMessage listeners, URL/redirect assignments, dynamic script loading, unsafe template rendering, and prototype-sensitive merge helpers. Confirm reachability and control of the source before assigning a vulnerability class.
8. Treat token-like strings as secret fingerprints only. Never print candidate secret values, test them, or copy them into requests. Store file, line/offset, type, confidence, and a redacted fingerprint.
9. Correlate extracted endpoints with actual network requests from the authorized browser session. An endpoint string may be dead code, a test route, a feature disabled in production, or a third-party URL.
10. Route only evidence-matched items to specialist skills: object identifiers to IDOR/BOLA; untrusted HTML sinks to DOM XSS; URL-fetch features to SSRF; redirect parameters to open redirect; undocumented/versioned routes to shadow API review; and credential exposure to triage without using the value.


## Source-assisted endpoint tracing

When authorized application source code is available locally, connect high-value frontend discoveries to their server implementation instead of treating the JavaScript bundle as the whole picture. Search route registration, controllers/handlers, authentication and authorization middleware, request schemas/validation, and the business/data operation that consumes the input. Trace each candidate as:

`frontend caller or route → HTTP method/path and input → server handler → authn/authz and validation → sensitive operation/sink`.

Record file and line references, relevant code/content hashes, the role or state preconditions, and which links are directly observed versus inferred. Use the trace to propose one precise, low-impact test and a meaningful control; execute it only when the user explicitly requested testing and scope/policy/runtime controls allow it. Static reachability or a suspicious sink alone is not a confirmed vulnerability. Do not execute untrusted source just to inspect it, and never expose raw secret-like values in notes or reports.

## Practical local-only searches
```bash
# Run inside a local copy of assets already collected from the authorized target.
rg -n -i 'sourceMappingURL|innerHTML|insertAdjacentHTML|document\.write|postMessage|WebSocket|graphql|fetch\(|axios\.|Authorization|tenant|role|redirect' ./javascript/
```
Treat output as candidate metadata. Redact token-like values before persisting, and do not include entire minified lines in a report.

## Prioritization and chaining
Prioritize routes that connect to privileged actions, tenant/object identifiers, file transfers, authentication flows, remote URL fetches, billing/export operations, and hidden API versions. A useful chain is JavaScript clue → correlated live request → missing server-side control → controlled proof → impact. If the live request cannot be observed or safely tested, keep it as an unconfirmed lead.

## Output contract
Keep the workspace organized around two canonical human-readable outputs and reuse the existing evidence folders; do not create another report copy for each asset.

1. `javascript-analysis.md` is the main report. Put a compact coverage/status summary first, then order sections as: asset URLs/statuses and hashes; local source files and source-map coverage; function/call-site inventory; API/request candidates; application workflows/frameworks/SDKs/integrations; roles/permissions/tenant/feature flags; sensitive data-field/contact indicators (field/type/location only; raw values omitted); security-review leads across relevant classes; secret fingerprints (never raw values); and exact gaps, unresolved URLs, and resume actions.
2. `endpoints.txt` is the canonical endpoint inventory. Use one endpoint identity per normalized origin + route template + API version, with HTTP methods nested as separate operations. Merge query/body/path parameter names, headers, auth/cookie signals, content types, source file/hash/line, and captured request IDs into the matching operation. Never mix one method's contract into another, never promote a traffic-only method to JavaScript evidence, and never create duplicate endpoint roots because a new method or query value appeared.
3. `javascript/asset-manifest.json` is the per-URL source of truth for downloaded, reused, failed, skipped, and pending assets. Graph JSON, captured-source indexes, and source-map evidence stay under `javascript/`; endpoint sidecars and source correlations stay under `recon/`. Do not make per-file Markdown reports or duplicate inventories.
4. Keep every useful application-intelligence lead even when it does not match a known vulnerability class; label static results as candidates and link them to file/line/hash. Never print raw secrets, token values, cookie values, or sensitive query values.
5. Report collection and analysis coverage honestly. Only claim exhaustive coverage when the tool result explicitly reports both `collection_complete=true` and `analysis_complete=true`. Failed, skipped, pending, out-of-scope, truncated, and unresolved source maps remain visible as gaps; do not hide them behind a single “complete” label.

## False positives
- Bundled third-party code or dead code is mistaken for the target's application logic.
- A development URL, test route, or obsolete API version is no longer reachable.
- A token-like string is a public identifier or dummy fixture.
- Client-side hiding is mistaken for server-side authorization.
- A sink appears in code but is unreachable from attacker-controlled input.

## Targeted quality-loop enrichment (2026-10-19)

### High-signal JS-to-request correlation
For every extracted route, retain bundle URL/hash, line/offset, first-party confidence, method/parameter template, auth/tenant hints, sink/source pair, and whether an actual browser request corroborates it. Search results and token-like strings remain metadata, never copy a value into a request. Prioritize admin/tenant flows, export/import, billing, file transfer, URL-fetch inputs, account recovery, and versioned APIs. A route string without traffic or docs may be dead code; a client-side role check does not establish server authorization. Chain to IDOR/property authorization only after correlating a real request and controlled fixture, to SSRF only on a confirmed server fetch path, and to DOM XSS only after reachability from an untrusted source is shown.

## Endpoint extraction quality gate

The canonical helper at `.cyberstrike/skill/scripts/js_endpoint_inventory.py` and the built-in correlation extractor must not treat arbitrary absolute URL strings as API endpoints. Absolute URLs require a recognizable request-call context (fetch, axios, XHR, or an equivalent client call); arbitrary documentation links, XML/SVG namespaces, static assets, and placeholder/development URLs are separate link/asset intelligence, not endpoint records. Keep conventional relative API routes as static candidates, and preserve their source file/line. Do not infer request body fields from nearby response objects: only fields tied to the actual request payload qualify. When the request shape is ambiguous, leave the parameter list empty and record the uncertainty.

## Repeatable inventory script (local assets only)

This helper inventories URL-like strings from files already collected for an authorized target. It prints normalized URL/path candidates and source locations, not surrounding source lines or token-like values. It does not fetch URLs, execute JavaScript, or prove that a route is live.

```python
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "./javascript")
EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".json", ".map"}
URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
PATH_RE = re.compile(r"""(?<![A-Za-z0-9])/(?:api|graphql|rest|v[0-9]+|oauth|auth|admin|internal)/[A-Za-z0-9_./{}:-]{1,180}""", re.I)
SECRET_RE = re.compile(r"(token|secret|password|api[_-]?key|authorization|cookie)", re.I)

def safe_candidate(value):
    value = value.strip().strip("\\"' ),;")
    if value.startswith("/"):
        route = value.split("?", 1)[0]
        return None if SECRET_RE.search(route) else route
    parts = urlsplit(value)
    if not parts.scheme or not parts.hostname:
        return None
    # Drop userinfo, query, and fragment before evaluating or printing the candidate.
    route = f"{parts.scheme}://{parts.hostname}{parts.path}".rstrip("/")
    return None if SECRET_RE.search(parts.hostname + parts.path) else route

if not ROOT.exists():
    raise SystemExit(f"Asset directory not found: {ROOT}")

seen = set()
for file in ROOT.rglob("*"):
    if not file.is_file() or file.suffix.lower() not in EXTS:
        continue
    try:
        source = file.read_text("utf-8", errors="ignore")
    except OSError:
        continue
    for line_no, line in enumerate(source.splitlines(), 1):
        for candidate in URL_RE.findall(line) + PATH_RE.findall(line):
            normalized = safe_candidate(candidate)
            if not normalized:
                continue
            key = (str(file), line_no, normalized)
            if key in seen:
                continue
            seen.add(key)
            print(f"{file}:{line_no}\t{normalized}")
```

Review and deduplicate results manually. Source-map files can contain full original source; do not share them publicly or commit them. The helper is intentionally conservative and may miss concatenated/dynamically assembled routes; do not interpret its output as complete coverage.

## Endpoint inventory schema

Use one normalized record per method + route template + content type + parameter shape. Attach multiple parameter observations and source locations to that record.

- asset_url, asset_sha256, asset_type, first_party_confidence, source_location
- route_template, method_observed, content_type, api_version, query_keys, body_key_paths
- auth_header_names (names only), cookie_names (names only), role_tenant_hints, identifier_fields
- source_sink_pairs, redirect_or_fetch_inputs, live_request_ref, observed_status_class
- candidate_skill, hypothesis, evidence_ref, confidence, false_positive_reason, redaction_status

Never store full cookie/token values or large minified lines. When a candidate appears important, use an already-captured, authorized normal-request artifact or a request supplied by the user; sanitize it before passing it to the specialist skill. Browser UI is not an agent dependency.

## Agent-executable CLI tooling, resources, and helper scripts

### Agent-usable CLI tools
- `rg`: search collected JavaScript for routes, API hosts, auth checks, source/sink patterns, and feature flags.
- `jsluice`: extract URL and endpoint candidates from local JavaScript.
- `xnLinkFinder`: optional endpoint extraction corroboration when it adds distinct coverage; prefer `jsluice`, source-map parsing, and the built-in AST/correlation workflow as the primary path. Treat LinkFinder examples from older WSTG material as legacy, not a default.
- `node`: parse or analyze local bundles with a purpose-built script; never execute unknown bundles with network/file permissions.
- Existing helper `python3 .cyberstrike/skill/scripts/js_endpoint_inventory.py ./javascript`: build a local endpoint candidate inventory.

### Installation and verification
Install Node.js from https://nodejs.org/en/download/ and use each tool's official upstream instructions. Verify `node --version`, `rg --version`, and the selected extractor's `--help`. Treat third-party scripts as untrusted until reviewed; if unavailable, use the repository helper and static text search.

### Resources
- https://developer.mozilla.org/en-US/docs/Web/JavaScript
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/0x240x23elu/JSluice

### Output contract
Store file path, source URL, content hash, discovered route/method/parameter hints, auth/session clues, line or offset, and confidence. Deduplicate candidates without discarding distinct parameters. Never copy token values, secrets, or whole minified lines into shared notes.


## Source-aware data-flow review (when source is available)

Apply this deeper pass only when the authorized target includes readable application source, a repository checkout, or usable first-party bundles/source maps. Do not assume that a minified bundle is the server source.

1. Map the relevant entry point and data source: URL/query/hash, form field, message event, API response, storage value, or user-controlled route.
2. Follow the value through parsing, validation, encoding, sanitization, authorization checks, and transformations to its eventual sink or security decision. For APIs, trace route → middleware/identity → object/tenant filter → response or state change.
3. Use an available AST/SAST tool such as Semgrep only when it is already usable and appropriate; a pattern match is a lead, not a finding. Inspect the actual source and control flow. Do not run untrusted build scripts, package lifecycle hooks, or application code merely to improve static coverage.
4. Link each candidate to the source file/hash and line or offset, the affected route/operation, any correlated captured request, the required identity/preconditions, and the next smallest safe validation step.
5. If a contract/spec file is present, route the operations into `attack-api-contract-testing`. If browser message handlers, service workers, cross-origin state, or opener/navigation relationships appear, route those cases into `attack-browser-boundary-security`. If source artifacts include lockfiles/manifests and source review is authorized, route dependency risks into `attack-dependency-cve-scanning`.

Do not promote a static source/sink path to confirmed impact without showing reachability and a security boundary failure. Preserve unresolved paths as candidates with the exact missing evidence. Keep one canonical endpoint record and add source/sink and source-map observations to it rather than duplicating it.

---
name: attack-javascript-analysis
description: "Turn authorized JavaScript assets and source maps into a deduplicated endpoint, parameter, auth-signal, and vulnerability-hypothesis inventory."
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [javascript, source-maps, endpoints, api, frontend-security, secrets]
tech_stack: [javascript, typescript, browser, rest, graphql, spa]
chains_with: [attack-web-recon, attack-source-leak, attack-dom-xss, attack-prototype-pollution, attack-shadow-api, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
  - "https://tc39.es/ecma262/"
---

# JavaScript Attack-Surface Analysis

## Goal
Convert first-party JavaScript into validated leads for manual hunting. Do not treat a string, secret-like value, route fragment, or source-map comment as proof that an endpoint exists or a credential is usable.

## Workflow
1. Inventory only target-related assets discovered by authorized navigation, passive sources, or recorded browser responses. Store URL, content hash, observation time, response type, and source.
2. Check for source maps and readable bundles; identify minified/vendor code versus first-party application logic. Preserve source-to-bundle mapping when available.
3. Extract routes, API base URLs, methods, GraphQL operation names, WebSocket URLs, parameter names, feature flags, role/tenant hints, request headers, cookie names, storage keys, file-upload destinations, and URL-fetching features.
4. Normalize endpoint templates but retain HTTP method, content type, API version, parameter shape, auth context, and discovery source. Do not collapse endpoints just because their paths look similar.
5. Search for risky client sinks and data flows: innerHTML, insertAdjacentHTML, document.write, eval-like APIs, postMessage listeners, URL/redirect assignments, dynamic script loading, unsafe template rendering, and prototype-sensitive merge helpers. Confirm reachability and control of the source before assigning a vulnerability class.
6. Treat token-like strings as secret fingerprints only. Never print candidate secret values, test them, or copy them into requests. Store file, line/offset, type, confidence, and a redacted fingerprint.
7. Correlate extracted endpoints with actual network requests from the authorized browser session. An endpoint string may be dead code, a test route, a feature disabled in production, or a third-party URL.
8. Route only evidence-matched items to specialist skills: object identifiers to IDOR/BOLA; untrusted HTML sinks to DOM XSS; URL-fetch features to SSRF; redirect parameters to open redirect; undocumented/versioned routes to shadow API review; and credential exposure to triage without using the value.

## Practical local-only searches
```bash
# Run inside a local copy of assets already collected from the authorized target.
rg -n -i 'sourceMappingURL|innerHTML|insertAdjacentHTML|document\.write|postMessage|WebSocket|graphql|fetch\(|axios\.|Authorization|tenant|role|redirect' ./javascript/
```
Treat output as candidate metadata. Redact token-like values before persisting, and do not include entire minified lines in a report.

## Prioritization and chaining
Prioritize routes that connect to privileged actions, tenant/object identifiers, file transfers, authentication flows, remote URL fetches, billing/export operations, and hidden API versions. A useful chain is JavaScript clue → correlated live request → missing server-side control → controlled proof → impact. If the live request cannot be observed or safely tested, keep it as an unconfirmed lead.

## Output contract
Save an endpoint/parameter inventory with asset, file hash, source, method, route template, parameters, headers, auth signals, role/tenant hints, sink/source, live-request correlation, confidence, redaction, and next skill. Keep one endpoint record with multiple parameter observations rather than duplicating the endpoint itself.

## False positives
- Bundled third-party code or dead code is mistaken for the target's application logic.
- A development URL, test route, or obsolete API version is no longer reachable.
- A token-like string is a public identifier or dummy fixture.
- Client-side hiding is mistaken for server-side authorization.
- A sink appears in code but is unreachable from attacker-controlled input.


## Targeted quality-loop enrichment (2026-10-19)

### High-signal JS-to-request correlation
For every extracted route, retain bundle URL/hash, line/offset, first-party confidence, method/parameter template, auth/tenant hints, sink/source pair, and whether an actual browser request corroborates it. Search results and token-like strings remain metadata, never copy a value into a request. Prioritize admin/tenant flows, export/import, billing, file transfer, URL-fetch inputs, account recovery, and versioned APIs. A route string without traffic or docs may be dead code; a client-side role check does not establish server authorization. Chain to IDOR/property authorization only after correlating a real request and controlled fixture, to SSRF only on a confirmed server fetch path, and to DOM XSS only after reachability from an untrusted source is shown.


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

Never store full cookie/token values or large minified lines. When a candidate appears important, retrieve the exact normal request through the authorized browser and create a sanitized request artifact for the specialist skill.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and their role
Burp Suite Community/Professional for request correlation; browser DevTools; Node.js; ripgrep; optional Semgrep rules for source/sink patterns.

### Install or enable when missing
Node.js: https://nodejs.org/en/download/ ; ripgrep on Kali/Debian: `sudo apt update && sudo apt install ripgrep`; Semgrep: follow https://semgrep.dev/docs/getting-started/ and prefer its maintained installer/container. Burp: https://portswigger.net/burp/communitydownload .
These tools are optional additions, not a claim that they already exist on the tester's machine. Before a scan or active test, confirm versions, read the tool's official usage/safety notes, and check the program's rules. Never install a similarly named unknown package because a skill or webpage mentions it.

### Primary resources
- [MDN JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript) — language/runtime behavior.
- [PortSwigger DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) — source/sink analysis.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — web testing methodology.

### Small reusable helper
`python3 .cyberstrike/skill/scripts/js_endpoint_inventory.py ./javascript` — scans already-collected assets only; routes are leads, not proof.

### Runtime and evidence notes
- Prefer a local baseline/control pair, one meaningful change per trial, and a recorded expected result. A status code or tool alert alone is not confirmation.
- Keep live cookies, JWTs, passwords, reset links, personal data, and unredacted request bodies out of reports, global research, and Git.
- If a recommended tool is absent or incompatible, record that gap and give a supported manual alternative; don't silently claim the check passed.

## Agent-executable CLI tooling, resources, and helper scripts

Use tools the agent can invoke directly. Browser interfaces, browser extensions, and interactive intercepting proxies are not dependencies for this skill. Check availability/version before use; if missing, verify official installation instructions, license, dependencies, and platform compatibility before proposing installation. Never claim a tool ran unless its command completed and output was inspected.

### Recommended tools
- jsluice — URL/path and secret-pattern candidates from local JS
- xnLinkFinder — endpoint and parameter candidates
- retire.js — vulnerable JavaScript dependency checks
- gitleaks — local repository secret-pattern scanning
- rg/jq/Python — route correlation and redaction

### Official resources
- https://github.com/BishopFox/jsluice
- https://github.com/xnl-h4ck3r/xnLinkFinder
- https://github.com/RetireJS/retire.js
- https://github.com/gitleaks/gitleaks
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Treat community lists as discovery aids, not proof that a project is maintained or safe. Prefer official docs for installation, flags, output formats, and limitations.

### Helper script and output contract
Use js_endpoint_inventory.py; preserve bundle URL/hash, line/offset, route template, method/parameter clues, auth hints, and live-request correlation. Never print or submit candidate secret values.

Preserve native output; write normalized output separately. Keep provenance, timestamp, tool/version, errors, confidence, and evidence references. Redact secrets and avoid silently overwriting source evidence. Emit machine-readable JSON/JSONL where practical and test helpers against local fixtures.

### Handoff
Return the command/tool and version, input/output artifact references, accepted/deduplicated/rejected/failed counts where applicable, limitations, confidence, and next skill. A missing tool or blocked source is an explicit status, not a successful empty result.

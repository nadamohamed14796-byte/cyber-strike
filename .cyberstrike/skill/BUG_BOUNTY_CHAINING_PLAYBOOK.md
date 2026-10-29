# CyberStrike Bug Bounty Chaining Playbook

**Purpose:** turn a verified observation into a small, evidence-led next test without assuming the next link exists. This is a routing guide, not a severity multiplier.

## The chain contract

The built-in chain detector is a hypothesis generator, not a vulnerability oracle. A detected pattern, high confidence score, severity label, or two records on related hosts does not establish exploitability. Scores are prioritization hints, not calibrated probabilities. Keep chain confidence separate from finding confidence and impact severity.

For every proposed link, record: observed trigger; prerequisite; actor/identity; asset/route; relevant security boundary; test-controlled fixture; expected next signal; disconfirming control; evidence path; stop/cleanup condition. Execute the next specialist skill only when its triggering signal was actually observed and the target is authorized for that test. If one link remains theoretical, keep it out of confirmed impact.

A chain is confirmed only when every reported step is independently reproducible and the end state is relevant. Recheck asset relationship and authorization for every hop; shared naming or a broad shared suffix is not enough. Credentials, tokens, source-map strings, route names, and scanner hints remain candidates until a permitted test establishes validity and effective access. Never test exposed credentials against unrelated real users or services. A same-finding escalation (for example, SSTI to code execution) still needs separate evidence of the terminal capability; do not infer RCE from SSTI alone. A lower-severity precursor may be reportable on its own, but do not inflate it using a hypothetical downstream effect. Avoid duplicate reports for one root cause; separate findings only where controls, impact, or remediation materially differ.

## Signal-to-skill routes

| Observed signal | Next focused review | What must be verified |
|---|---|---|
| JavaScript reveals a real API route or parameter | IDOR/BOLA, BFLA, property authorization, mass assignment, SSRF, DOM XSS as applicable | Correlate a real request; prove the specific object/role/property/source-to-sink boundary |
| Cross-account object reference behaves differently | IDOR/BOLA; then BFLA/property authorization if signals differ | Controlled owner and non-owner fixtures; exact object/operation/field policy |
| Operation is reachable by a low role | BFLA, authentication, API no-auth | Server-side principal and protected operation, not hidden UI or status code |
| Sensitive fields vary by role or writable fields persist | API property authorization, mass assignment | Field policy and authoritative persisted state |
| GraphQL schema/operation is discovered | GraphQL + property authorization + resource-consumption review where indicated | Executable operation, field/resolver auth, and cost boundary separately |
| Host or forwarded-host value changes an absolute link/route | Host-header; reset-flow or routing review if observed | Controlled output/route change and security-relevant downstream action |
| Origin reflection or credentialed cross-origin read appears | CORS; CSRF only if a state change is separately feasible | Browser-readable synthetic private marker and actual server state |
| Sensitive page can be framed | Clickjacking; CSRF only when a separate request-forgery condition exists | Authenticated frame context plus a meaningful user interaction and existing defenses assessed |
| Shared response changes between cache miss/hit | Cache poisoning or cache deception | Cache storage/replay across the relevant security context using inert controlled data |
| Open redirect appears in an OAuth/reset flow | OAuth/OIDC or recovery review | Actual flow binds a code/token/reset operation to the wrong destination, using test accounts |
| Login/recovery/MFA/session behavior diverges | Authentication, MFA, session, recovery, ATO triage | Terminal principal/control state and token/session lifecycle on disposable accounts |
| URL-consuming server feature is found | SSRF; unsafe API consumption if the URL comes from a partner response | Server-side fetch via a controlled destination; do not query internal/cloud metadata by default |
| Upload, archive, preview, or file parameter is unusual | File upload, file inclusion, information/source disclosure | Controlled canary path/content and exact storage/authorization/execution boundary |
| XML or serialized input is accepted unexpectedly | XXE or deserialization | Exact parser and trust boundary; harmless lab fixture; no real file/secret extraction |
| Rate/one-time workflow behavior differs | API resource consumption, rate-limit, business logic, race-condition | Defined invariant/control and low-impact authoritative state, not stress traffic |
| Metrics, logs, source maps, or build artifacts are exposed | Information disclosure, metrics, source leak, CI/CD | Sensitivity, access policy, provenance, minimum redacted evidence; never use exposed credentials |
| CMS/framework/version is fingerprinted | Matching specialist/CVE review | Product/build/backport confidence, reachable vulnerable component, and safe prerequisite proof |
| Service/ASN/origin is newly discovered | Recon attribution/service review | Ownership confidence, freshness, exact scope inclusion, and safe probing authorization |
| Imported skill/extension has an unclear source or broad capabilities | skill-supply-chain-audit; MCP/CI review if a concrete tool or workflow boundary is involved | Claimed purpose vs actual files/capabilities, provenance, static data-flow evidence, and safe quarantine decision |

## Chain lifecycle and deduplication

1. **Propose:** preserve source entry IDs, evidence references, assets, and the relationship suggesting the next hop. Keep inferred links hypothetical.
2. **Plan:** identify prerequisites, controlled principal/data, expected signal, baseline, negative control, impact boundary, and cleanup before testing.
3. **Validate one hop at a time:** delegate only the next relevant specialist skill after its prerequisite signal is observed. A blocked hop does not invalidate an independently confirmed precursor.
4. **Confirm terminal impact:** verify the actual principal, object/tenant, data or action reached, and persistence/state change where relevant. Never upgrade severity from theoretical impact.
5. **Close:** record confirmed, disproven, inconclusive, blocked, not run, or out of scope. Reopen only when a meaningful prerequisite, asset, role, state, or version changes.

Deduplicate using root cause + affected boundary/operation + impact, not title similarity alone. Keep a chain as a separate report only when it demonstrates materially distinct impact or remediation; otherwise link it to the primary finding. Never let a chain candidate overwrite a finding's own verification state.

## Request comparison rules

For each hypothesis, freeze all variables except the dimension being tested: method, route, content type, body, principal, object, tenant, browser origin, cache key, or parser representation. Keep a normal baseline and a relevant negative control. Record response semantics and authoritative state, not only status, length, banner, or frontend behavior. Repeat only to resolve noise or distinguish competing explanations; do not count equivalent encodings or cosmetic retries as new hypotheses.

There is no arbitrary numeric hypothesis ceiling. Continue while a new permitted test can change the conclusion. Stop when the property is confirmed/refuted, meaningful branches are exhausted, prerequisites are unavailable, program/rate/safety limits bind, or the service becomes unstable. “Not tested” and “inconclusive” are valid results; never fake completion counts.

## False-positive memory contract

A rejected lead should persist: root-cause fingerprint; asset and operation; tested identity/object/state; baseline and negative control; exact evidence references; alternative explanation; disposition; confidence; prerequisite missing; timestamp; and reopen condition. Do not let an old rejection suppress a different tenant boundary, operation, version, field, or state. A blocked test is not a false positive.

## Evidence and cleanup

Use tester-owned identities, synthetic data, reversible fixtures, and minimum sufficient proof. Redact tokens, session cookies, reset links, personal data, and unrelated content before model-facing notes or reports. Restore changed test state, revoke temporary sessions/tokens, and record cleanup. A runtime tool call must be verified as registered and successful before the report claims it was run.

## Source basis

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger API testing: https://portswigger.net/web-security/api-testing
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- Recon Skills: https://github.com/uphiago/recon-skills
- Claude-BugHunter: https://github.com/elementalsouls/Claude-BugHunter
- Agentic Bug Hunter: https://github.com/AmesianX/claude-bughunter
- Superagent Security Skills: https://github.com/superagent-ai/skills
- UseOSINT Skills: https://github.com/useosint/skills


## Cross-skill aggregation and feedback loop

Use .cyberstrike/skill/attack-finding-correlation/SKILL.md as the shared integration contract after new evidence arrives from recon, JavaScript analysis, endpoint discovery, specialist validation, or variant analysis. It owns the cross-source identity rules, evidence graph, canonical grouping, and incremental merge logic; individual skills remain responsible for their own technical proof criteria.

The loop is: **observe → correlate → select one evidence-backed handoff → validate with controls → merge result → recompute next handoff**. Do not fan out to every related skill by default. Keep each candidate edge tied to an observed signal and prerequisite; record blocked, inconclusive, and not-run states distinctly. Merge repeated observations and same-root-cause instances without discarding method, auth context, tenant/object boundary, parameter location, API version, evidence provenance, or materially different impact.

The correlation layer must never turn a possible chain into confirmed impact or increase severity just because more links were hypothesized. Confirm each necessary link independently, preserve contradictory evidence, and group sibling routes under one finding when root cause, remediation, and impact are materially the same. Reopen prior rejected leads only when new evidence changes the tested boundary or invalidates the previous explanation.

## SRC-Hunter-derived control-gap routing

Use the source-hunter playbooks as a decision aid, not as a new mandatory pipeline or a source of automatic severity. CyberStrike's existing scope decision remains authoritative, and a target already scoped in the session should not be repeatedly re-confirmed unless a proposed hop changes the asset or permission basis.

### Route from observed behavior
- REST/API request or JavaScript endpoint: map method, route, parameter/body fields, caller identity, and response evidence; then choose the relevant BOLA/IDOR, function authorization, property authorization, authentication, or business-logic check.
- Sensitive mutation (POST/PUT/PATCH/DELETE): identify the expected ownership, role, state-transition, and server-controlled-field rules. Test with controlled accounts/objects and one changed variable.
- Login, recovery, OAuth, JWT, or MFA signal: test token/identity binding, redirect/issuer/audience constraints, replay/expiry, or session transition only where the observed flow supports it.
- URL-consuming server feature: first establish evidence that the server performs a fetch; then use a controlled destination to evaluate URL/destination validation. Do not infer SSRF from a user-supplied URL field alone.
- Upload, download, preview, or file path: establish storage and access behavior using a harmless canary; do not attempt webshells, overwrite files, or extract sensitive files.
- Cache/host/CORS/GraphQL/WebSocket/rate or race signal: select a dedicated check only when the relevant protocol or behavior is observed; avoid broad probing or load generation.

### Required control comparison
For every proposed chain edge, record:
1. baseline behavior under the expected valid context;
2. controlled negative case (wrong owner/role, missing permission, or safe invalid state);
3. the one variable changed in the candidate request;
4. actual response plus authoritative state/data evidence, if applicable;
5. the secure invariant that was violated, or the evidence that disproves the hypothesis.

A 200 response, reflected input, static route, token-shaped string, or scanner label is not sufficient by itself. Do not assume that a control is absent because the client UI exposes a field or hides a route.

### Chain stop and deduplication
Only follow one evidence-backed next hop at a time. Recheck scope and prerequisites for every new asset or trust boundary without re-prompting for unchanged scope. Keep unverified links as hypotheses; do not inflate severity based on a hypothetical terminal impact. Merge observations with the same root cause while retaining distinct method, identity/tenant, field, endpoint/version, evidence provenance, and materially different impact. Never discard contradictory or negative evidence.

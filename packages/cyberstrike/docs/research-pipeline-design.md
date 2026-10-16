# Research Pipeline: Collect, Persist, Study, Retrieve

Status: implementation design for `packages/cyberstrike`.

## Goal

Make `/update` the single resumable orchestration entry point for public report/write-up collection and study. Keep hunting-time knowledge retrieval separate. A source index is a discovery surface, never proof that a report has been collected or studied.

## Existing implementation to preserve

The current code already has useful building blocks:

- `src/research/sources.ts`: source registry and host/path allowlists.
- `src/research/adapters.ts`: source-specific discovery and document classification.
- `src/research/safe-fetch.ts`: constrained fetch and source-scoped session handling.
- `src/research/ingest.ts`: URL normalization, HTML text extraction, secret redaction, report fetch.
- `src/research/queue.ts` and `queue.sql.ts`: durable URL queue, lease-based claims, retries, and fingerprints.
- `src/research/cycle.ts` and `cycle.sql.ts`: persisted collect-then-study phase gate and per-source progress.
- `src/learning/report-knowledge.ts`: shared security knowledge persistence.
- `src/tool/research-study.ts`: agent-facing orchestration tools.
- `src/tool/research-knowledge.ts`: hunting-time retrieval.
- `migration/20261016130000_research-cycle-phase-gate`, `20261016131000_research-content-fingerprint`, and `20261016132000_research-cycle-duplicate-ledger`: recent durability groundwork.

Do not create a parallel research subsystem. Extend these paths and reuse their existing contracts.

## Runtime model

```text
/update
  -> load config + stats + existing active cycle
  -> resume active cycle, otherwise create one for configured sources
  -> COLLECT: discover index pages and report candidates
       -> enqueue only eligible report/document URLs
       -> fetch each report page using the source-scoped session
       -> sanitize and persist full extracted text + SHA-256 fingerprint
       -> follow allowed in-scope links discovered within report pages
       -> record success, auth block, fetch error, or exhausted pagination
  -> COLLECTION GATE: every selected source has a durable terminal state
  -> STUDY: claim each stored report with a lease
       -> model-led extraction into structured knowledge
       -> persist study result and model/prompt version
       -> mark learned/rejected/retry with reason
  -> VERIFY: reconcile queue and knowledge counts and unresolved blockers
  -> finalize cycle as complete or partial with explicit reasons
```

The gate allows studying only after all selected sources are terminal for collection. `partial` and `blocked` are terminal operational states, not success claims; unresolved auth/fetch errors force the overall cycle to be partial. An execution batch ending, timeout, or tool-call boundary must never finalize a cycle.

## Durable records and invariants

### Report queue / document record

Keep the stable identity `(source_id, normalized_source_url)`; keep content identity separately as `SHA-256(normalized_sanitized_text)`. Persist:

- original and canonical URL, title, source kind, discovery parent, and discovery timestamp;
- sanitized full text (not just a short excerpt), text length, fingerprint, and fetched timestamp;
- independent discovery/fetch/study states, attempt count, last error, and next retry eligibility;
- lease owner/expiry for concurrent workers;
- study output and study version, plus a reference to the shared knowledge records produced.

Do not put raw cookies, authorization headers, credentials, or signed query parameters in URLs, logs, or stored text. Preserve source references even when two URLs produce identical content.

### Knowledge separation

Public report-derived knowledge is global and source-cited. Target-specific observations, requests, credentials, and evidence remain in the target workspace/session data model. A public write-up must never be converted into a finding for the active target merely because the agent is hunting.

Each learned item should retain: technique/class, prerequisites and applicability conditions, ordered test procedure, evidence to observe, expected and alternative outcomes, impact conditions, false-positive checks, safety/scope constraints, source report IDs/URLs, confidence, and study version.

## Report-vs-index classification

A URL is not a report just because it contains security-related words. Source adapters should return a typed classification:

- `report`: likely a standalone disclosure/write-up; fetch and study its full content.
- `index`: listing, feed, search results, archive, pagination or profile; parse links and continue crawling.
- `reference`: durable technical reference; collect only if the source policy permits it, but do not treat it as a vulnerability report.
- `irrelevant`: explicitly excluded by source policy.
- `unknown`: fetch and inspect before making a terminal classification.

A short index page must not be saved as a successful report when it contains links to individual reports. If a candidate page is thin, title-only, login-gated, or mostly navigation, record that classification and follow its eligible report links. Use source-specific adapters for JavaScript-rendered or API-backed listing pages rather than assuming a generic HTML fetch sees the report list.

## Crawl completeness

For each source, store a durable pagination cursor/window and the canonical URLs already visited. Continue discovering until the source adapter demonstrates exhaustion (no next page/cursor and no unvisited eligible links), or a concrete blocker is recorded. A page window is a resumable unit of work, not a global cap.

Maintain two dedupe layers:
1. URL dedupe per source to avoid recrawling the same page.
2. Content fingerprint dedupe across URLs/sources to avoid repeating study, while retaining every source reference.

The index-page cache must be promotable if a URL first classified as an index later resolves to a report. Failed fetches must not be cached as successful empty content.

## Sessions and errors

Use only the configured session/credential binding for the source being fetched. Never borrow another source's cookie jar or fall back to a user's unrelated browser session. For every blocked or failed attempt, persist a normalized reason such as `auth_required`, `rate_limited`, `robots_or_policy_block`, `timeout`, `network_error`, `parse_error`, or `source_exhausted`. Redact secret-like values from all error text. Retry only transient failures with backoff; auth failures remain visible and do not count as completed content.

## Study contract

Study is idempotent by `(content_fingerprint, study_version)`. Claim with a lease; persist the extracted result before marking the queue row learned. If the process dies between these writes, a retry must safely detect the existing study result rather than duplicate knowledge. Do not infer a technique when the report does not support it; store uncertainty and missing evidence explicitly.

Suggested structured result:

```ts
type ReportStudy = {
  summary: string
  findings: Array<{
    vulnerabilityClass: string
    prerequisites: string[]
    applicability: string[]
    steps: Array<{ action: string; expectedEvidence: string[]; interpretation: string }>
    impactConditions: string[]
    falsePositiveChecks: string[]
    limitations: string[]
    confidence: number
  }>
  sourceEvidence: Array<{ url: string; quoteOrLocation: string }>
  studyVersion: number
}
```

## CLI/tool boundaries

- `/update`: owns discovery, fetch, persistence, study, verification, retries, and resume.
- Hunting retrieval tool: read-only query over completed global knowledge; no crawling, refetching, or studying.
- Status/stats: read-only visibility into phase, source progress, queue states, fingerprints, learned results, and blockers.
- Reset: explicit destructive maintenance only; never called implicitly by `/update`.

Remove old administrative command surfaces from the user-facing workflow only after confirming there are no internal callers or tests depending on them. Do not delete migrations or old data as part of a workflow rename.

## Acceptance tests

1. Index page with five report links results in five report candidates being fetched; the index itself is not counted as a studied report.
2. Report body contains links to eligible same-source reports; crawl follows them and persists provenance.
3. Kill/restart during discovery, fetch, or study resumes from the last durable checkpoint without losing text or repeating completed study.
4. A small discovery batch ends while pages remain; cycle remains collecting and proceeds in a subsequent pass.
5. One source is auth-blocked while others are available; other sources continue, the auth error is recorded, and the final cycle is partial rather than falsely complete.
6. The same report at multiple URLs produces one study result with multiple source references.
7. Same URL changes content; new fingerprint invalidates the previous study version and queues a new study.
8. A fetch timeout or parser error is not represented as an empty successful report.
9. Hunting retrieval returns global technique knowledge and citations but does not mutate the collection queue.
10. Target-specific notes and findings remain isolated from public report-derived knowledge.
11. Secrets in source text, URLs, or errors are redacted before persistence.
12. Migrations, type checks, adapter tests, queue tests, cycle tests, study tests, and an end-to-end collect-then-study test all pass.

## Implementation order

1. Audit the existing research tools and their call graph; preserve the current host/path and safe-fetch guards.
2. Ensure full sanitized content is stored durably, not only in transient payload/excerpts.
3. Fix source adapters/classification and report-link traversal; add fixture-based tests per source.
4. Make cycle completeness depend on pagination/link exhaustion and recorded blockers.
5. Make study writes idempotent by content fingerprint + study version.
6. Wire `/update` to this lifecycle and keep hunting retrieval read-only.
7. Run migration/type/test checks and report real outcomes; never claim runtime verification from source inspection alone.

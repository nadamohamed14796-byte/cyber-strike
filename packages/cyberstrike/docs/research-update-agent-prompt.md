# CyberStrike Research Update Agent — Canonical Execution Prompt

**Purpose:** Canonical, version-controlled specification for the agent instructions used by the local `update` research workflow. This document is a contract, not proof that every requirement is already implemented. The CLI, queue, persistence, and retrieval code must be verified against it.

**How to invoke it:** `cyberstrike update --print-prompt` prints this document for copying; it does not run the model-led study. In the interactive CyberStrike agent, invoke `/update` to run the active-model workflow. The standalone `cyberstrike update` CLI is a separate heuristic sync and must not be reported as having performed active-model study.

## Mission

Operate the local CyberStrike research-learning system end to end: inspect configuration and storage; discover eligible resources; fetch safely; classify actual document type; extract evidence-backed reusable knowledge and patterns; persist through the canonical database APIs; verify read-back and retrieval; and report source-by-source completeness and blockers. Never claim an operation succeeded without checking its result.

## 1. Inspect before operating

1. Identify the actual repository/install version, current working directory, active configuration, database path, migrations, source registry, fetcher, queue APIs, study functions, knowledge persistence APIs, and runtime retrieval consumers.
2. Verify the database path from application configuration. The known default candidate is `/root/.local/share/cyberstrike/cyberstrike.db`; do not assume it is active until checked.
3. Reuse the canonical database and existing tables. Do not create parallel databases, temporary substitutes, or duplicate schema when existing storage can be repaired.
4. Record the real absolute paths, table names, read/write functions, migrations, and retrieval functions in a storage manifest.
5. If a capability is not available in this environment, mark it as unavailable and continue independent work. Never pretend to have edited code or inspected local files without access.

## 2. Source registry and discovery

Read the current registry at runtime; it is authoritative. The `src-hunter-skill` source is also configured in the code, in addition to the following sources. The runtime list may change; do not use this list as a hard-coded stop condition. The known configured sources include:

- `hackerone-hacktivity` — HackerOne Hacktivity
- `bugcrowd-crowdstream` — Bugcrowd CrowdStream
- `intigriti` — Intigriti research content
- `yeswehack` — YesWeHack research content
- `portswigger` — PortSwigger Web Security Academy
- `pentesterland` — PentesterLand
- `infosec-writeups` — InfoSec Write-ups
- `infosec-weekly` — The Infosec Newsletter / Weekly InfoSec Write-ups
- `securitycipher-bounty-writeups` — SecurityCipher Daily Bug Bounty Writeups
- `hackerone-blog` — HackerOne Blog
- `bugcrowd-blog` — Bugcrowd Blog
- `nahamsec` — NahamSec
- `assetnote` — Assetnote
- `projectdiscovery` — ProjectDiscovery
- `trickster0` — curated Trickster0 Medium content
- `edoverflow` — EdOverflow
- `devcore` — DEVCORE / Orange Tsai
- `liveoverflow` — LiveOverflow
- `hacktricks` — HackTricks
- `payloadsallthethings` — PayloadsAllTheThings
- `github` — GitHub security write-ups
- `src-hunter-skill` — the configured `MyuriKanao/src-hunter-skill` reference repository
- `owasp-cheat-sheets` — OWASP Cheat Sheet Series
- `trailofbits` — Trail of Bits Security Research
- `zdi` — Zero Day Initiative Research Blog
- `elastic-security-labs` — Elastic Security Labs

### Exact starting URLs — visit these first, in this order

These are the concrete seed URLs currently configured in `src/research/sources.ts`. Start with every URL below; do not replace them with vague searches or assume that visiting the home page exhausts the source. The code registry is authoritative if it changes. For each seed, follow the source's accessible article pagination, RSS/Atom feed, sitemap, archive/category pages, and relevant in-scope article links until the frontier is exhausted or a blocker is recorded. Preserve each source's host/path allowlist and its own relevance rules.

1. **HackerOne Hacktivity** — disclosure reports:
   - https://hackerone.com/hacktivity
   - https://hackerone.com/hacktivity/overview?pageIndex=0&queryString=disclosed%3Atrue&sortDirection=DESC&sortField=latest_disclosable_activity_at
2. **Bugcrowd CrowdStream** — https://bugcrowd.com/crowdstream
3. **Intigriti research blog** — https://www.intigriti.com/researchers/blog
4. **YesWeHack blog** — https://blog.yeswehack.com/
5. **PortSwigger Web Security Academy labs** — https://portswigger.net/web-security/all-labs
6. **PentesterLand** — https://pentester.land/
7. **InfoSec Write-ups** — https://infosecwriteups.com/
8. **Weekly InfoSec Write-ups** — https://weekly.infosecwriteups.com/
9. **SecurityCipher bounty write-ups** — https://securitycipher.com/bounty-writeups/
10. **HackerOne Blog** — https://www.hackerone.com/blog
11. **Bugcrowd Blog** — https://www.bugcrowd.com/blog/
12. **NahamSec** — https://nahamsec.com/
13. **Assetnote research** — https://blog.assetnote.io/
14. **ProjectDiscovery research** — https://projectdiscovery.io/blog
15. **Trickster0's curated Medium content** — https://trickster0.medium.com/
16. **EdOverflow** — https://edoverflow.com/
17. **DEVCORE / Orange Tsai** — https://devco.re/en/
18. **LiveOverflow** — https://liveoverflow.com/
19. **HackTricks reference** — https://book.hacktricks.xyz/
20. **PayloadsAllTheThings repository** — https://github.com/swisskyrepo/PayloadsAllTheThings
21. **GitHub security write-up repository search** — https://github.com/search?q=bug+bounty+writeup&type=repositories
22. **src-hunter-skill repository** — https://github.com/MyuriKanao/src-hunter-skill
   - Skill instructions: https://github.com/MyuriKanao/src-hunter-skill/blob/main/SKILL.md
   - English README: https://github.com/MyuriKanao/src-hunter-skill/blob/main/README.en.md
23. **OWASP Cheat Sheet Series** — https://cheatsheetseries.owasp.org/
24. **Trail of Bits Security Research** — https://blog.trailofbits.com/
25. **Zero Day Initiative research blog** — https://www.zerodayinitiative.com/blog/
26. **Elastic Security Labs** — https://www.elastic.co/security-labs/blog

**Required traversal for every seed:** (a) fetch and inspect the seed itself; (b) identify pagination, feeds, sitemaps, and archive/category links; (c) enumerate article/report URLs from those mechanisms; (d) continue through every accessible page/cursor/batch; (e) fetch and study every eligible unique document; (f) record exact counts and evidence that the frontier is exhausted. Where a source requires JavaScript or an unsupported API, record the exact URL and limitation, then use another permitted route on that same source if available. Never label a source COMPLETE merely because its seed page loaded. Do not use generic Medium-wide crawling; only crawl the configured Trickster0 profile and eligible content linked from it under the existing source policy. GitHub search results are discovery leads, not proof that every matching repository or file was studied.

Do not silently skip any source ID returned by the runtime registry. The current implementation can safely crawl only sources in `RESEARCH_SOURCES` (including their configured allowed hosts); there is no runtime tool that permanently registers an arbitrary new host. If external research surfaces another useful source outside that registry, record it as an external-source gap with its URL, resource type, relevance, and exact reason it was not ingested; do not claim all of the public internet was searched. Adding it to the persistent workflow requires a reviewed source-registry/adapter/SSRF-allowlist change. Preserve the actual origin and document type: hosting on Medium or GitHub does not itself determine the type.

For each source, use its configured seed URLs, allowed hosts, source-specific adapter, pagination rules, feeds, sitemaps, and eligible links. Use only the existing safe fetcher and source-scoped authentication. Respect access controls, rate limits, source policies, and SSRF protections. Do not bypass authentication or broaden host allowlists to force a crawl.

Normalize URLs and strip credentials/sensitive query parameters before persistence. Persist discovery progress, outgoing links, content fingerprints, retries, authentication blockers, and crawl errors so work resumes after interruption. Detect pagination loops, repeated pages, duplicate URLs, and unchanged frontiers.

### No artificial total-work caps

Do not impose a fixed total limit on pages, links, reports, or resources. Per-call batch sizes and continuation windows are allowed only if the process continues in further batches until the accessible eligible frontier is exhausted or a concrete blocker is recorded. A batch size of 500 is not permission to stop after 500. Do not repeatedly refetch the same frontier without progress. Revisit changed content when its fingerprint changes.

A source is exhausted only when its accessible discovery frontier has been checked. If pagination cannot be proven complete, report uncertain/partial status. Do not claim the whole internet has been searched.

## 3. Fetch and study lifecycle

The current safe-fetcher also has a per-document byte ceiling (currently 1,500,000 bytes), redirect ceiling, and total fetch-time budget. These are transport/resource-safety guards, not global page or item limits. If a resource exceeds a transport guard, record it as blocked/partial with the exact reason; never silently treat a partial body as a complete study. The active-model queue uses terminal `blocked_size` for the safe-fetch document-size ceiling and `blocked_fetch` for other non-retryable safe-fetch errors (for example, unsupported content type, terminal HTTP errors, invalid queued URLs, or unsafe redirects); count and report both separately from irrelevant-content rejections and retryable network failures. If the user explicitly wants larger documents supported, implement safe streaming/chunking and tests rather than removing SSRF, timeout, redirect, or memory protections.

For each discovered candidate:

1. Validate protocol, host, URL normalization, and source provenance.
2. Fetch through the configured safe fetcher.
3. Detect authentication walls, deleted content, HTTP errors, and incomplete responses.
4. Extract the main article/document content and sanitize HTML.
5. Redact secrets before any content is stored or logged.
6. Compute a stable content fingerprint.
7. Detect unchanged content, duplicates, and changed versions.
8. Classify the document by its actual contents.
9. Study all accessible meaningful content, not only the title or search snippet. `research_study(action=next)` claims one resource per response and emits a bounded first text chunk; per-call size is not a total page/resource cap. When `has_more_text=true`, call `research_study(action=read)` with the exact `public_id` and `lease_owner`, setting its `offset` parameter to the previous response's `next_text_offset`, until the returned `has_more_text` is false. Read chunks in order; the durable read cursor blocks save/rejection while source text remains unread.
10. Extract structured facts, reusable techniques, evidence, prerequisites, limitations, and uncertainty.
11. Persist through the canonical knowledge API.
12. Read the record back from persistent storage and verify key fields and source relationships.
13. Verify that a relevant retrieval query can find the record.
14. Only then mark the queue item as successfully learned.

Do not confuse a queue status of `learned` with a vulnerability status of `confirmed`. A failed persistence or read-back must not produce a successful learning state. Keep failures retryable when appropriate and record the actual reason.

## 4. Document-type classification

Classification must use the actual content, not only the domain or configured source kind. Store the primary type and secondary types where a document contains multiple distinct kinds of material.

### Report

A specific vulnerability case or disclosure. Extract source URL, author when known, product/program when public, disclosure status, vulnerability class, CWE/CVE when supported, affected component/endpoint, prerequisites, attacker capability, reproduction, evidence, impact, root cause, remediation, and verification status. Distinguish observed, submitted, triaged, disclosed, independently reproduced, and unknown. Never invent confirmation or severity.

### Write-up

A research journey. Extract initial signal, hypothesis, ordered test attempts, positive and negative observations, rejected hypotheses, decisive clue, root cause if established, final outcome, and reusable discovery strategy. Do not rewrite failed tests as successful exploits.

### Blog

Concepts, advice, tools, design explanations, and techniques that may not document a real vulnerability. Extract the mechanism, assumptions, conditions of applicability, testing method, examples, limitations, false-positive risks, and defensive implications. Do not fabricate a real target or confirmed finding.

### Reference / Academy / Technical research

Extract concepts, prerequisites, lab or test method, expected positive/negative observations, tool configuration, limitations, and security implications. Keep educational lab outcomes separate from real-world vulnerability evidence.

Mixed content may yield multiple linked records, but every record must retain the original source relationship. A lack of a recognized vulnerability class must not by itself reject a useful general blog, reference, or research article.

## 5. Knowledge and pattern schema

Use existing database field names and APIs, extending the schema with migrations only where necessary. Do not create a parallel store. Map the following logical fields to the actual schema and document the mapping.

### Identity and provenance
- Stable knowledge ID; source ID/name; canonical source URL; author; publication/retrieval timestamps.
- Primary and secondary document types.
- Content fingerprint; extraction/study version.
- Source trust and explicit verification status.

### Technical classification
- Vulnerability class; CWE/CVE only when supported.
- Technology, component, attack surface, authentication and authorization context.
- Required capabilities and prerequisites.
- Phase relevance, trigger signals, tags, and classification confidence.

### Reusable pattern
- Pattern ID/name and concise summary.
- Security assumption and trigger signal.
- Preconditions and attack hypothesis.
- Ordered test procedure and request mutations.
- Expected positive and negative signals.
- Evidence and impact requirements.
- Validation steps and false-positive indicators.
- Failure conditions, limitations, remediation, and related pattern IDs.
- Provenance links to one or more source records and supporting passages.

### Investigation details
- Initial observation; hypotheses; attempted tests; successful tests; failed tests; rejected hypotheses; decisive evidence; root cause; reported outcome; verification status; unresolved questions.

### Retrieval and quality
- Search terms, keywords, tags, technology/endpoint/parameter/header/auth tags, phase tags, signal tags, applicability and non-applicability conditions.
- Evidence references, confidence, quality notes, duplicate/supersedes relationships.
- Seen/retrieved/useful/irrelevant/rejected counters and timestamps where supported.

Do not fill unknown fields with guesses or generic filler. A pattern is a reusable, evidence-backed test strategy, not merely a vulnerability name or payload string.

## 6. Quality and status semantics

### Explicit accept / reject / unresolved decision rubric

Make three separate decisions for every candidate; never collapse them into one opaque score:

1. **Access and processing status:** Was the source fetched safely, and was all accessible meaningful text read? Authentication walls, unsafe URLs/redirects, unsupported content, terminal HTTP errors, size ceilings, timeouts, parsing failures, unread chunks, and tool/model failures are access/processing states—not evidence that the article is irrelevant.
2. **Document relevance and type:** Classify the actual content as report, write-up, blog, academy, reference, research, mixed, or uncertain. Domain reputation and configured source kind are hints, not proof of type or relevance.
3. **Extracted-knowledge decision:** Decide learned, rejected, or unresolved/retry using the criteria below.

**LEARNED / accept** only when the full accessible content has been read; it contains at least one specific, reusable security lesson or pattern; the lesson is grounded in source text/evidence; source URL, content fingerprint, and actual document type are retained; uncertainty, applicability, and verification state are explicit; and persistence read-back plus a relevant retrieval query both succeed. A useful general blog, reference, academy lesson, or research article can be learned without a named vulnerability class, CVE, CWE, or real-world PoC.

**REJECTED** only after all accessible chunks have been read and the content is genuinely out of security scope, empty/boilerplate without security value, unusable after extraction, or a true duplicate with no incremental information. Every rejection needs a specific reason tied to the content; duplicate rejection should identify the duplicate record/fingerprint when available. Do not reject solely because there is no recognized vulnerability class, CVE/CWE, PoC, confirmed exploit, or real-target finding.

**UNRESOLVED / RETRY** when evidence is ambiguous or conflicting, content is incomplete/unread, extraction is uncertain, or a transient model/tool/network/database failure prevented a reliable decision. Do not turn uncertainty or infrastructure failure into a relevance rejection.

**BLOCKED** when a terminal access/transport condition applies: use the matching supported state such as authentication-blocked, `blocked_size`, or `blocked_fetch`. Keep blockers separate from irrelevant-content rejections and retryable errors; do not endlessly retry permanent blockers.

Track evidence quality, completeness, reusability, source trust, confidence, and runtime applicability independently. A reputable source does not automatically make every claim true. A report's stated outcome is not independent confirmation. A successful result on one target is not universal proof, and a failed test on one target does not disprove a technique globally. Never mark a record learned before durable persistence, read-back, and retrieval verification pass.


Track document classification, security relevance, completeness, evidence quality, reusability, source trust, confidence, and runtime applicability separately. Do not collapse them into one unexplained score.

A high-trust source does not make every claim true. A failed test on one target does not disprove a technique globally. A successful target-specific test does not confirm every source claim globally.

Use the existing queue and knowledge statuses consistently, including discovered, queued, studying, learned, retry, rejected, authentication-blocked, observed, useful, confirmed, disproven, and duplicate where supported. Every rejection must have a reason. Revisit records when the learning/extraction version changes.

Deduplicate URL identity, content fingerprints, knowledge records, and patterns separately. Preserve source provenance, distinct negative results, conflicting claims, verification status, and changed versions.

## 7. Exact local persistence

Use the existing database configuration and canonical persistence functions. The current known default candidate is `/root/.local/share/cyberstrike/cyberstrike.db`, but verify the active path before use. The safe fetcher also has a per-resource response-size ceiling; if a document exceeds that ceiling or cannot be safely extracted, report that resource as partial/blocked rather than claiming its complete contents were studied. This per-resource safety guard is distinct from the absence of total page/item caps.

The existing architecture includes a durable research queue and shared research knowledge represented by `report_knowledge` and related event records. Inspect actual migrations and schema before changing them. Do not assume that the table name alone proves the data is correctly persisted.

For each record:
1. Validate and sanitize the extracted content.
2. Validate source provenance and compute stable fingerprints.
3. Map fields into the actual schema.
4. Persist the knowledge and evidence relationships transactionally where supported.
5. Update queue state only after the required write succeeds.
6. Read the saved row back and verify identity, type, source URL, fingerprint, tags, metadata, and pattern/evidence fields.
7. Test retrieval from the canonical query/recommendation API.
8. Preserve restart/resume behavior.

Store readable filesystem artifacts only where the actual architecture calls for them. If the implementation uses a local knowledge directory, report its exact absolute path and purpose. Document which store is authoritative. Never save live credentials, session cookies, private keys, or unredacted secrets in knowledge or logs.

## 8. Runtime retrieval integration

Inspect actual methodology phases and every relevant retrieval consumer. Verify that learned knowledge is not merely stored but available to the appropriate agent.

- Recon: retrieve discovery write-ups, reconnaissance references, technology-specific patterns, endpoint/parameter discovery methods.
- Endpoint analysis: match route, method, parameter, content type, observed behavior, and relevant workflow/auth context.
- Authentication/authorization: retrieve relevant reports and write-ups with prerequisites, verification status, and evidence requirements.
- Unknown behavior: retrieve blogs, references, official documentation, and technical research.
- Validation: retrieve relevant reports/patterns to guide evidence collection; distinguish source examples from current-target evidence.

Return only relevant references, with a reason for each match. Preserve source URL, document type, matching signal/phase, applicability, confidence, verification state, and limitations. Never dump the entire database into every agent context. Keep global research separate from target-specific observations and secrets.

Where supported, record which references were retrieved and whether they were later useful, irrelevant, disproven, or untested. Target-specific outcomes must not silently rewrite global truth.

## 9. Failure handling and resumption

Record source/resource, operation, timestamp, failure category, safe error summary, retry eligibility/count, next action, and completion impact. Distinguish network/HTTP failures, authentication, rate limits, source restrictions, parsing, invalid URLs, unsupported pagination, classification, study, persistence, read-back, and retrieval failures.

Retry transient errors safely; do not retry permanent errors forever. Persist retryable work. Resume from durable state. Do not mark a source complete when unresolved blockers undermine that claim.

## 10. Verification and final report

Verify discovery, classification, learning, persistence, and runtime retrieval separately.

The final report must include:

1. Execution summary, time window, install/configuration/database paths, and status.
2. A per-source table with discovery method, pages/frontier processed, candidates, new queue entries, existing duplicates, learned, skipped/rejected, retries, authentication blockers, errors, and exhaustion evidence.
3. Classification counts for reports, write-ups, blogs, academy/reference, technical research, mixed, and uncertain.
4. Knowledge and pattern counts, updates, duplicates, provenance coverage, and validation criteria coverage.
5. Exact local storage manifest with paths, tables, responsible read/write APIs, counts, and verification results.
6. Methodology/agent consumers inspected and retrieval tests performed.
7. Initial/final counts and deltas with explanations.
8. All unresolved failures, evidence, impact, retryability, and next action.
9. Final status: COMPLETE, PARTIAL, or BLOCKED.

Use COMPLETE only when accessible source frontiers were verified, eligible work was processed, persistence/read-back passed, and representative retrieval tests passed. Use PARTIAL when work succeeded but any source, persistence, or retrieval blocker remains. Use BLOCKED when a critical dependency prevents meaningful completion.

## Non-negotiable constraints

- No artificial total caps on pages/resources/study work.
- No fabricated content, findings, confirmation, or completion claims.
- No collapsing reports, write-ups, blogs, and references into one undifferentiated type.
- No lost provenance, negative evidence, or uncertainty.
- No marking a record learned before required persistence verification.
- No claiming retrieval works without testing the real retrieval path.
- No parallel accidental database or silent storage fallback.
- No silent source skips or swallowed errors.
- No secret leakage.
- No treating a target-specific result as universal proof.

Start with a factual audit of the actual local installation and code. Execute all available steps, continue through batches until exhaustion or a recorded blocker, and report only verified outcomes.

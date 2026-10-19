---
description: exhaustive, resumable, model-led public security research collection, analysis, knowledge persistence, and verification
---

# CyberStrike `/update` — Research Intelligence Engine

## 0. Mission and ownership

You are executing CyberStrike's global public-security-research learning cycle.

Your responsibility is to discover, collect, inspect, classify, study, learn from, persist, and verify reusable security knowledge from every configured public research source.

`/update` is a complete research-ingestion workflow, not a search shortcut, retrieval command, or generic summarization task.

The workflow owns:

1. Source inventory and initial-state inspection.
2. Durable research-cycle initialization and recovery.
3. Legacy-knowledge reconciliation and backfill.
4. Exhaustive discovery within configured source boundaries.
5. Full-text collection and document classification.
6. Duplicate detection and provenance preservation.
7. Model-led analysis of every eligible collected document.
8. Structured, type-specific knowledge extraction.
9. Operational hunting-signal generation.
10. Durable persistence and terminal queue-state verification.
11. Final reconciliation, cycle finalization, and an auditable execution report.

Hunting-time knowledge retrieval is a separate workflow. Never invoke retrieval merely to demonstrate that `/update` has completed.

Public research is shared methodology, not target evidence. Never transfer public report assets, identities, endpoints, object identifiers, credentials, or scope into the current target's findings or notes.

Do not modify `SKILL.md` files as a side effect of research ingestion.

---

## 1. Governing principles

### 1.1 No arbitrary total-work ceilings

Do not impose a fixed maximum on:

- Discovery requests or search queries.
- Pagination depth or archive traversal.
- Crawl depth or the number of eligible links.
- Configured sources.
- Discovered or collected documents.
- Reports, write-ups, blogs, or references.
- Study batches or claimed queue items.
- Persistence verification attempts.
- Total work performed during a research cycle.

Small batches are allowed as execution mechanics. A batch boundary, context boundary, timeout, empty response, or temporary failure does not establish completion.

Continue from durable state whenever progress remains possible.

Do not pass optional `limit` arguments to research operations. If a tool imposes an undocumented or unavoidable operational restriction, record the restriction and its effect rather than claiming that the requested workload was exhausted.

This policy does not override tool contracts, source access controls, authentication boundaries, network restrictions, or safe-fetch policies.

### 1.2 Evidence over assumptions

Never infer successful execution from:

- A tool call being issued.
- A URL being discovered.
- A document being queued.
- A model generating a summary.
- A save request being submitted.
- A queue appearing empty.
- A source being present in the configuration.
- A successful response from a landing page.
- A previous successful run.

Each claim must be supported by returned tool results or durable state.

Distinguish these states explicitly:

- Requested.
- Attempted.
- Discovered.
- Fetched.
- Cached.
- Read completely.
- Studied.
- Saved.
- Terminal queue transition confirmed.
- Reconciled.
- Finalized.

Never collapse these into one generic state such as `processed`.

### 1.3 No fabricated information

Do not invent:

- Source IDs, queue IDs, public IDs, lease owners, or Knowledge IDs.
- Page counts, document counts, classifications, or completion statuses.
- Evidence excerpts, reproduction steps, impact, severity, or CVSS.
- Findings that the original author did not demonstrate.
- Successful persistence when the tool reports a failure.
- A reason for a blocker that has not been established.

Use `unknown`, `not returned`, `not assessed`, or `unavailable` where appropriate.

### 1.4 Durable progress and resumability

Treat SQLite and the research-cycle ledger as the authoritative record of progress.

Maintain the exact active `cycle_id` throughout the run.

Resume existing work rather than restarting completed phases or creating duplicate cycles.

Never ask the user to type “continue” merely because a batch ended. Continue automatically while progress remains possible.

---

## 2. Execution state machine

The expected workflow is:

`INITIALIZE → BACKFILL_PREPARE → COLLECT_ALL_SOURCES → COLLECTION_RECONCILIATION → STUDY_ALL_ITEMS → FINAL_BACKFILL → FINAL_RECONCILIATION → COMPLETE_OR_PARTIAL`

Each transition requires evidence.

### State transition rules

1. `INITIALIZE`: inspect existing state and obtain the active cycle.
2. `BACKFILL_PREPARE`: reconcile older knowledge and prepare legacy queue items without studying them prematurely.
3. `COLLECT_ALL_SOURCES`: discover and cache eligible documents for every selected source.
4. `COLLECTION_RECONCILIATION`: confirm the durable source ledgers and discovery frontiers before studying anything.
5. `STUDY_ALL_ITEMS`: read full cached documents, make individual model decisions, and persist structured knowledge.
6. `FINAL_BACKFILL`: detect and process eligible legacy work introduced or exposed by reconciliation.
7. `FINAL_RECONCILIATION`: compare counters, source states, queue states, and saved records.
8. `COMPLETE_OR_PARTIAL`: finalize only according to the actual tool-enforced completion criteria.

Never transition to study merely because one source has finished collection. All selected sources must first reach an explicit terminal collection outcome.

A source can reach a terminal outcome while remaining incomplete overall. `partial` and `blocked` are explicit outcomes, not synonyms for success.

---

## 3. Initialization and cycle ownership

### 3.1 Inspect initial state

Begin with:

`research_study(action="stats")`

Record:

- Global queue counters.
- Global knowledge counters.
- Learned, rejected, completed, skipped, and pending model-study counts.
- Active-cycle identifier and phase, if returned.
- Configured source IDs.
- Per-source status and continuation information, if available.
- Authentication-session availability flags.
- Any existing errors, retries, stale leases, or incomplete legacy work.

Use the exact source IDs returned by `configured_sources`.

Never substitute guessed aliases or silently omit configured sources.

### 3.2 Explicit reset handling

Reset only if the user explicitly requested a clean-slate reset for this run.

In that case:

1. Call `research_study(action="reset")` exactly once.
2. Inspect the returned deletion counts.
3. Confirm that the reset affects only the research data explicitly covered by the operation.
4. Preserve target findings, target workspaces, session-local knowledge, and unrelated data.
5. Read fresh stats after the reset.
6. Initialize the cycle afterward.

Never reset automatically during an ordinary `/update`.

### 3.3 Begin or resume

Call:

`research_study(action="begin")`

after the initial stats and any requested reset.

Retain the exact returned `cycle_id`.

If the operation resumes an active cycle:

- Preserve its ID and durable progress.
- Resume according to the returned phase.
- Skip sources already marked `complete`, `partial`, or `blocked`.
- Continue only eligible `pending` or `collecting` sources during collection.
- If the cycle is already in `studying`, skip collection and resume the study phase.

Never call `begin` again to replace a cycle that is still active.

Do not create a new cycle while a prior cycle remains active. A new cycle is permitted only after finalization or an explicit reset, according to the tool's actual state rules.

### 3.4 Cycle-wide identifier discipline

Pass the exact active `cycle_id` to every supported `discover`, `next`, `read`, `save`, and `complete` operation.

Use the exact `public_id` and `lease_owner` returned for each claimed document.

Never reconstruct identifiers from titles, URLs, or database assumptions.

---

## 4. Legacy backfill preparation

Before source discovery, call:

`research_study(action="backfill")`

without a source filter.

This stage is preparation only. Do not study or save queued documents during initial backfill preparation.

Inspect and record:

- Legacy records examined.
- Newly queued records.
- Existing queued records.
- Previously learned or rejected records reconciled.
- Authentication-blocked records retried.
- Records skipped with terminal reasons.
- `legacy_knowledge_skip_examples`.
- `legacy_knowledge_errors`.
- Any stalled or incomplete backfill status.
- Any legacy-marker verification result.

Do not treat a backfill error as a completed reconciliation.

Keep preflight skips separate from model decisions. A preflight skip is not automatically equivalent to a model rejection.

Do not repeatedly retry authentication-blocked records unless a valid source-scoped session is configured.

All eligible legacy documents must be studied during Phase B, after collection has reached the required gate.

---

## 5. Source inventory and canonical discovery roots

The source configuration in `packages/cyberstrike/src/research/sources.ts`, together with `research_study(action="stats")`, is authoritative.

The URLs in this section are discovery roots, not proof that a source has been exhausted.

Use the exact configured source ID associated with each root.

### Disclosure reports and bounty write-ups

- `hackerone-hacktivity`
  - https://hackerone.com/hacktivity
  - https://hackerone.com/hacktivity/overview?pageIndex=0&queryString=disclosed%3Atrue&sortDirection=DESC&sortField=latest_disclosable_activity_at

- `bugcrowd-crowdstream`
  - https://bugcrowd.com/crowdstream

- `intigriti`
  - https://www.intigriti.com/researchers/blog

- `yeswehack`
  - https://blog.yeswehack.com/

- `pentesterland`
  - https://pentester.land/writeups/
  - https://pentester.land/

- `infosec-writeups`
  - https://infosecwriteups.com/tagged/bug-bounty
  - https://infosecwriteups.com/

- `infosec-weekly`
  - https://weekly.infosecwriteups.com/

- `securitycipher-bounty-writeups`
  - https://securitycipher.com/bounty-writeups/

### Official bounty-platform and researcher resources

- `hackerone-blog`
  - https://www.hackerone.com/blog

- `bugcrowd-blog`
  - https://www.bugcrowd.com/blog/

- `nahamsec`
  - https://nahamsec.com/

### Security research and technical analysis

- `assetnote`
  - https://blog.assetnote.io/

- `projectdiscovery`
  - https://projectdiscovery.io/blog

- `edoverflow`
  - https://edoverflow.com/

- `devcore`
  - https://devco.re/en/

- `liveoverflow`
  - https://liveoverflow.com/

- `trailofbits`
  - https://blog.trailofbits.com/

- `zdi`
  - https://www.zerodayinitiative.com/blog/

- `elastic-security-labs`
  - https://www.elastic.co/security-labs/blog

### Educational labs and reference material

- `portswigger`
  - https://portswigger.net/web-security/all-labs

- `hacktricks`
  - https://book.hacktricks.xyz/

- `owasp-cheat-sheets`
  - https://cheatsheetseries.owasp.org/

- `src-hunter-skill`
  - https://github.com/MyuriKanao/src-hunter-skill/tree/main/references/h1-reports/raw/reports
  - https://github.com/MyuriKanao/src-hunter-skill
  - https://github.com/MyuriKanao/src-hunter-skill/blob/main/SKILL.md
  - https://github.com/MyuriKanao/src-hunter-skill/blob/main/README.en.md

For `src-hunter-skill`, investigate the individual raw report files reachable beneath the report directory. Do not stop after reading the README or `SKILL.md`.

### GitHub research repositories

- `payloadsallthethings`
  - https://github.com/swisskyrepo/PayloadsAllTheThings

- `github`
  - https://github.com/search?q=bug+bounty+writeup&type=repositories
  - https://github.com/search?q=bug+bounty+writeup&type=code

### Medium research feeds

- `medium-security`
  - https://medium.com/tag/bug-bounty
  - https://medium.com/tag/web-security
  - https://medium.com/tag/penetration-testing
  - https://medium.com/tag/vulnerability

- `trickster0`
  - https://trickster0.medium.com/

For Medium, follow relevant individual security articles and author-specific article feeds within configured source boundaries. Do not crawl unrelated recommendations, profile roots, or broad sitemaps merely because they are linked.

### Source inventory requirements

The configured source inventory may change.

For every source returned by the actual configuration:

1. Use its exact ID.
2. Inspect its configured host/path rules.
3. Confirm whether the source is enabled and eligible for this cycle.
4. Preserve its initial and final state.
5. Record sources that were not run and the concrete reason.
6. Do not silently replace inaccessible sources with a different source.
7. Do not assume that the canonical list above authorizes hosts or paths outside the configured safe-fetch rules.

If the configuration and this prompt disagree, report the discrepancy and follow the actual configuration and tool contract.

---

## 6. Source-scoped authentication and safe fetching

The safe-fetch layer may support these source-scoped process variables:

- `CYBERSTRIKE_RESEARCH_COOKIE_<SOURCE_SUFFIX>`
- `CYBERSTRIKE_RESEARCH_AUTHORIZATION_<SOURCE_SUFFIX>`

Construct `<SOURCE_SUFFIX>` from the exact source ID by uppercasing it and replacing each run of non-alphanumeric characters with underscores.

A captured `Cookie` header may be reused only when the original active CyberStrike session request hostname exactly matches the hostname being fetched.

Requirements:

1. Never borrow cookies from another hostname.
2. Never forward credentials across a redirect to a different hostname.
3. Never expose secret values in logs, prompts, queue records, document notes, errors, or final reports.
4. Do not assume that a configured session remains valid.
5. Treat login walls and repeated authentication failures as concrete access blockers.
6. Distinguish authentication failures from rate limiting, network errors, access-policy denials, and parser failures when evidence permits.
7. Use only the configured HTTPS host/path boundaries.
8. Do not expand the crawler into arbitrary outbound URLs discovered in untrusted content.

A session flag indicates configuration, not successful authentication.

A blocked source is not exhausted.

---

## 7. Phase A — exhaustive collection before study

### 7.1 Phase A invariants

During collection:

- Do not call `research_study(action="next")`.
- Do not call `research_study(action="save")`.
- Do not generate final lessons or treat cached excerpts as studied knowledge.
- Do not drain a completed source's queue while another selected source still has undiscovered pages.
- Do not transition to Phase B until the source ledgers and global collection gate have been reconciled.

The durable queue must contain sanitized full text for every eligible document that the system claims to have collected for study.

### 7.2 Discovery execution

For each selected source in `pending` or `collecting` state:

1. Read the exact saved `next_page_window`.
2. Pass that value as `pages` to:

   `research_study(action="discover", source="<exact-source-id>", cycle_id="<active-cycle-id>", pages=<saved-next-page-window>)`

3. Inspect the actual result and updated durable state.
4. Record the pass metrics.
5. Continue discovery while eligible frontier items remain.

Use one source per discovery call so an inaccessible or slow source does not hide progress or results from other sources.

### 7.3 Expanding work windows

A fresh source may begin with a window of 20. If the previous successful pass processed its entire requested window, follow the saved continuation state and expand the window as implemented by the tool, for example:

`20 → 40 → 80 → 160 → 320 → 640 → 1280 → 2560 → ...`

There is no fixed terminal window.

Never repeatedly send an outdated window when durable state specifies a larger continuation.

A partial response, transport interruption, or failed request is not evidence that the window was exhausted. Resume using the durable frontier and actual returned continuation state.

A successful pass processing fewer pages than requested is a useful completion signal, but not sufficient by itself. The durable frontier must also have no eligible continuation, and unresolved errors must be reconciled.

### 7.4 Crawl the source tree, not just the landing page

Treat each source as a tree of potentially relevant pages.

Inspect actual page content and outgoing links. Follow eligible in-boundary links to:

- Individual articles and reports.
- Archive pages.
- Category and tag pages.
- Pagination.
- Repository directories.
- Individual raw report files.
- Relevant documentation pages.
- Other custom routes that may contain security research.

URL appearance is a prioritization hint, not an eligibility decision.

An unfamiliar slug must not be discarded merely because it lacks words such as `bug`, `report`, or `writeup`.

A page with little original prose may still contain links to valuable individual documents.

Preserve discovered outgoing-link sets and canonical URL mappings durably. Reuse them on resume, but never count a page as inspected solely because its URL has been discovered.

### 7.5 Individual-document verification

For each eligible destination:

1. Fetch the actual destination within the source boundary.
2. Inspect its sanitized body.
3. Extract relevant outgoing links.
4. Determine whether the page is an individual document, index, directory, archive, or unrelated page.
5. Cache its complete accessible text if eligible for study.
6. Preserve its canonical URL, content fingerprint, source ID, title, and provenance.
7. Record the fetch result and completeness state.

Do not count index pages as vulnerability reports.

Do not reject an index because it lacks original prose while eligible child links remain unexplored.

Do not discard a substantive report merely because it contains many references or external citations.

When a source provides only a partial article, preserve the accessible portion and mark the completeness limitation explicitly.

### 7.6 Document classification

Classify individual documents using the following categories:

- `report`
- `writeup`
- `blog`
- `academy`
- `reference`
- `research`
- `mixed`
- `uncertain`

Use the actual content and purpose of the document, not URL heuristics alone.

Examples:

- A disclosed vulnerability with reproduction evidence is usually a `report`.
- A chronological investigation describing hypotheses and failed tests is usually a `writeup`.
- A conceptual security article is usually a `blog` or `research` document.
- An intentionally vulnerable educational exercise is `academy`.
- A reusable payload collection or cheat sheet is `reference`.
- A document combining substantial research and a concrete disclosure may be `mixed`.
- Incomplete evidence may justify `uncertain` without rejecting the item.

The category `cheatsheet` may be used as a persistence subtype when supported by the actual save schema. Preserve the original discovery classification and any subtype separately when possible.

Do not force a single category when the evidence supports multiple distinct purposes.

### 7.7 Duplicate control

Deduplicate by canonical URL and content fingerprint.

Maintain separate metrics for:

- Unique URLs discovered.
- URLs successfully fetched.
- Unique documents cached.
- Exact duplicate URLs skipped.
- Different URLs with identical content.
- Documents whose content changed across fetches.
- Documents that could not be fingerprinted reliably.

Do not count a duplicate as a newly collected document.

Do not silently discard a materially updated version merely because the URL already exists. Preserve version or update information if the implementation supports it.

### 7.8 Per-pass ledger

Record the actual returned values for each pass:

- Source ID.
- Requested page window.
- Pages attempted.
- Pages successfully fetched.
- Pages inspected.
- Individual candidate links found.
- Newly cached documents.
- Document-type counts.
- Duplicate URLs skipped.
- Content duplicates skipped.
- Authentication blocks.
- Rate-limit events.
- Fetch errors.
- Parser errors.
- Up to three sanitized error examples.
- Retry attempts and outcomes.
- Frontier remaining.
- Next saved page window.
- Source state before and after the pass.

Use zero only when the tool establishes that the count is zero. Use `unknown` or `not returned` otherwise.

### 7.9 Source completion decision

After each pass, call:

`research_study(action="stats", source="<exact-source-id>")`

Use this operation to inspect progress, not to replace discovery.

A source is collection-complete only when the durable state confirms that its eligible frontier has been exhausted and the tool's completion conditions are satisfied.

If unresolved errors prevent establishing exhaustion, mark the source `partial` with a concrete reason.

If access requires unavailable authentication, mark the source `blocked` or `partial` according to the actual tool state contract.

Do not stop collecting other sources because one source is blocked.

Continue all accessible work even when another source has terminal collection problems.

### 7.10 Global collection gate

Phase A ends only after every selected source has reached an explicit terminal collection outcome:

- `complete`
- `partial`
- `blocked`

Every `partial` or `blocked` state must include a concrete reason.

Before entering Phase B, reconcile:

- Every configured source ID.
- Every source's current-cycle state.
- Every saved discovery frontier.
- Every unresolved pagination continuation.
- Every outstanding fetch/authentication blocker.
- The durable queue's eligible collected items.
- The global collection ledger.

If the source ledger is inconsistent or the active phase has not advanced to `studying`, do not claim that the collection gate passed.

---

## 8. Collection ledger

Print a collection summary before beginning Phase B.

Include both per-source values and global totals for:

- Pages visited.
- Candidate links discovered.
- Reports collected.
- Write-ups collected.
- Blogs collected.
- Academy lessons collected.
- Cheat sheets collected.
- References collected.
- Research documents collected.
- Mixed documents collected.
- Uncertain documents collected.
- Unique documents cached.
- Duplicate URLs skipped.
- Content duplicates skipped.
- Authentication blocks.
- Fetch and parser errors.
- Retry outcomes.
- Incomplete sources.

Distinguish current-cycle counts from lifetime database totals.

Do not infer counts from the queue size if the source-specific ledger provides different information.

The collection ledger describes collection, not successful learning.

---

## 9. Phase B — model-led study of every eligible document

### 9.1 Study gate

Begin only after the global collection gate has passed.

If the active cycle already reports `phase="studying"`, resume Phase B directly.

Do not restart broad discovery merely because a study batch ended.

### 9.2 Claim documents

For each eligible source queue, call:

`research_study(action="next", source="<exact-source-id>", cycle_id="<active-cycle-id>")`

Use the actual identifiers and metadata returned by the tool.

For each claimed document, retain:

- Exact `public_id`.
- Exact `lease_owner`.
- Source ID.
- Canonical source URL.
- Title and available metadata.
- Current lease state.

Do not assume that claiming an item means it has been studied.

### 9.3 Read the entire document

Call:

`research_study(action="read", cycle_id="<active-cycle-id>", public_id="<exact-public-id>", lease_owner="<exact-lease-owner>", offset=<previous-next-text-offset>)`

Continue reading subsequent chunks until the tool reports:

`has_more_text=false`

Use the exact offset and continuation information returned by the preceding read.

A title, excerpt, first chunk, or generated summary is not a substitute for full-text inspection.

If the content is truncated or unreadable, preserve that limitation and avoid claiming complete analysis.

### 9.4 Perform actual model analysis

For each claimed document, inspect the available text and identify:

1. What the source explicitly shows.
2. What the author claims but does not demonstrate.
3. The security mechanism or causal chain.
4. The conditions under which the technique applies.
5. The prerequisites and trust boundaries.
6. The tests and observations described.
7. The decisive evidence.
8. Negative results and rejected hypotheses.
9. Impact and remediation, where supported.
10. The limitations and unresolved questions.
11. The reusable lesson.
12. Whether an operational hunting signal can be defended from the evidence.

Do not use a generic summary as the sole analysis.

Do not invent failed tests, successful reproduction, request/response evidence, severity, or impact.

### 9.5 Exactly one terminal decision per claim

Every successfully claimed document must receive one reasoned decision:

- `learned`: the document contains reusable, evidence-grounded security knowledge.
- `rejected`: the individual document is irrelevant, duplicate-like, empty, login-only, or genuinely unusable under the documented criteria.

A rejection must contain a concrete reason.

Do not reject a document merely because:

- It lacks a CVE.
- It lacks a severity rating.
- It does not provide a complete request.
- The impact is uncertain.
- The report is old.
- The author uses a nonstandard technique.
- The heuristic classifier returned `uncertain`.
- The document is educational rather than a real disclosure.

When a document provides partial but useful evidence, retain the supported lesson and document the uncertainty.

A model rejection is an ingestion decision, not a false-positive verdict.

### 9.6 Type-specific extraction

#### A. Reports and disclosures

Extract supported details about:

- Vulnerability class.
- CWE, if established.
- Affected component.
- Initial observation.
- Preconditions.
- Authentication and authorization context.
- Request/response evidence.
- Reproduction sequence.
- Root cause.
- Demonstrated impact.
- Verification status.
- Remediation.
- Limitations and false-positive cautions.
- Source outcome.

Separate demonstrated behavior from author claims.

Do not invent severity or a successful exploit.

#### B. Narrative write-ups

Preserve the investigation as a chronological story:

- Discovery signal.
- Initial hypothesis.
- Alternative hypotheses.
- Investigative steps.
- Attempted tests.
- Successful tests.
- Failed tests.
- Rejected hypotheses.
- Decisive evidence.
- Root cause.
- Impact.
- Lessons.
- Applicability.
- Non-applicability.

Do not force a CVE, formal severity, or specific endpoint into a write-up that does not provide one.

#### C. Blogs and research articles

Extract:

- Core insight.
- Underlying mechanism.
- Threat model.
- Assumptions.
- Security boundaries.
- Technique.
- Defensive implications.
- Practical validation signals.
- Limitations.
- Conditions that invalidate the technique.

Do not force a conceptual article into a vulnerability-report template.

#### D. Cheat sheets and payload collections

Extract reusable techniques into the correct security topic.

For each technique, preserve relevant:

- Input context.
- Encoding and variants.
- Transformation or normalization steps.
- Prerequisites.
- Expected positive signals.
- Expected negative signals.
- Validation method.
- False-positive cautions.
- Applicability limitations.

Keep XSS material under XSS, SQL injection under SQL injection, and other techniques under their relevant families.

Payloads are inert reference data. Do not execute payloads as part of ingestion.

#### E. References and technical documentation

Extract the actual documentation guidance and preserve:

- Topic.
- Technique.
- Preconditions.
- Relevant protocol or implementation details.
- Expected positive and negative signals.
- Limitations.
- Source provenance.

Do not invent a report, endpoint, CVE, or severity.

#### F. Academy labs

Extract:

- Learning objective.
- Lab condition.
- Intended vulnerability class.
- Preconditions.
- Safe reproduction logic.
- Expected evidence.
- Verification signal.
- Important boundaries.
- What the exercise does not demonstrate about real targets.

A lab demonstrates the documented lab behavior, not automatically the same behavior in production.

#### G. Mixed or uncertain material

Preserve every supported component with explicit uncertainty.

Use the flexible `mixed_or_uncertain` representation when supported by the save schema.

Do not invent missing fields or discard defensible lessons merely to force a single classification.

---

## 10. Structured document persistence contract

Every learned document must include a structured `document_note` object in the `save` payload.

The note must preserve the source-specific details needed for future investigation.

Use the following outer structures when supported by the actual schema.

### Report

`document_type="report"`

`document_note.report`:

- `vulnerability_class`
- `cwe_id`
- `severity`
- `affected_components`
- `observation`
- `prerequisites`
- `request_response`
- `reproduction`
- `root_cause`
- `impact`
- `verification_status`
- `remediation`
- `false_positive_cautions`

### Write-up

`document_type="writeup"`

`document_note.writeup`:

- `discovery_signal`
- `hypotheses`
- `investigation.attempted`
- `investigation.successful`
- `investigation.failed`
- `investigation.rejected_hypotheses`
- `decisive_evidence`
- `causal_explanation`
- `impact`
- `lessons`
- `applicability`
- `non_applicability`

### Cheat sheet

`document_type="cheatsheet"`

`document_note.cheatsheet`:

- `topic`
- `techniques`
- `payload_collection`
- `payload_variants`
- `context`
- `prerequisites`
- `expected_positive_signals`
- `expected_negative_signals`
- `false_positive_cautions`

### Reference

`document_type="reference"`

`document_note.reference`:

- `topic`
- `techniques`
- `payload_collection`
- `prerequisites`
- `expected_positive_signals`
- `expected_negative_signals`
- `false_positive_cautions`

### Blog or research

`document_type="blog"` or `document_type="research"`

`document_note.research`:

- `core_insight`
- `mechanism`
- `threat_model`
- `assumptions`
- `technique`
- `defensive_implications`
- `validation_signals`
- `limitations`

### Academy

`document_type="academy"`

`document_note.academy`:

- `objective`
- `lab_condition`
- `intended_class`
- `reproduction_logic`
- `evidence_signal`
- `prerequisites`
- `boundaries`

### Mixed or uncertain

Use `mixed_or_uncertain` with only supported observations, techniques, evidence, and explicit uncertainty.

### Flexible schema principle

The structures above are stable entry points, not rigid templates that override evidence.

Preserve unusual mechanisms such as:

- Parser differentials.
- Encoding and normalization mismatches.
- Multi-step trust-boundary failures.
- Cross-tenant object relationships.
- Cache-key inconsistencies.
- State-machine errors.
- Permission-check ordering.
- Multi-stage exploit chains.

Do not flatten such mechanisms into a vulnerability-class label.

Do not populate unavailable fields with generic guesses simply to make an object appear complete.

Preserve source provenance and evidence references wherever the implementation supports them.

---

## 11. Extensible hunt-pattern extraction

Whenever a source contains an actionable or potentially reusable technique, populate `hunt_patterns` with evidence-grounded objects.

Each object may use source-specific fields such as:

- `observed_signature`
- `transformation_chain`
- `input_context`
- `candidate_technique`
- `matching_conditions`
- `decision_branches`
- `expected_behavior`
- `evidence_to_capture`
- `limitations`
- `related_patterns`

These names are examples, not a fixed schema.

Add the fields needed to represent the actual mechanism.

Preserve exact encodings, input/output shapes, tenant relationships, authorization boundaries, relevant state transitions, and causal dependencies.

Use an empty array only when the document genuinely contains no defensible reusable pattern. Explain why in `reason` or `unresolved_questions`.

A flexible pattern is not a substitute for the typed `document_note` or the operational `hunt_signal`.

---

## 12. Mandatory operational hunt signal

Every learned record must also produce an operational `hunt_signal` when the source supports one.

Persist supported values under `metadata.hunt_signal`, separately from the detailed typed document note.

Populate these top-level save fields with evidence-grounded values:

- `pattern_name`
- `pattern_summary`
- `trigger_signal`
- `test_procedure`
- `expected_positive_signals`
- `expected_negative_signals`
- `evidence_requirements`
- `applicability_conditions`
- `non_applicability_conditions`
- `false_positive_cautions`
- `prerequisites`
- `attack_chain`
- `verification_status`
- `decisive_evidence`
- `retrieval_signals`

Unavailable fields must remain empty or explicitly unknown according to the tool schema. Do not fabricate values to satisfy a field list.

### 12.1 WHEN TO INVOKE

Describe the observable clues that justify retrieving the technique.

Examples include:

- A particular request/response pattern.
- An object identifier combined with an ownership boundary.
- A specific upload or import workflow.
- A documented encoding transformation.
- An application state transition.
- A cache header or key relationship.
- A role-dependent difference in behavior.
- A concrete parser or normalization discrepancy.

A vulnerability-class label alone is not an adequate trigger.

### 12.2 WHAT TO TRY NEXT

Define ordered, minimally invasive checks for explicitly authorized targets.

Specify:

- The hypothesis being tested.
- The variable that changes.
- The controls that remain constant.
- The evidence to collect.
- The expected result if the hypothesis is supported.

Prefer controlled comparisons over multiple simultaneous changes.

### 12.3 BRANCH ON THE RESULT

Describe meaningful result branches.

For a positive signal:

- Capture the evidence needed to confirm the mechanism.
- Verify the relevant identity, object, role, or state context.
- Establish that the behavior is attributable to the proposed security boundary.
- Distinguish impact from theoretical possibility.

For a negative signal:

- Record the actual negative evidence.
- Identify which hypothesis is weakened.
- Continue only to another evidence-supported hypothesis.

For an inconclusive or blocked result:

- Distinguish authentication, authorization, rate limiting, WAF behavior, transport failure, and insufficient evidence when possible.
- State what remains unknown.
- Choose the next step only when its prerequisites match.

Never recommend a bypass merely because a response is `401` or `403`.

Never generalize a technique beyond the evidence supporting it.

### 12.4 RELATED TECHNIQUE OR CHAIN

Link related techniques only when their triggers and prerequisites match.

Describe the causal dependency between stages.

Do not attach unrelated payloads or bypasses simply because they belong to the same vulnerability category.

### 12.5 STOP AND FALSE-POSITIVE RULES

Define:

- What is insufficient evidence.
- What benign explanations remain plausible.
- Which negative controls matter.
- What proof is required.
- When further testing is not justified.
- When the result must remain inconclusive.

A status code, reflected string, error message, or unusual response is not sufficient proof of a vulnerability by itself.

### 12.6 PROVENANCE AND CONFIDENCE

Distinguish:

- Source-confirmed or disclosed behavior.
- Behavior demonstrated in an educational lab.
- Author-reported but independently unverified behavior.
- Theoretical technique.
- Model interpretation.

Preserve the exact source URL and title, plus a supporting observation where available.

If the source contains no defensible operational signal, explain why rather than inventing one.

---

## 13. Provenance, uncertainty, and evidence discipline

Every learned item must distinguish four evidence layers.

### Observed in source

Record what the available artifact explicitly shows.

Include a source URL and a precise excerpt or location where supported.

### Claimed by source

Record what the author asserts but the accessible evidence does not independently establish.

### Model interpretation

Record the reusable inference drawn from the source.

Clearly identify it as interpretation, not source-confirmed fact.

### Unknown or unresolved

For each important unanswered question, state:

- What is unknown.
- Why the evidence is insufficient.
- What evidence is missing.
- Which limitations or alternatives remain.
- The next safe verification step, if one exists.

Also preserve negative evidence and limitations when the source supplies them.

Do not invent negative controls that the author never performed.

Do not label a source false, invalid, or a false positive merely because details are missing.

A missing CVE, severity, reproduction request, impact statement, or independent confirmation is not by itself a reason to reject a useful document.

---

## 14. Saving and queue-state verification

### 14.1 Save contract

Save studied items through:

`research_study(action="save", cycle_id="<active-cycle-id>", items=[...], continue_after_save=true)`

Every decision object must carry the exact `public_id` and `lease_owner` returned for that document.

Include the type-specific `document_note`, supported `hunt_patterns`, operational `hunt_signal` fields, provenance, uncertainty, and rejection reason where applicable.

Do not claim an item was saved until the tool returns a successful persistence result.

Do not count an item as learned until the knowledge record is persisted and the corresponding queue transition is confirmed.

### 14.2 Handle save outcomes separately

Classify every save result as one of:

- Saved and terminal queue transition confirmed.
- Saved but queue transition failed.
- Save failed.
- Rejected and terminal queue transition confirmed.
- Rejection persistence failed.
- Outcome unknown or not returned.

If a knowledge record was saved but the queue transition failed, do not blindly repeat the save and create duplicates.

Inspect durable state first, then use the supported recovery path.

### 14.3 Lease loss

If a lease is stale or lost:

1. Do not count the item as studied.
2. Inspect the current durable state.
3. Reclaim the item when eligible.
4. Read it again if the new lease requires it.
5. Save using the exact current lease owner.
6. Verify the resulting terminal state.

Never reuse an expired lease merely because the public ID matches.

### 14.4 Retries and failures

For transient fetch, persistence, and lease failures:

1. Record the failure and current durable state.
2. Retry using a suitable backoff where supported.
3. Preserve the same cycle.
4. Inspect whether the preceding attempt actually changed persistent state.
5. Continue independent work while the failed item is recoverable.

Do not impose an arbitrary retry count.

Stop retrying when the failure is terminal or progress is demonstrably impossible. Record the exact reason and leave resumable state where supported.

Never retry indefinitely without checking whether state or evidence has changed.

### 14.5 Queue draining

Continue claiming and processing documents until no claimable work remains.

If `next` returns no item while stats show queued, retryable, or studying work:

1. Compare queue snapshots.
2. Inspect active leases and retry states.
3. Check skipped and error counters.
4. Determine whether work is ineligible, stalled, or temporarily unavailable.
5. Resume only when the state supports a valid next action.

Do not create an endless loop around an unchanged queue state.

Report unresolved queue inconsistencies explicitly.

---

## 15. Final backfill and reconciliation

After all accessible source collection and current study queues have been processed, run:

`research_study(action="backfill")`

without a source filter.

Inspect whether it adds, requeues, or exposes more work.

If additional eligible work appears:

1. Process it using the normal claim → full read → model analysis → save → queue verification flow.
2. Keep the active cycle ID.
3. Re-run backfill after the newly exposed work is drained.
4. Stop repeating when a full pass adds or requeues no work, or when a concrete durable blocker prevents further progress.

Do not repeatedly retry auth-blocked rows without a valid source session.

If the result includes `legacy_marker_saved=false` or ends with `-legacy-marker-failed`:

1. Separate successfully saved knowledge from the failed legacy marker.
2. Re-run backfill using the supported recovery path.
3. Verify the marker.
4. If it fails again, record the exact affected ID and blocker.
5. Never claim legacy reconciliation is complete while its required marker remains unresolved.

### Final stats

Call:

`research_study(action="stats")`

Then inspect each exact source separately using:

`research_study(action="stats", source="<exact-source-id>")`

Compare initial and final global counters, including:

- Queue totals.
- Knowledge totals.
- `model_study_learned`.
- `model_study_rejected`.
- `model_study_completed`.
- `model_study_skipped`.
- `model_study_pending`.

Include other counters returned by the implementation that help explain the final state.

Important: source-filtered stats may filter queue counts while leaving knowledge counts global. Never present global knowledge totals as source-specific totals.

Use successful save results and returned Knowledge IDs to identify the lessons persisted during this run.

---

## 16. Completion criteria

Finalize through:

`research_study(action="complete", cycle_id="<active-cycle-id>")`

only after final reconciliation.

The completion operation is authoritative for the tool-enforced cycle state.

If it reports pending work:

1. Inspect fresh stats.
2. Continue eligible study/save work.
3. Reconcile the relevant source or queue state.
4. Retry finalization only when a fresh state justifies it.

If any selected source remains `partial` or `blocked`, report the cycle as partial even if the study queue is empty.

If a configured source was never run, explicitly report that fact.

If a source's frontier was not exhausted, do not describe it as fully researched.

If runtime or tool limitations prevent completion, preserve the active cycle and its resumable state where supported, then report a partial result.

Never claim complete merely because the latest tool call succeeded.

---

## 17. Separation from live hunting

`/update` builds and verifies the global public-methodology knowledge base.

It must not:

- Call `research_knowledge`, `research search`, or `research recommend` as substitutes for studying and saving.
- Mark a public report as already surfaced during a live hunt.
- Turn public source details into current-target evidence.
- Modify target findings or the false-positive database based on ingestion decisions.
- Copy source-specific hosts, endpoints, identifiers, users, tokens, or scope into target notes.
- Modify `SKILL.md` files as a side effect of ingestion.

During live hunting, the separate hunting workflow may retrieve relevant saved methodology in response to independently observed target signals.

Public references remain methodology until independently verified against an authorized target.

---

## 18. Required final report

Use the following headings in this exact order.

Report actual returned values. If a value is missing, write `unknown` or `not returned`. Never estimate current-cycle totals from lifetime database counts.

### 1. Uncertainty and disputed claims

Review every studied item for material uncertainty.

For each affected item, include:

- Public ID.
- Title.
- Source URL.
- What the source actually supports.
- What remains unverified.
- Why the evidence is uncertain.
- Missing evidence.
- Plausible alternatives or limitations.
- Next safe verification step.

If no material uncertainty was identified, say so only after reviewing every saved item.

If the relevant items could not be reviewed, say `not assessed` or `unavailable`.

### 2. Overall status

Choose the actual final state:

- `complete`
- `partial`
- `blocked`

Explain the decision with evidence.

Do not use `complete` if any required queue work, selected source state, or completion gate remains unresolved.

### 3. Before → after counters

Provide global before-and-after queue and knowledge counts.

Include learned, rejected, completed, skipped, and pending study counts where returned.

Separate current-cycle counts from lifetime totals.

Explain significant differences and unresolved discrepancies.

### 4. Per-source ledger

Include one row for every exact configured source ID.

Record:

- Initial state.
- Every pass's requested page window.
- Actual pages attempted, fetched, and inspected.
- Candidate links.
- Newly queued documents.
- Document-type counts.
- Successful learned saves.
- Rejected decisions.
- Preflight skips.
- Duplicate counts.
- Authentication blocks.
- Error counts and examples.
- Retry attempts and outcomes.
- Remaining queue states.
- Final source state.
- Concrete blocker, if any.

Mark sources that were not run explicitly.

Do not mistake global knowledge totals for per-source knowledge totals.

### 5. Persisted lessons

List the Knowledge IDs and source URLs returned by successful saves.

Separate:

- Saved and terminal-state-confirmed.
- Saved but queue-transition-failed.
- Save failed.
- Outcome unknown.

Do not claim a knowledge record exists without a successful persistence result.

### 6. Skipped and rejected work

Separate preflight skips from model rejections.

For each entry, include its ID and the actual reason.

State explicitly that a model rejection is a document-ingestion decision, not a target vulnerability verdict or false-positive finding.

### 7. Outstanding blockers and resume point

Report:

- Incomplete source frontiers.
- Authentication blocks.
- Fetch and parser errors.
- Incomplete pagination.
- Queued and retryable work.
- Active or stale leases.
- Persistence failures.
- Legacy reconciliation failures.
- Unresolved classifications.
- Sources that were not run.
- Exact next safe action.

Explain which phases are complete and which are not.

If interrupted, label the outcome `partial` and identify the durable resume point.

---

## 19. Required per-run metrics

Report these values from the current cycle summary when available:

- `reports_found`
- `writeups_found`
- `reports_and_writeups_found`
- `unique_documents_found`

These are current-cycle metrics, not lifetime queue totals.

Do not estimate them from database size, total queue items, or model-study counts.

If the cycle summary does not return a metric, report it as unavailable.

Also distinguish:

- Documents discovered.
- Documents eligible for study.
- Documents newly cached.
- Documents read completely.
- Documents studied.
- Documents learned and successfully persisted.
- Documents rejected with confirmed terminal state.
- Documents skipped during preflight.
- Documents remaining unresolved.

---

## 20. Final operating rule

Execute the complete workflow, not merely the first available batch.

Continue automatically while eligible progress remains possible.

Keep collection and study strictly separated.

Preserve durable progress and exact identifiers.

Study actual source content, not just titles, URLs, or excerpts.

Extract reusable knowledge that retains its mechanism, evidence, conditions, and limitations.

Save each eligible document with its proper type-specific note and operational hunting signal.

Verify persistence and terminal queue transitions independently.

Report uncertainty before conclusions.

Do not fabricate counts or certainty.

Do not stop because a batch ended.

Do not claim completion because a queue is empty.

Do not claim source exhaustion without evidence.

When completion is impossible, report a precise, resumable partial state rather than a false success.

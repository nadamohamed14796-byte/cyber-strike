# CyberStrike Repository Repair Ledger

**Checkpoint timestamp:** 2026-10-12  
**Repository:** `nadamohamed14796-byte/cyber-strike`  
**Baseline `main`:** `7ff8bbe5a1bc931549bb1cefdd9bee8bd36245e3` (refreshed after PR #22 merged)  
**Working ref:** `main` (focused fixes committed directly; no per-fix branch created)  
**Execution limitation:** the runtime could not resolve `github.com` for a local clone, and Bun is not installed in the execution container. Repository inspection and edits are therefore being performed through GitHub's repository API; verification must use GitHub Actions for this branch. No local test result is claimed.


## Latest-main verification checkpoint — 2026-10-12

- **Latest verified code head (CI):** `71fe91869eb845398c4604eeaa105ce0886a4477`. The policy requires 20 distinct valid attempts before a false-positive/disproven verdict across both the durable verification ledger and `validate_finding`, excludes invalid-precondition attempts from the budget, keeps scope/safety hard stops dominant, normalizes legacy premature DISPROVEN rows, reopens legacy false-positive findings when current evidence is inconclusive, and gates VRT clean coverage on 20 valid attempts. The agent prompt was reconciled to avoid contradictory early-disproof wording. A SQLite regression test verifies legacy `target_workspace` owner-key backfill, stale-index replacement, cross-owner duplicate allowance, and same-owner duplicate rejection. On `71fe9186`, GitHub Actions unit tests, typecheck, monorepo build, and CodeQL all passed.
- **Latest-main GitHub Actions:** typecheck [38242067494](https://github.com/nadamohamed14796-byte/cyber-strike/actions/runs/38242067494), unit/integration tests [38242067491](https://github.com/nadamohamed14796-byte/cyber-strike/actions/runs/38242067491), build [38242067501](https://github.com/nadamohamed14796-byte/cyber-strike/actions/runs/38242067501), and CodeQL [38242067818](https://github.com/nadamohamed14796-byte/cyber-strike/actions/runs/38242067818) all completed successfully on current `main`.
- **Test detail:** 1,799 passed, 5 skipped, 0 failed across 1,804 tests in 148 files; a separate package-level suite reported 225 passed and 0 failed across 47 files.
- **Scope of claim:** this confirms automated CI on the recorded commit. It does not claim live Gmail/OAuth, external target validation, browser MFA, or manual runtime scenarios were exercised.


### PR disposition follow-up — 2026-10-12

- **PR #40** was closed without merging because it contained only a stale audit-ledger snapshot; the current ledger already contains the newer fixes and CI evidence. Closure comment added to the PR.
- **PR #7**: tree-level comparison found no branch-only paths among its 77 changed files. Current main already contains the paths and has newer versions of the 19 divergent blobs; no bulk merge was performed.
- **PR #6**: tree-level comparison found no branch-only paths among its 99 changed files. 61 blobs match main; 38 differ. The branch contains much longer versions of some skills, but longer does not automatically mean better: keep main's reconciled variants until unique procedures, safety controls, and references are compared section by section.

## Confirmed issues

| ID | Priority | Category | Root cause / evidence | Attempts | Status |
|---|---|---|---|---:|---|
| SEC-001 | P1 | Security / path confinement | Remote skill cache paths and archive extraction are constrained in current `main`; PR #18's parser failure is historical, not the current-main state. | 5 | resolved; current-main CI green |
| SEC-002 | P2 | Test and type contract | Tests call helpers through the `Discovery` namespace; current-main typecheck passed on code head `71fe91869eb845398c4604eeaa105ce0886a4477`. | 3 | resolved |
| INT-001 | P2 | Branch integration | PR #11 (`skills/import-phase-1-methodology-recon`) is a stale divergent snapshot. Compared its five added methodology/evidence/reporting/recon skills and migration documentation against current `main`; the reviewed files already exist on main, so no unique skill content remains to port from this snapshot. | 2 | resolved_superseded_no_merge |
| INT-002 | P2 | Branch integration | PR #7 (`feat/target-memory-foundation`) is 311 commits ahead / 190 behind, with 77 changed files. PR #17 integrated the feature set; current `main` has newer reviewed implementations, so no wholesale merge is safe. | 2 | blocked_no_bulk_merge |
| INT-003 | P2 | Branch integration | PR #6 (`improve/skill-quality-reference-audit`) is 159 commits ahead / 190 behind, with 99 changed files. PR #15's reconciled quality work is already merged; skill changes are out of scope for this pass and must not be merged wholesale. | 2 | blocked_out_of_scope_and_diverged |
| INT-004 | P1 | Branch integration / TLS safety | PR #2 (`hackbrowser-improvement`) is 44 commits ahead / 300 behind, with 36 changed files. Its launcher disables TLS certificate verification (`NODE_TLS_REJECT_UNAUTHORIZED=0`); do not merge wholesale. Review only isolated safe changes. | 2 | blocked_unsafe_to_merge_wholesale |

| FUN-001 | P2 | Archive download integrity | Remote downloads use bounded byte streaming and binary archives are written without text decoding. Current-main tests and build pass. | 1 | resolved |
| SEC-003 | P2 | Test/type contract | Tar entry properties are validated at runtime; current-main tests and typecheck pass. | 1 | resolved |
| SEC-004 | P1 | Path normalization | Archive path normalization now handles single backslashes and is covered by current safe-path checks; current-main tests and typecheck pass. | 1 | resolved |

## Baseline verification evidence

- Initial `main` commit: `eb9a1d1cc08a0d8c7595617878526b58e3f80128`; before refresh, `main` advanced to `7ff8bbe5a1bc931549bb1cefdd9bee8bd36245e3` through merged PR #22. The four code/manifest files being changed had identical Git blobs on both bases, so the repair was ported without overwriting intervening edits.
- GitHub Actions on that exact commit: `typecheck`, `test`, and `CodeQL` all completed successfully (runs 38225871885, 38225871954, 38225871923).
- PR #18 head `2a1f1e8492658bf3e50f95a5350c105ee8181759`: `typecheck` failed with TS1127/TS1005/TS1160 at `discovery.ts`; test/build failed with `Unexpected escaped backtick`. These are baseline failures for that PR, not failures introduced by this repair branch.

## Repair records

### SEC-001 / SEC-002 — remote skill cache confinement

- **Attempt 1 (reproduce/diagnose):** read the current `main` implementation and the complete PR #18 CI logs; confirmed that `skill.name` and `skill.files[]` fed filesystem paths before robust containment validation, and the PR's source contained escaped template-literal delimiters.
- **Attempt 2 (primary repair):** ported the mitigation to a new branch from current `main`; corrected escaped template literals/interpolation, included the missing archive helper import in tests, fixed the `get(url, dest, root)` call contract, removed the pre-validation parent-directory creation, canonicalized the cache root, rejected symlink/non-directory skill roots, and constrained archive entries to safe path/type combinations. Added the required `tar@7.5.7` package and lockfile entry.
- **Attempt 3 (integration correction):** GitHub typecheck on PR #23 (run 38227294532) found the `tar.t()` callback is typed as `ReadEntry | Stats`, and that tests imported namespace functions as top-level exports. Changed tests to call `Discovery.isSafeSkillName`, `Discovery.resolveSkillFilePath`, and `Discovery.isSafeArchiveEntry`.
- **Attempt 4 (alternative diagnosis):** the next typecheck (run 38227486303) still rejected `'type' in entry` narrowing for `ReadEntry | Stats`. Replaced the guard with runtime checks on a narrow `{ path?: unknown; type?: unknown }` view, requiring both fields to be strings before adding a tar member to the allow-list.
- **Historical verification note:** the earlier PR head failed typecheck/tests because of malformed template-literal escaping and incorrect helper imports. Those failures were corrected in subsequent commits; the current-main implementation has since passed unit tests, typecheck, build, and CodeQL. Do not use the historical PR-head failure as the current-main status.

## Branch / PR ledger (updated during execution)

- Repairs described below were committed directly to `main`; no per-fix feature branches were created.
- **PR #40 — audit-ledger refresh:** its 20-pass evidence and merged-fix summary are already represented in this ledger. The branch is 1 commit ahead / 64 behind and unmergeable; treat it as superseded rather than merging its stale snapshot.
- **PR #7 — target memory/auth/Gmail:** 311 commits ahead / 190 behind at the latest comparison. Preserve its history; reviewed feature paths are integrated through PR #17 and follow-up fixes, so no wholesale merge is safe.
- **PR #6 — skill-quality/reference audit:** 159 commits ahead / 190 behind; newer/reconciled skill content is on `main`. Skill files are out of scope for this pass; do not merge wholesale.
- **PR #2 — Hackbrowser improvement:** 44 commits ahead / 300 behind; the inspected branch disables TLS certificate verification. Do not merge wholesale.
- **No merge needed:** scope-check IPv4/CIDR, bounded WebFetch, non-mutating WebRecon probes, target-workspace owner-index reconciliation, and remote skill cache confinement are already represented on main with later hardening.
- **No unique commits relative to main:** `ci/monorepo-build-validation-20261012`, `fix/pr-management-fork-label-guard`, `fix/remote-skill-cache-confinement-main-20261012`, `improve/skill-quality-reference-audit-reconciled`, `feat/spa-nav-discovery`, and `stage` were reported as behind-only in the inspected comparisons.
- **Dependency branches:** the DOMPurify proposal was ported with its lockfile; the mysql2 proposal was superseded by a safer 3.23.1 update; the provider-utils branch's manifest versions already match main, while its lockfile snapshot is stale relative to main.
- **Retain for selective review:** `feat/discovery-core`, `feat/proxy-config`, `dev`, `fix/target-memory-owner-isolation`, and `fix/remove-orphan-auth-manager-typecheck-blocker` are divergent or contain older versions of code that main has since extended. `docs/idor-skill-expansion` and `skills/import-phase-1-methodology-recon` were rechecked against main; the reviewed skill additions already exist on main, so no further cherry-pick is required. Do not merge any of these branches wholesale.
- **Branch deletion:** no branches were deleted. The available GitHub actions in this execution context do not expose a safe branch-delete operation; unmerged divergent branches remain preserved to avoid losing unreviewed unique work.

## Branch / PR ledger (snapshot at baseline)

| PR | Branch | Baseline classification | Reason / next action |
|---:|---|---|---|
| #18 | `fix/audit-skill-discovery-path-confinement` | NEEDS_FIXES / NEEDS_REBASE_OR_UPDATE | Security-relevant work retained as a clean integration branch; old head fails typecheck and tests. |
| #11 | `skills/import-phase-1-methodology-recon` | DUPLICATE_OR_PARTIALLY_SUPERSEDED | Compare unique file deltas against merged #20/#21 and port only missing, validated content. |
| #7 | `feat/target-memory-foundation` | PARTIALLY_SUPERSEDED / NEEDS_DIFF_AUDIT | Related target-memory/global-learning/auth integration is already on main via #17; do not merge the 311-commit branch wholesale. |
| #6 (draft) | `improve/skill-quality-reference-audit` | SUPERSEDED / NEEDS_SELECTIVE_REVIEW | Reconciled audit PR #15 is already merged; preserve useful unique content only. |
| #2 | `hackbrowser-improvement` | NEEDS_FIXES / BLOCKED_PENDING_REVIEW | Very stale, broad behavioral changes; cookie removal already merged in #14; review in isolated chunks. |

## Twenty-pass audit ledger

These 20 review lenses were inspected through repository source/manifest/API review. Rows distinguish CI evidence from blocked live/local validation. This is not a claim that every possible execution path was exercised or that the 20-pass process is fully complete: passes with blockers explicitly retain the missing checks.

| Pass | Audit lens | Status | Evidence / remaining limit |
|---:|---|---|---|
| 01 | Repository integrity and completeness | PASS_WITH_BLOCKERS | Reviewed repository metadata, package manifests, AGENTS instructions, README, and the prior tree inventory (19,546 entries, 11,244 blobs, not truncated). Local clone/untracked-file status remains unavailable because shell DNS failed. |
| 02 | Architecture and dependencies | PASS_WITH_BLOCKERS | Traced root workspace/Turbo layout and imports between CLI, agent, prompt, tool registry, target memory, research and database. Local dependency-graph tooling was not run. |
| 03 | Type safety and runtime contracts | PASS_WITH_CI_EVIDENCE | Latest code checkpoint typecheck passed on `71fe91869eb845398c4604eeaa105ce0886a4477` (run 38248616677); previous feature-specific fixes also passed their final PR-head typechecks. No local typecheck was run. |
| 04 | Build and packaging | PASS_WITH_CI_EVIDENCE | Monorepo build passed on code checkpoint `71fe91869eb845398c4604eeaa105ce0886a4477` (run 38248616637). Local publishing and install smoke tests remain unrun. |
| 05 | CLI and configuration | PASS_WITH_BLOCKERS | CLI entry imports/registers TargetCommand, ResearchCommand and UpdateCommand. The commands expose target workspaces, research sync/search/queue and bounded update cycles. No local CLI help/run was possible without Bun. |
| 06 | Agent orchestration and lifecycle | PASS_WITH_BLOCKERS | Inspected agent tool policies and prompt lifecycle/context insertion, including TargetMemory and ResearchContext. Provider-backed sessions and resume/cancel flows were not exercised end to end. |
| 07 | Skill discovery and linkage | PASS_WITH_CI_EVIDENCE | Inspected cache confinement, bounded remote bodies, bounded gzip expansion, archive member filtering, SkillIndex, SkillContext and SkillTool. Current-main tests/typecheck/build/CodeQL all passed on code checkpoint `71fe91869eb845398c4604eeaa105ce0886a4477`; filesystem TOCTOU and full skill catalog coherence remain review items. |
| 08 | Tool registration and external execution | PASS_WITH_BLOCKERS | Inspected tool/registry.ts registrations for finding validation, research knowledge, target notes, JavaScript correlation, scope checks, and browser tools. No live scanner/browser/external-tool run was performed in this runtime. |
| 09 | Research ingestion | PASS_WITH_BLOCKERS | Inspected research ingest and safe-fetch controls: source host allow-list, manual redirects, DNS checks, streaming body limit, timeouts/retry bounds, and secret redaction. DNS check-to-connection rebinding resistance still needs independent runtime validation. |
| 10 | Knowledge quality and retrieval | PASS_WITH_BLOCKERS | Inspected ReportKnowledge, ResearchContext and research_knowledge prompt contract. External reports are explicitly untrusted references rather than evidence for the current target; actual retrieval quality needs live-provider evaluation. |
| 11 | Finding and evidence lifecycle | PASS_WITH_BLOCKERS | Inspected vulnerability reporting, evidence-gated candidate handling and the 20-distinct-attempt validation rubric. A candidate can be upgraded in place only with matching execution evidence; no target-side finding was tested. |
| 12 | Persistence, migrations and recovery | PASS_WITH_CI_EVIDENCE | PR #34 fixed owner-scoped target workspace indexes and legacy owner backfill. Current-main test/typecheck/build/CodeQL are green on code checkpoint `71fe91869eb845398c4604eeaa105ce0886a4477`; the focused legacy-schema regression test now covers owner-key backfill and owner-scoped index replacement, while a separate local existing-database migration simulation remains unavailable. |
| 13 | Scope enforcement and network safety | PASS_WITH_CI_EVIDENCE_AND_LIMITS | PR #36 changed scope_check to parse the actual URL hostname, validate IPv4 components and CIDR prefix, and reject arbitrary embedded-IP matches. Current-main CI is green on code checkpoint `71fe91869eb845398c4604eeaa105ce0886a4477`. This helper does not replace execution-boundary authorization. |
| 14 | Authentication, authorization and secrets | PASS_WITH_BLOCKERS | Inspected web-credential public-event projection, session-owned credential lookup and target-note redaction. PR #24 previously integrated credential event redaction; AD skill gates merged in #32. The unmerged Hackbrowser PR #2 sets NODE_TLS_REJECT_UNAUTHORIZED to 0 and is unsafe to merge as a whole. No real credentials were used. |
| 15 | Reconnaissance and discovery | PASS_WITH_BLOCKERS | Reviewed methodCheck and its test; main sends OPTIONS only and tests assert no TRACE, PUT or DELETE. The old feat/discovery-core branch sends those active methods and was not integrated. Live recon tools were not run. |
| 16 | Events, queues and background workflows | PASS_WITH_BLOCKERS | Reviewed research queue transactions, idempotent enqueues, leases, expired-lease reclaim and lease-owner completion; queue tests cover stale workers. Full multi-worker stress test was not independently run beyond CI. |
| 17 | Tests and CI integrity | PASS_WITH_CI_EVIDENCE | On current-main code checkpoint `71fe91869eb845398c4604eeaa105ce0886a4477`, typecheck, build, test and CodeQL passed. The test workflow reported 1,799 passed, 5 skipped, 0 failed across 1,804 tests in 148 files. Root test is intentionally disallowed by repository instructions; no local package tests were run. |
| 18 | Documentation and repository hygiene | PASS_WITH_BLOCKERS | Updated security methodology and audit ledger; inspected README/package metadata/AGENTS. Public upstream URL may be intentional and was left unchanged. Local git status, secret scan across untracked files, and automated formatting checks remain unavailable. |
| 19 | End-to-end workflow validation | BLOCKED_EXTERNAL_RUNTIME | Traced CLI research update to durable queue and ResearchContext injection; target notes and JS correlation have a linked path into session context. No live provider-backed hunt, full browser multi-account crawl, or authorized target-side workflow was executable here. |
| 20 | Independent adversarial review | PASS_WITH_BLOCKERS | Review uncovered target-memory uniqueness/index mismatch (fixed #34), IPv4-substring CIDR false match (fixed #36), and WebFetch unbounded body buffering/redirect permission gap (fixed #38). Unsafe active-method probing and disabled TLS verification were found only in unmerged branches and were not merged. Broad stale branches and local runtime remain blockers. |
## Completion policy

- Do not change an issue to `fixed_verified` until the final code on the relevant branch passes the required CI and integration checks.
- Do not merge stale branches merely because a related feature name appears in `main`; inspect unique diffs first.
- Do not claim the 20-pass audit is complete until every row has independent inspection/check evidence.


## Follow-up checkpoint — 2026-10-12: target workspace ownership reconciliation

### DB-001 — P1: stale target-workspace indexes can defeat owner isolation

- **Evidence:** `packages/cyberstrike/src/target/target.sql.ts` defines `owner_key` and owner-scoped indexes. Although the follow-up `20261011210000_target-workspace-owner-key/migration.sql` remains branch-only, current `Database.reconcile()` now adds missing columns, backfills owner keys for existing project-owned rows, assigns private legacy keys to old global rows where ownership cannot be inferred, drops stale project-scoped indexes, and creates owner-scoped indexes. The runtime behavior is selectively ported on `main`; do not merge the older branch wholesale.
- **Impact:** non-Git directories use `project_id = "global"`; a stale unique index on `(project_id, target_key)` can reject the same target in a second directory even though application lookups use an owner key. Existing rows added by schema reconciliation may also have `owner_key = "legacy:unscoped"`.
- **Repair strategy:** make startup reconciliation backfill non-global owners, isolate un-attributable legacy global rows using a per-row legacy key, remove obsolete indexes, and create the owner-key indexes idempotently. Do not blindly port the stale branch wholesale because its `target/index.ts` predates current path-confinement and secret-redaction hardening.
- **Regression coverage added:** `packages/cyberstrike/test/target/target-memory.test.ts` now verifies that two non-Git directories with the shared global Project ID can create distinct workspaces for the same target and cannot see each other's notes.
- **Historical note:** this was pending on the original branch when first recorded. The owner-index reconciliation was subsequently merged in PR #34 and its test/build/typecheck passed; current-main CI is also green. Local Bun execution and a separate pre-existing-database migration simulation remain unavailable.
- **Branch disposition:** `fix/target-memory-owner-isolation` is not safe to merge wholesale because its target implementation lacks current `ensureSafeDirectoryPath` and note-secret-redaction paths. The owner-key backfill and owner-scoped index replacement now exist in `main`'s reconciliation path; keep the branch only as a reference until a legacy-database regression test confirms the behavior.




## Verified merged fixes — 2026-10-12

### DB-001 — target workspace owner index reconciliation (PR #34)

- Merged as `c26ddbda91a76dadef3aa12c3faa603cc81f57f2`.
- Startup reconciliation backfills missing/legacy owner keys, gives ambiguous legacy global rows per-row private keys, drops old project-based target indexes and creates owner-based indexes idempotently.
- Regression coverage proves two non-Git directories sharing the global project ID can keep distinct workspaces for the same target and do not share notes.
- GitHub Actions on the final PR head passed test 38232995676, build 38232995678 and typecheck 38232995605.

### SEC-005 — scope_check IPv4/CIDR parsing (PR #36)

- Merged as `f043780b8d631819f85a95444dfc1e42a61edc0e`.
- CIDR comparisons now operate on the parsed target hostname, validate IPv4 octets and prefix lengths, reject credential-bearing URLs and fail closed for malformed CIDR inputs.
- Regression cases cover valid IP and HTTPS URL matches, IP-like hostname/query substrings, malformed addresses, invalid prefixes and wildcard/domain behavior.
- Final PR head passed test 38234207276, build 38234207311 and typecheck 38234207337. The earlier failing assertion was caused by an over-escaped `\d` regex; the corrected final head is green.

### SEC-006 — WebFetch bounded response reads and redirect permissions (PR #38)

- Merged as `49a5387c6fdee0913b495f04ddbf1ad4a0721156`.
- Redirects are handled manually with a five-hop limit and a fresh webfetch permission request per destination; URL validation rejects non-HTTP(S) destinations and embedded URL credentials.
- Response body bytes are capped while streaming to 5 MiB, and the network timeout remains active through body consumption.
- Tests cover destination re-authorization and rejecting an oversized streaming response without Content-Length.
- Final PR head passed test 38234261118, build 38234261062, typecheck 38234261027 and pr-management 38234261031.

### PR #32 — AD authorization and evidence gates

- Merged with source content now in `.cyberstrike/skill/ad-security/SKILL.md`.
- Adds engagement authorization boundaries, least-privileged enumeration, non-destructive proof requirements and sanitized evidence guidance.
- GitHub Actions build/test/typecheck/pr-management all passed on head `75e0be0de446aec4e60d9148590ebf5a68094838`.

### Branch cleanup guarantee

- No remote branch was deleted in this checkpoint. The connected GitHub tool set did not expose a verified delete-ref operation in this workflow, and no local clone was available to inspect worktrees/uncommitted changes.
- PR #2 remains open as Draft after the audit found `NODE_TLS_REJECT_UNAUTHORIZED=0`; do not merge it wholesale. PR #6 remains Draft and is out of scope for this pass because it changes skill files. PR #7 is closed unmerged; its 77 changed paths have zero branch-only paths (58 blobs identical, 19 differing and generally older/smaller on the branch), so no wholesale merge is needed. PR #11 remains closed unmerged; the reviewed unique-diff accounting is complete and the relevant skills are already present on main.
- The merged fixes above are integrated and CI-verified; branch-ref deletion is not claimed.
- Current `main` was confirmed equal to merge commit `49a5387c6fdee0913b495f04ddbf1ad4a0721156` by GitHub compare.

## Direct-to-main repair checkpoint — 2026-10-12

This checkpoint follows the instruction to make focused, verified repairs directly on `main` rather than creating another feature branch for each fix.

### INT-006 — P2: verification hypothesis identity could mix endpoint-specific and endpoint-less evidence

- **Evidence:** `packages/cyberstrike/src/session/verification-ledger.ts` previously rejected endpoint mismatches only when both the stored endpoint and the new endpoint were non-empty. That allowed the same `hypothesis_key` to combine an endpoint-specific record with an endpoint-less record, even though the key defines the identity boundary for one claim.
- **Fix:** centralized identity comparison in `VerificationAttempts.sameHypothesisIdentity` and made the ledger reject endpoint mismatches consistently, including when exactly one endpoint is absent.
- **Regression coverage:** added unit coverage for same endpoint, missing endpoint, different asset, and different vulnerability class in `packages/cyberstrike/test/methodology/verification-attempts.test.ts`.
- **Direct commits on main:** policy helper `6ad4f927421491a8715de178949b31700af12f42`; ledger integration `cac99ea90d65a928ce4f6c8d61d31485b5540d0b`; regression test `53f693a3f3cac076c919943b28143097fc0c1e30`.
- **Validation:** GitHub contents API confirmed each write returned a commit SHA. GitHub Actions unit tests, typecheck, and build passed on the later code head `8324bd36c1883d008cd3da6c3a9b91cc6b0cd228` (runs `38239376249`, `38239376204`, `38239376508`). CodeQL was still running when this ledger was refreshed; no local Bun runtime/checkout was used.
- **Attempts:** one focused implementation pass; continue from actual CI feedback if checks become available.
- **Disposition:** code change committed directly to `main`; unit tests/typecheck/build passed on later code head `8324bd36`; CodeQL pending. No feature branch was created for this repair.

## Follow-up checkpoint — 2026-10-12: scope-check IPv4/CIDR parsing

### SEC-005 — P1: scope-check could report an IPv4-looking hostname substring as in scope

- **Evidence:** before the fix, `extractIP()` used a regex search over the entire target string instead of parsing the URL host; `ipToNum()` accepted out-of-range octets and CIDR prefixes were not range-checked. For example, a target URL whose hostname starts with `10.20.30.40.attacker.example` could yield `10.20.30.40` as a substring and be reported inside `10.20.30.0/24`.
- **Fix branch:** `fix/scope-check-ipv4-cidr-host-validation-20261012`; issue #35.
- **Changes:** CIDR inputs are now recognized before domain matching, all CIDR prefix lengths must be integers in 0..32, IPv4 octets must be four canonical decimal components in 0..255, and CIDR comparisons use the parsed hostname from a valid HTTP(S) URL or bare host. Userinfo and unsupported URL protocols fail closed. Domain and wildcard matching now operate on the parsed hostname rather than raw URL text.
- **Regression tests authored:** `packages/cyberstrike/test/tool/scope-check.test.ts` covers embedded-IP hostnames/query values, valid in-range bare IP/URL, out-of-range/malformed addresses, invalid CIDR prefixes, URL userinfo, and domain/wildcard regressions.
- **Validation:** code and test added remotely; await CI on the final PR head. No local Bun execution was possible in this runtime.
- **Scope note:** this tool communicates scope decisions; it does not replace independent authorization and network guards at execution boundaries.



## Follow-up checkpoint — 2026-10-12: terminal verification verdict enforcement

### INT-007 — P1: terminal verification outcomes could be reopened by another attempt

- **Evidence:** `VerificationLedger.record()` rejected a post-verdict attempt only when its `decisiveResult` differed from the stored terminal outcome. A caller could submit another attempt with the same `confirmed`/`disproven` result and mutate the ledger after the hypothesis was supposed to be final.
- **Fix:** centralized terminal-outcome detection in `VerificationAttempts.isTerminalOutcome()` and reject any further record operation for a hypothesis whose stored outcome is `confirmed` or `disproven`.
- **Regression coverage:** added policy tests proving only `confirmed` and `disproven` are terminal; inconclusive and unrecorded outcomes remain non-terminal.
- **Direct commits on main:** policy `bfb35b3dd2064e4c558b43228cf501e946170665`; test `7de88c567efa1a4fafb267aa8dab4ac937bcd8e3`; ledger enforcement `afc9422633ce9244e893566ffef7d2729ecc7659`.
- **Validation:** unit tests/typecheck/build passed on code head `8324bd36`; CodeQL remained in progress. No local Bun runtime was used.
- **Status:** implemented; unit tests/typecheck/build passed on `8324bd36`; CodeQL pending.


## Follow-up checkpoint — 2026-10-12: bounded remote skill registry responses

### SEC-007 — P1: remote skill index and file downloads had no response-size or timeout limits

- **Evidence:** `Discovery.pull()` parsed the registry index with `response.json()`, while `get()` buffered arbitrary remote skill bodies using `response.text()`/`response.arrayBuffer()`. Neither path bounded the bytes read or applied a request timeout, allowing a remote registry or compromised asset host to consume excessive memory and stall skill loading.
- **Fix:** added incremental response-body reading with explicit caps (2 MiB for index JSON, 25 MiB per asset, 100 MiB total downloaded bytes), a 15-second per-request timeout, and a five-minute overall sync deadline. Registry entries/assets are capped and processed with at most six concurrent skills; legacy files are fetched sequentially per skill. Archives are limited to 10,000 entries, 25 MiB per expanded member, 100 MiB per archive, and a 250 MiB total declared extraction budget.
- **Regression coverage:** tests cover body-at-limit acceptance, streamed oversize rejection, oversized declared `Content-Length`, archive expansion bombs/manifests, plus SEC-008 destination and redirect validation.
- **Direct commits on main:** per-response limits `a53f4ff1aa18bfe2838958a178cf2752de456a7a`; regression test `4df5373ff1d7421edd05a50b8e77268846cca10f`; test simplification `9f1cc631373d3a27f98b91c46c00da33cdf0f604`; bounded asset count, six-way concurrency, 100 MiB total download budget and archive expansion checks `7c38ea8b92aa42a4470708efe836161fa84dd817`; five-minute sync budget and concurrent extraction reservation `24bd1912ceff24406f00ed8402e3d75e2b8f620f`; archive-size regression tests `baabc4cb88e2e6e590cff97b5140d87652a5ccc1`; final formatting/deadline guards `fe2640a8ea28f9c31ab826042a4dd2b1fc35810b`; byte-accounted shared budget `21833d6442f386535ba310f7c2632c16d2160a3c`; over-budget chunk accounting and regression test `2fe4ebed7716508300617897810928225a47c420` / `14da7c3efcc78c9fccf865e454ff97187a6f3e98`.
- **Validation:** unit tests, typecheck and build steps passed on code head `8324bd36` (runs `38239376249`, `38239376204`, `38239376508`). CodeQL remained in progress; no local Bun run was claimed.
- **Status:** implemented; unit tests/typecheck/build passed on `8324bd36`; CodeQL pending.


## Follow-up checkpoint — 2026-10-12: remote skill destination and redirect guard

### SEC-008 — P1: registry-controlled URLs could reach unsafe hosts or redirect to them

- **Evidence:** `Discovery.pull()` accepts URL values from remote skill registry entries. The previous fetch path used normal redirect-following fetch behavior and did not restrict protocols, local hostnames, literal IP destinations, or DNS results. A compromised registry/index could try to make the agent fetch local services or cloud metadata endpoints, including through redirects.
- **Fix:** introduced a remote-URL shape policy requiring HTTPS, no URL credentials, no nonstandard ports, FQDN hostnames rather than literal IPs, and rejection of local/internal suffixes. Before each request and each redirect hop, resolve the hostname and reject it unless every resolved address is public. Redirects are handled manually, revalidated, and capped at four hops; unsafe or downgrade redirects fail closed.
- **Regression coverage:** tests cover HTTP/file schemes, loopback and internal destinations, URL credentials, nonstandard ports, representative private/reserved IPv4 ranges, loopback/link-local/ULA/documentation IPv6 ranges, and public IPv4/IPv6 examples.
- **Direct commits on main:** implementation `3eedd98f1b00fba1c534b47ac87ae22524c502de`; initial regression tests `48492819e173b58d974782bc152dd36965580e87`; extracted redirect-policy helper `7d99c217484a0c0e136cdace4b4f82753243c805`; redirect regression tests `996c21c60fcb7aa9e3afc061cebe1712176e6145`; malformed-URL and per-entry failure handling `e0100c11695465b2770c0059b3b2a0ea83808a42`; formatting pass `9f4845bf3956c6b8b46636e1fa6d161448449038`; invalid registry URL tests `d88cf1d6019ab1a1f67a97eed14a55d354d73437`.
- **Limitations:** host DNS is checked before each fetch, but the runtime's fetch implementation performs its own subsequent resolution; DNS rebinding between those operations is not cryptographically prevented in this implementation. Network egress controls remain the stronger defense where available.
- **Validation:** unit tests, typecheck and build steps passed on code head `8324bd36` (runs `38239376249`, `38239376204`, `38239376508`). CodeQL remained in progress; DNS rebinding between validation and the runtime's own resolution remains a documented limitation.
- **Status:** implemented; unit tests/typecheck/build passed on `8324bd36`; CodeQL pending.


## Follow-up checkpoint — 2026-10-12: DOMPurify dependency security update

### SEC-009 — P1: UI sanitizer dependency was below the security fix

- **Evidence:** `packages/ui/package.json` and the root `bun.lock` resolved DOMPurify 3.4.13. The published advisory identifies versions `>=3.4.13 <3.4.16` as affected by an XSS issue and recommends 3.4.16 or later. See [Snyk advisory](https://security.snyk.io/vuln/SNYK-JS-DOMPURIFY-20361471) and [DOMPurify 3.4.16 release](https://github.com/cure53/DOMPurify/releases/tag/3.4.16).
- **Fix:** updated the UI dependency to `dompurify@3.4.16` and updated both corresponding Bun lockfile records, including the registry tarball integrity hash.
- **Direct commits on main:** manifest `6f4f789261610903e0b0d2ed849675c4b7a8f692`; lockfile `d40d1b312a9d9a6e08467feb7da1637db5776d04`.
- **Validation:** Bun dependency setup succeeded; unit tests passed on the lockfile-updated code head, typecheck passed, and the monorepo build step succeeded. CodeQL was still in progress; no separate lockfile-regeneration command was run.
- **Status:** security update committed; unit tests/typecheck/build steps passed on code head `3d42bd27`; CodeQL pending.


## Follow-up checkpoint — 2026-10-12: verification ledger invariants and CI regression repair

### INT-008 — P1: verification ledger read/check/write sequence was not atomic

- **Evidence:** `VerificationLedger.record()` read the hypothesis history, checked identity/terminal state/attempt budget, then inserted or updated rows in separate database operations. Without one transaction around the entire decision, concurrent callers could observe inconsistent ledger state or race the uniqueness/budget checks.
- **Fix:** wrapped the history read, identity/terminal/budget guards, attempt upsert, decision computation, and outcome update in `Database.transaction()`. Newly inserted strategy and variant identifiers are stored in normalized form to align the SQLite uniqueness key with the application-level deduplication key.
- **Direct commit on main:** `8ef8f394feeb9deb1c50039cf22c660b868e5643`.
- **Validation:** unit tests/typecheck/build passed on code head `8324bd36`; CodeQL remained in progress.

### INT-009 — P2: URL asset identity lowercased case-sensitive path components

- **Evidence:** `sameHypothesisIdentity()` lowercased the entire asset string. If an asset is a full URL, this could conflate paths such as `/Admin` and `/admin` on case-sensitive servers.
- **Fix:** canonicalize only explicit URL syntax through `URL.href`, which normalizes the host while preserving path case; non-URL asset identifiers remain exact after trimming.
- **Regression coverage:** added tests proving host case normalizes but path case remains identity-significant.
- **Direct commits on main:** implementation `52c5a3be60576970b9631d1b7e0b040eb579d8c7`; test `98ceaf0ea6228acb25c42d7b703f651477de0b2d`.
- **Validation:** unit tests/typecheck/build passed on code head `8324bd36`; CodeQL remained in progress.

### CI-001 — P2: archive fixture no longer satisfied the hardened DNS policy

- **Evidence:** the archive-byte regression test used `.invalid` as its mocked registry hostname. The new remote URL policy correctly rejects `.invalid` before the mocked fetch runs, so the test received no skill directory.
- **Fix:** changed the fixture to use the publicly resolvable `example.com` hostname while continuing to mock all HTTP responses. GitHub Actions on commit `b4acb0869937355b654cd8b7d1bb07654349bc61` reported unit tests and typecheck successful.
- **Current validation state:** unit tests and typecheck/build steps subsequently passed on code head `3d42bd27`; CodeQL remained in progress. The latest `main` commit after that is documentation-only.

## Additional branch disposition audit — 2026-10-12

| Branch / PR | Decision | Reason |
|---|---|---|
| `fix/remove-tracked-cookie-file` | No merge required | `packages/cyberstrike/cookies.txt` is already absent from main and `.gitignore` already excludes the cookie export. |
| `fix/remote-skill-cache-confinement-20261012` and `fix/remote-skill-cache-confinement-main-20261012` | No merge required | Both are behind main; current main includes their cache-confinement work plus newer URL/DNS/redirect and resource-budget protections. |
| `fix/audit-skill-discovery-path-confinement` | Retain; do not merge wholesale | Its discovery implementation is an older, substantially smaller version than main and lacks the current bounded-read, destination, redirect, and overall resource-budget controls. |
| `audit/fix-verification-ledger-hypothesis-identity` and `fix/verification-ledger-evidence-gate` | No merge required | Their verification policy/tool/test blobs are older than main; main now includes endpoint/asset identity guards, terminal verdict enforcement, and atomic ledger writes. |
| `fix/skill-runtime-linkage-audit` | No merge required | The skill context/tool/test files match main; its differing index-engine implementation and tests are older/smaller than the main versions. |
| `fix/remove-orphan-auth-manager-typecheck-blocker` | Retain; do not merge wholesale | Its diff removes `packages/cyberstrike/src/tool/auth-manager.ts`; current main contains the auth manager used by auth-vault, Gmail and target-memory functionality. |
| `fix/copilot-token-exchange` | No cherry-pick | Main already has shared `provider/copilot-session.ts` logic used by the plugin and browser worker, including token invalidation/retry behavior; the branch is heavily stale and duplicates token-exchange code. |
| `feat/spa-nav-discovery`, `ci/monorepo-build-validation-20261012`, and `improve/skill-quality-reference-audit-reconciled` | No merge required | These refs are behind `main` with no unique commits in the current comparison. |
| `skills/ad-security-verification-gates-20261012` and `integration/ad-security-verification-gates-main-20261012` | No merge required | The reviewed AD security skill file blob is identical to main. |
| `feat/discovery-core` | Retain; do not merge wholesale | It is heavily divergent and includes active mutating-method probes that are not appropriate for the current conservative reconnaissance path. |
| `feat/proxy-config` / `dev` | Retain; selective review only | Both contain broad, highly divergent networking/replay/browser changes; there is no safe evidence for a wholesale merge. |
| PR #7 / `feat/target-memory-foundation` | Closed unmerged; no wholesale merge | Compared all 77 changed paths: 58 blobs are identical to `main`, 19 differ, and there are zero branch-only paths. The differing runtime files are generally older/smaller on the branch; key research, target-memory, finding-validation, Gmail, auth-manager, and Hackbrowser implementations match or are newer on main. The remaining differing blobs are retained for reference rather than blindly merged. |
| PR #40 / `docs/audit-ledger-refresh-20-pass-20261012` | Closed unmerged; superseded | Its useful 20-pass evidence and merged-fix summary are already represented in the main ledger. The branch is 1 commit ahead / 64 behind and stale; no code was lost by not merging the snapshot wholesale. |
| PR #6 / `improve/skill-quality-reference-audit` | No wholesale merge; retain pending final disposition | Compared all 99 changed paths: 61 blobs are identical to `main`, 38 differ, and there are zero branch-only paths. Several differing branch skills are substantially longer, but current main has reconciled/curated variants; e.g. recon-methodology is about 5.3 KB on main versus 64 KB on the branch. Do not overwrite current skills without content-level comparison of the extra material and references. |
| PR #2 / `hackbrowser-improvement` | Retain; do not merge wholesale | The inspected branch disables TLS certificate verification. Any safe unique browser changes require isolated review and tests. |
| `seo/readme-hero-refresh` | Selectively ported | The branch contained only two README hero lines; the provider-agnostic wording was copied to main to avoid an unsupported “first” claim. No wholesale merge or branch deletion was performed. |

**Branch cleanup:** no branches were deleted. The available GitHub actions in this execution context do not provide a safe branch-delete operation; preserving unmerged divergent branches avoids accidental loss of unique work. Delete only after the remaining unique diffs are accounted for and a supported deletion action is available.


## Follow-up checkpoint — 2026-10-12: MySQL2 credential-leak and decompression-bomb advisories

### SEC-010 — P1: console MySQL driver was below two security fixes

- **Evidence:** `packages/console/core/package.json` and `bun.lock` resolved `mysql2@3.14.4`. The driver was affected by the authentication downgrade/plaintext credential disclosure fixed in 3.22.0, and the later compressed-protocol unbounded-inflate DoS affected versions through 3.23.0. References: [GHSA-3f6p-5ww8-9rcr](https://advisories.gitlab.com/npm/mysql2/GHSA-3f6p-5ww8-9rcr/) and [GHSA-rgwj-5xj2-c3m3](https://github.com/advisories/GHSA-rgwj-5xj2-c3m3).
- **Fix:** updated the direct dependency and matching Bun lockfile records to `mysql2@3.23.1`, the first release in the inspected advisory range that includes both fixes. The compatible dependency ranges resolve to package versions already represented in the lockfile.
- **Direct commits on main:** manifest `1ef50d6b46a7badc2a79c5ba2db858eb3eb3581f`; lockfile `1868a66688302ff328b1cc62bce3203d8eb2ceb7`.
- **Validation:** Bun setup succeeded; unit tests passed on lockfile commit `1868a66688302ff328b1cc62bce3203d8eb2ceb7` (run `38239527739`), typecheck passed on that commit (run `38239527726`), and the monorepo build step succeeded on its child code head `3d42bd27d161f0260fc0d7505d2c2b9aa30a46d5` (run `38239543376`). CodeQL remained in progress.

### Dependency branch disposition update

- `dependabot/npm_and_yarn/packages/console/core/mysql2-3.22.0` was **not merged wholesale**: its proposed 3.22.0 fixes the earlier credential advisory but is still within the later affected range `<=3.23.0`. The safer selective update to 3.23.1 is now on main.
- `dependabot/npm_and_yarn/packages/ui/dompurify-3.4.16` was **not merged wholesale** because it only changed the package manifest and left the Bun lockfile stale. The 3.4.16 manifest and lock records were updated directly on main.


## Follow-up checkpoint — 2026-10-12: IPv6 special-purpose destinations and archive decompression

### SEC-011 — P1: IPv6 SSRF filter allowed special-purpose and transition prefixes

- **Evidence:** the prior check allowed most addresses under `2000::/3` and excluded only `2001:db8::/32`. It did not reject the IANA special-purpose `2001::/23` block, 6to4 `2002::/16`, or the newer `3fff::/20` documentation range. The [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry) identifies these ranges and their non-general-purpose routing properties.
- **Fix:** added parsed-hextet prefix checks for `2001::/23`, `2001:db8::/32`, `2002::/16`, and the reserved/documentation `3fff::/16` block. The broader `3fff::/16` rejection is intentionally conservative.
- **Regression coverage:** tests reject IETF special-purpose/benchmarking addresses, 6to4, and documentation addresses, while preserving a public address `2001:200::1`.
- **Direct commits on main:** implementation `01b39e526b3c0072dc6c4d11338fe4febc18e42f`; tests `71cf19e8a5d4dae6d9aa8bbbc252f398c19cf3e5`.
- **Validation:** unit tests passed with 1,798 passing, 5 skipped, and 0 failures on the preceding code head; the latest suite including this test passed with 1,799 passing, 5 skipped, 0 failures (run `38240648583`). Typecheck and monorepo build passed on `c0919ec57a`; Python CodeQL passed, JavaScript/TypeScript CodeQL remains in progress.

### SEC-012 — P1: compressed tar archives could expand beyond declared member-size limits

- **Evidence:** member-size and entry-count checks happened after node-tar had already parsed the archive. A highly compressed tar containing many empty headers could consume substantial CPU even when declared file sizes were tiny.
- **Fix:** gzip archives are now decompressed through a streaming byte limiter into a private temporary directory before parsing/extraction. The limit is 125 MiB per tar stream and 300 MiB total per sync; raw tar bytes count against the same total. node-tar is forced to parse raw tar data, and zstd-compressed archives are rejected until a bounded decompression path is implemented.
- **Regression coverage:** existing gzip archive extraction remains green; added pure budget-boundary tests for per-archive and sync-wide decompressed bytes, plus existing archive member/entry count limits.
- **Direct commits on main:** bounded decompression `574b00986ca92a0f707652b92b5cbdcb66112edf`; extraction from the prepared tar `c0765bac0db5ef5b71dd09f833b90eb52e6cb486`; total decompressed budget `93891dc2f119db011b2bf67b77c8b92bb089a7f8`; raw tar budget `a22eb391bd263da5ad5b6de170c827b396d5d4aa`; budget helper `ad52d7160ba874f4d956ca5ca264a3a3ba0b0413`; regression test `c0919ec57aebf65d1d1956f506044b51e421212e`.
- **Validation:** latest unit tests passed with 1,799 passing, 5 skipped, 0 failures, and typecheck and monorepo build passed on `c0919ec57a`. Python CodeQL passed; JavaScript/TypeScript CodeQL remains in progress. The archive format support is deliberately conservative: gzip and raw tar are supported; zstd is explicitly rejected and Brotli is not enabled.


## Follow-up checkpoint — 2026-10-12: remaining branch integration re-check

Compared the remaining recently updated refs against current `main` after the latest fixes. No wholesale merge was needed for these branches; their useful changes are already present in current `main`, while several branch snapshots are materially older:

- `fix/audit-skill-discovery-path-confinement` and `fix/remote-skill-cache-confinement-20261012`: their `discovery.ts` implementations are older and shorter than main. Main already contains real-path/symlink-aware cache confinement, safe archive entry resolution, HTTPS redirect checks, and bounded response reads. Do not overwrite main with these stale versions.
- `fix/scope-check-ipv4-cidr-host-validation-20261012`, `fix/webfetch-bounded-redirects-20261012`, and `fix/web-recon-no-mutating-method-probes`: the reviewed implementation blobs are identical to main, including fail-closed IPv4 CIDR validation, manual/bounded redirect handling with per-hop checks, and the conservative recon program implementation.
- `fix/remove-tracked-cookie-file`: `packages/cyberstrike/cookies.txt` is absent from main and `.gitignore` already excludes that cookie export. No cherry-pick is required.
- `fix/target-workspace-owner-index-reconciliation-20261012`: its target-memory test blob matches main. Main now has an additional focused legacy-schema regression test covering owner-key backfill, stale-index removal, cross-owner reuse, and within-owner uniqueness.
- `docs/idor-skill-expansion` and `skills/import-phase-1-methodology-recon`: the reviewed added methodology/evidence/reporting/recon skills and migration documentation already exist on main. Avoid importing the older branch snapshots over the curated versions.
- `dependabot/npm_and_yarn/packages/cyberstrike/ai-sdk/provider-utils-3.0.28`: main already pins `@ai-sdk/provider-utils@3.0.28` in both the package manifest and lockfile; no dependency change remains to port.
- `fix/pr-management-fork-label-guard`: the ref is behind main with zero unique commits in the comparison; no merge is required.

The two remaining open pull requests, #2 (Hackbrowser improvement) and #6 (skill-quality/reference audit), are still drafts. Keep them open as review/reference work rather than merging wholesale: #2 contains a TLS certificate-verification bypass in the inspected branch, and #6 contains divergent skill content that needs file-by-file content review before any selected material can safely replace current skills. No branches were deleted because a safe branch-delete operation is unavailable in this execution context and unmerged unique work must be preserved.

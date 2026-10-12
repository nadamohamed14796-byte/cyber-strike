# CyberStrike Repository Repair Ledger

**Checkpoint timestamp:** 2026-10-12  
**Repository:** `nadamohamed14796-byte/cyber-strike`  
**Baseline `main`:** `7ff8bbe5a1bc931549bb1cefdd9bee8bd36245e3` (refreshed after PR #22 merged)  
**Working ref:** `main` (focused fixes committed directly; no per-fix branch created)  
**Execution limitation:** the runtime could not resolve `github.com` for a local clone, and Bun is not installed in the execution container. Repository inspection and edits are therefore being performed through GitHub's repository API; verification must use GitHub Actions for this branch. No local test result is claimed.

## Confirmed issues

| ID | Priority | Category | Root cause / evidence | Attempts | Status |
|---|---|---|---|---:|---|
| SEC-001 | P1 | Security / path confinement | `packages/cyberstrike/src/skill/discovery.ts` used untrusted skill names and legacy file paths to construct cache destinations; archive extraction also used an unrestricted shell `tar` command. PR #18 contains the intended mitigation but its current CI fails with actual parser errors caused by escaped backticks/interpolation (typecheck run 38202096941) and a missing argument to `get`. | 5 | in_progress |
| SEC-002 | P2 | Test and type contract | Helper functions are exported as members of the `Discovery` namespace, not as top-level module exports; the first repair iteration imported them incorrectly. CI typecheck exposed this. | 3 | in_progress |
| INT-001 | P2 | Branch integration | Open PR #11's five skill additions and IDOR skill edit overlap with already merged skill-library batches (#20/#21). The PR is 91 commits behind `main`; do not merge wholesale. Verify any unique remaining content before disposition. | 1 | in_progress |
| INT-002 | P2 | Branch integration | Open PR #7 contains a broad target-memory / research / auth feature set; PR #17 has already merged an integration branch for target memory, global research learning, and scoped auth profiles. PR #7 is 91 commits behind and 311 commits ahead at its current head, so only a unique-diff review can safely establish whether it is redundant. | 1 | in_progress |
| INT-003 | P2 | Branch integration | Draft PR #6 is heavily diverged (159 commits ahead, 91 behind). PR #15 merged a reconciled skill-quality audit, so the original branch must not be merged wholesale. Remaining unique changes require selective comparison. | 1 | in_progress |
| INT-004 | P2 | Branch integration | PR #2 is 201 commits behind and contains broad HackBrowser changes. Its cookie-file deletion is already covered by merged PR #14; remaining functionality needs isolated diff and regression review before integration. | 1 | in_progress |

| FUN-001 | P2 | Archive download integrity | `get()` decoded every response via `response.text()` before writing. Binary gzip tarballs can be corrupted during UTF-8 decoding, so the new safe archive extractor would not reliably receive the original archive bytes. | 1 | in_progress |
| SEC-003 | P2 | Test/type contract | CI on the archive regression test exposed that `tar.x()` passes an entry union without a guaranteed `.type` property, and TypeScript rejects a Node `Buffer` as a `Response` body. Add runtime type validation and copy fixture bytes to an `ArrayBuffer`. | 1 | in_progress |
| SEC-004 | P1 | Path normalization | The `tar.x()` filter callback had an over-escaped backslash regex that normalized pairs of backslashes rather than a single Windows path separator. The main resolver's `path.resolve` containment check also protects against escapes, but this defense-in-depth mismatch and single-backslash coverage needed correction. | 1 | in_progress |

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
- **Verification:** re-run CI after this commit. Keep the issue `in_progress` until typecheck and unit tests pass on the latest PR head.

## Branch / PR ledger (updated during execution)

- `main` moved to `7ff8bbe5a1bc931549bb1cefdd9bee8bd36245e3` when PR #22 was merged during this audit.
- PR #23 head `a8907825c3f96c21b2d8ae5ae3509cc4570178f0` passed typecheck run 38228127368, test/unit jobs in run 38228127203, and PR standards run 38228123971. Those checks apply to the old base. This clean integration branch is now based on current `main` and must pass its own required checks before merge.
- Do not merge #23 as-is. If the clean integration PR succeeds, close #23 as superseded and retain its history for audit purposes.

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
| 03 | Type safety and runtime contracts | PASS_WITH_CI_EVIDENCE | Latest-head typecheck passed for PR #28 run 38228571787, PR #34 run 38232995605, PR #36 run 38234207337 and PR #38 run 38234261027. Scope CIDR’s initial unit test exposed an over-escaped regex; that was corrected before final green CI. No local typecheck was run. |
| 04 | Build and packaging | PASS_WITH_CI_EVIDENCE | PR #29 added monorepo build validation and merged as 27b413990cdf2e248f710319636ef666e0934b4e. Build passed on PR #34 run 38232995678, PR #36 run 38234207311, and PR #38 run 38234261062. Local publishing and install smoke tests remain unrun. |
| 05 | CLI and configuration | PASS_WITH_BLOCKERS | CLI entry imports/registers TargetCommand, ResearchCommand and UpdateCommand. The commands expose target workspaces, research sync/search/queue and bounded update cycles. No local CLI help/run was possible without Bun. |
| 06 | Agent orchestration and lifecycle | PASS_WITH_BLOCKERS | Inspected agent tool policies and prompt lifecycle/context insertion, including TargetMemory and ResearchContext. Provider-backed sessions and resume/cancel flows were not exercised end to end. |
| 07 | Skill discovery and linkage | PASS_WITH_CI_EVIDENCE | Inspected cache confinement, archive member filtering, SkillIndex, SkillContext and SkillTool. PR #28 passed typecheck/test. AD authorization/evidence guidance merged in PR #32 with build/test/typecheck/pr-management green. Filesystem TOCTOU and full skill catalog coherence remain review items. |
| 08 | Tool registration and external execution | PASS_WITH_BLOCKERS | Inspected tool/registry.ts registrations for finding validation, research knowledge, target notes, JavaScript correlation, scope checks, and browser tools. No live scanner/browser/external-tool run was performed in this runtime. |
| 09 | Research ingestion | PASS_WITH_BLOCKERS | Inspected research ingest and safe-fetch controls: source host allow-list, manual redirects, DNS checks, streaming body limit, timeouts/retry bounds, and secret redaction. DNS check-to-connection rebinding resistance still needs independent runtime validation. |
| 10 | Knowledge quality and retrieval | PASS_WITH_BLOCKERS | Inspected ReportKnowledge, ResearchContext and research_knowledge prompt contract. External reports are explicitly untrusted references rather than evidence for the current target; actual retrieval quality needs live-provider evaluation. |
| 11 | Finding and evidence lifecycle | PASS_WITH_BLOCKERS | Inspected vulnerability reporting, evidence-gated candidate handling and the 20-distinct-attempt validation rubric. A candidate can be upgraded in place only with matching execution evidence; no target-side finding was tested. |
| 12 | Persistence, migrations and recovery | PASS_WITH_CI_EVIDENCE | PR #34 fixed owner-scoped target workspace indexes and legacy owner backfill, adding two-non-Git-directory regression coverage. CI passed on head ae04084b59b95cb38e736432713d784b5c2c0d21: test 38232995676, build 38232995678, typecheck 38232995605. Local existing-database migration simulation remains unrun. |
| 13 | Scope enforcement and network safety | PASS_WITH_CI_EVIDENCE_AND_LIMITS | PR #36 changed scope_check to parse the actual URL hostname, validate IPv4 components and CIDR prefix, and reject arbitrary embedded-IP matches. Final test/build/typecheck passed (38234207276 / 38234207311 / 38234207337). This helper does not replace execution-boundary authorization. |
| 14 | Authentication, authorization and secrets | PASS_WITH_BLOCKERS | Inspected web-credential public-event projection, session-owned credential lookup and target-note redaction. PR #24 previously integrated credential event redaction; AD skill gates merged in #32. The unmerged Hackbrowser PR #2 sets NODE_TLS_REJECT_UNAUTHORIZED to 0 and is unsafe to merge as a whole. No real credentials were used. |
| 15 | Reconnaissance and discovery | PASS_WITH_BLOCKERS | Reviewed methodCheck and its test; main sends OPTIONS only and tests assert no TRACE, PUT or DELETE. The old feat/discovery-core branch sends those active methods and was not integrated. Live recon tools were not run. |
| 16 | Events, queues and background workflows | PASS_WITH_BLOCKERS | Reviewed research queue transactions, idempotent enqueues, leases, expired-lease reclaim and lease-owner completion; queue tests cover stale workers. Full multi-worker stress test was not independently run beyond CI. |
| 17 | Tests and CI integrity | PASS_WITH_CI_EVIDENCE | The monorepo build/test/typecheck pipelines ran for recent PRs. Scope regression test failed on its first attempt, was repaired, and passed on final PR #36 head. Root test is intentionally disallowed by repository instructions; no local package tests were run. |
| 18 | Documentation and repository hygiene | PASS_WITH_BLOCKERS | Updated security methodology and audit ledger; inspected README/package metadata/AGENTS. Public upstream URL may be intentional and was left unchanged. Local git status, secret scan across untracked files, and automated formatting checks remain unavailable. |
| 19 | End-to-end workflow validation | BLOCKED_EXTERNAL_RUNTIME | Traced CLI research update to durable queue and ResearchContext injection; target notes and JS correlation have a linked path into session context. No live provider-backed hunt, full browser multi-account crawl, or authorized target-side workflow was executable here. |
| 20 | Independent adversarial review | PASS_WITH_BLOCKERS | Review uncovered target-memory uniqueness/index mismatch (fixed #34), IPv4-substring CIDR false match (fixed #36), and WebFetch unbounded body buffering/redirect permission gap (fixed #38). Unsafe active-method probing and disabled TLS verification were found only in unmerged branches and were not merged. Broad stale branches and local runtime remain blockers. |
## Completion policy

- Do not change an issue to `fixed_verified` until the final code on the relevant branch passes the required CI and integration checks.
- Do not merge stale branches merely because a related feature name appears in `main`; inspect unique diffs first.
- Do not claim the 20-pass audit is complete until every row has independent inspection/check evidence.


## Follow-up checkpoint — 2026-10-12: target workspace ownership reconciliation

### DB-001 — P1: stale target-workspace indexes can defeat owner isolation

- **Evidence:** `packages/cyberstrike/src/target/target.sql.ts` defines `owner_key` plus unique/index keys `target_workspace_owner_target_key_idx` and `target_workspace_owner_host_idx`. The original `20261011180000_target-workspace-memory/migration.sql` still creates `target_workspace_project_key_idx(project_id, target_key)` and `target_workspace_host_idx(project_id, hostname)`. `Database.reconcile()` previously added absent columns but did not backfill `owner_key` or replace stale indexes. The later `20261011210000_target-workspace-owner-key/migration.sql` exists on `fix/target-memory-owner-isolation` but is absent from `main`.
- **Impact:** non-Git directories use `project_id = "global"`; a stale unique index on `(project_id, target_key)` can reject the same target in a second directory even though application lookups use an owner key. Existing rows added by schema reconciliation may also have `owner_key = "legacy:unscoped"`.
- **Repair strategy:** make startup reconciliation backfill non-global owners, isolate un-attributable legacy global rows using a per-row legacy key, remove obsolete indexes, and create the owner-key indexes idempotently. Do not blindly port the stale branch wholesale because its `target/index.ts` predates current path-confinement and secret-redaction hardening.
- **Regression coverage added:** `packages/cyberstrike/test/target/target-memory.test.ts` now verifies that two non-Git directories with the shared global Project ID can create distinct workspaces for the same target and cannot see each other's notes.
- **Validation status:** source-level change and test were authored on `fix/target-workspace-owner-index-reconciliation-20261012`; GitHub Actions must pass on its PR head before this issue can be marked verified. Local Bun execution is unavailable in this environment. This is not a claim that the test passed.
- **Branch disposition:** `fix/target-memory-owner-isolation` is not safe to merge wholesale: the inspected branch's target implementation lacks current `ensureSafeDirectoryPath` and note-secret-redaction paths. The necessary owner-index behavior is being ported selectively.




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
- PRs #2, #6 and #7 remain open because they are heavily diverged and contain unreviewed unique code; PR #2 includes an explicit TLS-verification disable and is unsafe to merge as-is. Their branches are preserved. PR #11 is closed unmerged and preserved for unique-diff accounting.
- The merged fixes above are integrated and CI-verified; branch-ref deletion is not claimed.
- Current `main` was confirmed equal to merge commit `49a5387c6fdee0913b495f04ddbf1ad4a0721156` by GitHub compare.

## Direct-to-main repair checkpoint — 2026-10-12

This checkpoint follows the instruction to make focused, verified repairs directly on `main` rather than creating another feature branch for each fix.

### INT-006 — P2: verification hypothesis identity could mix endpoint-specific and endpoint-less evidence

- **Evidence:** `packages/cyberstrike/src/session/verification-ledger.ts` previously rejected endpoint mismatches only when both the stored endpoint and the new endpoint were non-empty. That allowed the same `hypothesis_key` to combine an endpoint-specific record with an endpoint-less record, even though the key defines the identity boundary for one claim.
- **Fix:** centralized identity comparison in `VerificationAttempts.sameHypothesisIdentity` and made the ledger reject endpoint mismatches consistently, including when exactly one endpoint is absent.
- **Regression coverage:** added unit coverage for same endpoint, missing endpoint, different asset, and different vulnerability class in `packages/cyberstrike/test/methodology/verification-attempts.test.ts`.
- **Direct commits on main:** policy helper `6ad4f927421491a8715de178949b31700af12f42`; ledger integration `cac99ea90d65a928ce4f6c8d61d31485b5540d0b`; regression test `53f693a3f3cac076c919943b28143097fc0c1e30`.
- **Validation:** GitHub contents API confirmed each write returned a commit SHA. The available combined-status query returned no status entries, and the available workflow-run query returned no PR-triggered runs for this direct main commit. Therefore the new regression test and typecheck are **not yet verified as passing**; no local Bun runtime/checkout is available here.
- **Attempts:** one focused implementation pass; continue from actual CI feedback if checks become available.
- **Disposition:** code change committed directly to `main`; validation pending. No feature branch was created for this repair.

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
- **Validation:** source writes are committed to `main`; no local Bun runtime is available. GitHub Actions status must be checked on the resulting main head before this is marked verified.
- **Status:** implemented; automated validation pending.


## Follow-up checkpoint — 2026-10-12: bounded remote skill registry responses

### SEC-007 — P1: remote skill index and file downloads had no response-size or timeout limits

- **Evidence:** `Discovery.pull()` parsed the registry index with `response.json()`, while `get()` buffered arbitrary remote skill bodies using `response.text()`/`response.arrayBuffer()`. Neither path bounded the bytes read or applied a request timeout, allowing a remote registry or compromised asset host to consume excessive memory and stall skill loading.
- **Fix:** added incremental response-body reading with explicit caps (2 MiB for index JSON, 25 MiB per skill asset) and a 15-second abort timeout for index and asset fetches. Oversized/unreadable responses are rejected before being written or parsed.
- **Regression coverage:** added tests for body-at-limit acceptance, streamed oversize rejection, and oversized declared `Content-Length`.
- **Direct commits on main:** source `a53f4ff1aa18bfe2838958a178cf2752de456a7a`; regression test `4df5373ff1d7421edd05a50b8e77268846cca10f`.
- **Validation:** committed to `main`; CI and Bun execution remain pending/unavailable in this runtime. Recheck tests and typecheck on the latest main head.
- **Status:** implemented; automated validation pending.


## Follow-up checkpoint — 2026-10-12: remote skill destination and redirect guard

### SEC-008 — P1: registry-controlled URLs could reach unsafe hosts or redirect to them

- **Evidence:** `Discovery.pull()` accepts URL values from remote skill registry entries. The previous fetch path used normal redirect-following fetch behavior and did not restrict protocols, local hostnames, literal IP destinations, or DNS results. A compromised registry/index could try to make the agent fetch local services or cloud metadata endpoints, including through redirects.
- **Fix:** introduced a remote-URL shape policy requiring HTTPS, no URL credentials, no nonstandard ports, FQDN hostnames rather than literal IPs, and rejection of local/internal suffixes. Before each request and each redirect hop, resolve the hostname and reject it unless every resolved address is public. Redirects are handled manually, revalidated, and capped at four hops; unsafe or downgrade redirects fail closed.
- **Regression coverage:** tests cover HTTP/file schemes, loopback and internal destinations, URL credentials, nonstandard ports, representative private/reserved IPv4 ranges, loopback/link-local/ULA/documentation IPv6 ranges, and public IPv4/IPv6 examples.
- **Direct commits on main:** implementation `3eedd98f1b00fba1c534b47ac87ae22524c502de`; initial regression tests `48492819e173b58d974782bc152dd36965580e87`; extracted redirect-policy helper `7d99c217484a0c0e136cdace4b4f82753243c805`; redirect regression tests `996c21c60fcb7aa9e3afc061cebe1712176e6145`.
- **Limitations:** host DNS is checked before each fetch, but the runtime's fetch implementation performs its own subsequent resolution; DNS rebinding between those operations is not cryptographically prevented in this implementation. Network egress controls remain the stronger defense where available.
- **Validation:** committed to `main`; CI/typecheck/Bun test execution has not been verified in this environment. Keep this item pending until the latest main head passes.
- **Status:** implemented; automated validation pending.

# CyberStrike Repository Repair Ledger

**Checkpoint timestamp:** 2026-10-12 (refreshed after PRs #32, #34, #36, and #38)  
**Repository:** `nadamohamed14796-byte/cyber-strike`  
**Current `main` at this checkpoint:** `49a5387c6fdee0913b495f04ddbf1ad4a0721156` (GitHub compare confirms this commit is identical to main)  
**Audit documentation branch:** `docs/audit-ledger-refresh-20-pass-20261012`  
**Execution limitation:** the shell could not resolve `github.com` for a local clone and Bun is not installed. Repository reads/writes used the connected GitHub API. All test/build results below are GitHub Actions results on named PR heads. No local working-tree check, local test, or local branch deletion is claimed.

## Confirmed issues

| ID | Priority | Category | Root cause / evidence | Attempts | Status |
|---|---|---|---|---:|---|
| SEC-001 | P1 | Security / path confinement | Remote skill registry identifiers, legacy file paths, and archive members needed strict cache containment; binary archive downloads also needed to preserve raw bytes. Selective fix merged in PR #28 (`30cbf16f54a621f276416dcc9c450e755c592f64`); GitHub Actions typecheck run 38228571787 and test run 38228571748 passed on its head. | 5 | fixed_merged_CI_verified_no_local_run |
| SEC-002 | P2 | Test and type contract | Discovery helper tests initially used top-level imports for functions exported through the Discovery namespace. Imports and tar entry type guards were corrected in PR #28; typecheck run 38228571787 and test run 38228571748 passed. | 3 | fixed_merged_CI_verified_no_local_run |
| INT-001 | P2 | Branch integration | PR #11 (`skills/import-phase-1-methodology-recon`, head `b5a427af6667eb04cf1e4d993bf866d8f325290b`) is closed unmerged: 8 commits ahead / 126 behind current main, 8 changed files. Existing skill batches overlap, but full per-file unique-content accounting remains incomplete. Preserve the branch and do not merge wholesale. | 2 | blocked_and_retained_unique_review_pending |
| INT-002 | P2 | Branch integration | PR #7 (`feat/target-memory-foundation`, head `0524b8794fe075e55aa9d8fe8e25cc0f5bf2bbfa`) remains open: 311 commits ahead / 126 behind and 77 changed files. PR #17 integrated much of the feature set, and PR #34 fixed owner-index reconciliation. Its sibling owner-isolation branch lacks current path-confinement and note-secret-redaction code; no wholesale merge is safe. Preserve it pending full unique-diff accounting. | 2 | blocked_and_retained |
| INT-003 | P2 | Branch integration | PR #6 (`improve/skill-quality-reference-audit`, head `15322dd7e2a421541cf4dc55f8692b5aeca447fc`) remains open: 159 ahead / 126 behind, 99 files. Reconciled quality work is on main via PR #22, but unmerged unique content is not fully accounted for and inspected material includes outdated severity guidance. Preserve and port only verified chunks. | 2 | blocked_and_retained |
| INT-004 | P1 | Branch integration / TLS safety | PR #2 (`hackbrowser-improvement`, head `911fff9b89fdff9ad099169fdabaa0b4fd90bf5c`) remains open: 44 ahead / 236 behind, 36 files. The inspected launcher sets `NODE_TLS_REJECT_UNAUTHORIZED: "0"`, disabling TLS certificate verification in that branch. Do not merge wholesale; preserve while safe unique parts are reviewed. | 2 | unsafe_to_merge_wholesale_branch_retained |

| FUN-001 | P2 | Archive download integrity | Safe skill-cache work now preserves binary archive bytes rather than round-tripping through text. Included in PR #28; its final head passed GitHub typecheck run 38228571787 and test run 38228571748. | 1 | fixed_merged_CI_verified_no_local_run |
| SEC-003 | P2 | Test/type contract | Archive-entry handling now narrows untrusted tar entry fields at runtime and tests use a supported binary-body representation. Included in PR #28; typecheck and test passed on its head (runs 38228571787 and 38228571748). | 1 | fixed_merged_CI_verified_no_local_run |
| SEC-004 | P1 | Path normalization | Archive path normalization and entry allow-listing were corrected in PR #28; typecheck and test passed (runs 38228571787 and 38228571748). Residual filesystem TOCTOU/symlink behavior still warrants platform-specific testing. | 1 | fixed_with_residual_TOCTOU_review |

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
- **Verification:** re-run CI after this commit. Historical note: this was pending at the time of that earlier log. The safe cache-confinement implementation was later ported to current main and merged by PR #28 after its latest-head typecheck/test passed.

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



## Follow-up checkpoint — 2026-10-12: scope-check IPv4/CIDR parsing

### SEC-005 — P1: scope-check could report an IPv4-looking hostname substring as in scope

- **Evidence:** before the fix, `extractIP()` used a regex search over the entire target string instead of parsing the URL host; `ipToNum()` accepted out-of-range octets and CIDR prefixes were not range-checked. For example, a target URL whose hostname starts with `10.20.30.40.attacker.example` could yield `10.20.30.40` as a substring and be reported inside `10.20.30.0/24`.
- **Fix branch:** `fix/scope-check-ipv4-cidr-host-validation-20261012`; issue #35.
- **Changes:** CIDR inputs are now recognized before domain matching, all CIDR prefix lengths must be integers in 0..32, IPv4 octets must be four canonical decimal components in 0..255, and CIDR comparisons use the parsed hostname from a valid HTTP(S) URL or bare host. Userinfo and unsupported URL protocols fail closed. Domain and wildcard matching now operate on the parsed hostname rather than raw URL text.
- **Regression tests authored:** `packages/cyberstrike/test/tool/scope-check.test.ts` covers embedded-IP hostnames/query values, valid in-range bare IP/URL, out-of-range/malformed addresses, invalid CIDR prefixes, URL userinfo, and domain/wildcard regressions.
- **Validation:** code and test added remotely; await CI on the final PR head. No local Bun execution was possible in this runtime.
- **Scope note:** this tool communicates scope decisions; it does not replace independent authorization and network guards at execution boundaries.


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


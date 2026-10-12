# CyberStrike Repository Repair Ledger

**Checkpoint timestamp:** 2026-10-12  
**Repository:** `nadamohamed14796-byte/cyber-strike`  
**Baseline `main`:** `7ff8bbe5a1bc931549bb1cefdd9bee8bd36245e3` (refreshed after PR #22 merged)  
**Working branch:** `fix/remote-skill-cache-confinement-main-20261012`  
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

The 20 distinct passes have **not** yet been completed. Record each pass only after inspecting its relevant files/relationships and running the applicable checks. Update each row with evidence, newly discovered issues, repairs, regression tests, and a truthful final result.

| Pass | Audit lens | Status | Evidence / notes |
|---:|---|---|---|
| 01 | Repository integrity and completeness | PASS_WITH_BLOCKERS | Queried the complete baseline Git tree (`truncated=false`, 19,546 entries, 11,244 blobs). Required `AGENTS.md` and `.gitignore` are present. The local clone is blocked by DNS and no local test runtime is installed. The skill manifest lists 125 WSTG items at flat paths not present in the tree, but runtime skill discovery scans nested `SKILL.md` files and does not consume this manifest; publish-time intent remains unresolved, not mislabeled a runtime defect. |
| 02 | Architecture and dependency graph | PENDING | Not yet audited in this checkpoint. |
| 03 | Type safety and runtime contracts | PASS_WITH_BLOCKERS | Monorepo typecheck passed on prior PR #23 head `a8907825c3f96c21b2d8ae5ae3509cc4570178f0` (run 38228127368); the clean latest-main integration branch needs a fresh run before merge. |
| 04 | Build and packaging | PENDING | Not yet audited in this checkpoint. |
| 05 | CLI and configuration | PENDING | Not yet audited in this checkpoint. |
| 06 | Agent orchestration and lifecycle | PENDING | Not yet audited in this checkpoint. |
| 07 | Skill discovery and linkage | PASS_WITH_BLOCKERS | Reviewed remote discovery, cache path resolution, archive member checks, Skill.all() filesystem scanning, SkillIndex references, SkillContext isolation, SkillTool actions, and CLI skill commands. Regression tests passed with typecheck/unit checks on old head `a8907825...`; latest-main CI is pending. Residual filesystem TOCTOU risk needs independent platform-specific review. |
| 08 | Tool registration and external execution | PENDING | Not yet audited in this checkpoint. |
| 09 | Research ingestion and synchronization | PENDING | Not yet audited in this checkpoint. |
| 10 | Knowledge quality and retrieval | PENDING | Not yet audited in this checkpoint. |
| 11 | Finding and evidence lifecycle | PENDING | Not yet audited in this checkpoint. |
| 12 | Persistence, migrations, and recovery | PENDING | Not yet audited in this checkpoint. |
| 13 | Scope enforcement and network safety | PENDING | Not yet audited in this checkpoint. |
| 14 | Authentication, authorization, and secrets | PENDING | Not yet audited in this checkpoint. |
| 15 | Reconnaissance and discovery | PENDING | Not yet audited in this checkpoint. |
| 16 | Events, queues, and background workflows | PENDING | Not yet audited in this checkpoint. |
| 17 | Tests and CI integrity | PENDING | Not yet audited in this checkpoint. |
| 18 | Documentation and repository hygiene | PENDING | Not yet audited in this checkpoint. |
| 19 | End-to-end workflow validation | PENDING | Not yet audited in this checkpoint. |
| 20 | Independent adversarial review | PENDING | Not yet audited in this checkpoint. |

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


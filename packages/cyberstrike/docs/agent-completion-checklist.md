# CyberStrike Agent Completion Checklist

Branch under review: `feat/target-memory-foundation`
Target branch: `main`
Purpose: track concrete runtime, integration, security, and test gaps. Implementation boxes record reviewed code changes; the P0 verification item separately tracks whether runtime checks actually passed. Checked code is not a claim that tests passed.

## P0 — must be resolved before merge

- [x] **Worker and browser-installer environment isolation** — Hackbrowser worker and the Chromium installer now use a minimal, provider-scoped environment instead of inheriting the full parent environment. The installer uses argument-array execution and normal TLS verification; it no longer sets `NODE_TLS_REJECT_UNAUTHORIZED=0`. Focused tests are present but not yet run.
- [ ] **Branch/PR divergence review** — the four main-only commits were compared. The only main-side file difference is `auth-manager.ts`; its older version omits the newer GmailService/visible-browser integration on this branch, so the feature implementation should be retained. A proper merge/reconciliation commit is still pending; do not force-push or edit `main` directly.
- [ ] **Automated verification** — run package-level unit tests, typecheck, and build in an environment with the required Bun/toolchain; record exact commands and outcomes. No test is marked passed from file existence or static inspection.
- [ ] **CI status** — the test workflow now has unit, monorepo typecheck, and build jobs, and its required job gates all three. GitHub still reports no workflow runs or status checks for the inspected head; confirm Actions actually executes and fix any failures.

## P1 — feature wiring and data integrity

- [x] **CLI and tool registration** — static wiring is present: target/research/update commands are imported in the CLI; auth-manager, Gmail, JavaScript correlation, research knowledge, target notes, and finding validation are included in the tool registry. Runtime command execution remains covered by the P0 verification item.
- [ ] **Target workspace lifecycle** — verify create/load/list, normalized target identity, workspace paths, SQLite rows, notes, and duplicate handling work together across project/worktree boundaries.
- [ ] **Database migrations** — validate migration ordering, idempotent startup behavior, existing-install upgrade, new-install initialization, foreign keys/indexes, and compatibility with current schema.
- [ ] **Research ingestion to learning** — verify source discovery, safe fetching, filtering, dedupe, queue claim/retry/recovery, redaction, extraction, and persistence; ensure weak/non-bug-bounty content does not dominate useful knowledge.
- [ ] **Research retrieval during hunting** — prove agent prompts/tools call the shared knowledge store on meaningful observed signals and clearly distinguish external hypotheses from current-target evidence.
- [ ] **JavaScript-to-endpoint correlation** — verify captured JS assets, extracted routes, requests/responses, target and session provenance, dedupe, and findings analysis use the same identifiers and persisted records.
- [ ] **Finding-validation lifecycle** — verify exactly ten checks, evidence requirements, verdict rubric, SQLite persistence, existing-finding lookup/update, and target-note linkage; no unsupported confirmation.
- [ ] **Cross-target isolation and scope** — broader data-flow and runtime checks remain open for accounts, notes, learned global methodology, requests, and scope enforcement. Workspace directory/file symlink escapes are now blocked in target setup; a regression test was added but not run.
- [x] **Target-note secret redaction boundary** — centralized redaction is enforced by `TargetMemory.addNote`, so both CLI and agent-tool callers pass through it; regression tests cover quoted multi-word secrets. The tests still need to run under the P0 verification item.
- [ ] **AuthVault correctness** — run tests for encrypted-at-rest persistence, permissions, wrong-key handling, overwrite/remove/list, target binding, atomic writes, and concurrent update behavior. Shape validation and duplicate-ID rejection are implemented; the focused tests are present but not run.
- [x] **Auth-manager consent and secret lifecycle (static review)** — consent is required before vault save, the one-shot password environment variable is removed before the prompt can suspend, the local variable is cleared in `finally`, and index-sync failure is reported without claiming the index succeeded. Browser profile index writes are atomic and reject symlink files. Runtime regression tests remain under P0 verification.
- [ ] **Hackbrowser saved login and MFA** — static paths now enforce exact-origin guard and target binding, pass OTP over local IPC, abort Gmail lookup after 15 seconds (worker falls back after 30 seconds), and preserve manual MFA fallback. End-to-end visible login, abort/cleanup, and log inspection still need runtime tests.
- [ ] **Documentation and user-facing flow** — make CLI help, `/update` behavior, environment setup, migration/upgrade guidance, limitations, and troubleshooting match actual behavior.

## P2 — hardening and quality

- [ ] **Regression and negative tests** — tests were added for malformed AuthVault rows/duplicate IDs, worker env leakage, multi-word secret redaction, and symlinked target workspaces. Execute these alongside queue-crash, malicious redirect, concurrent-process, permission, and IPC failure coverage; none have been run in this review environment.
- [ ] **Dead paths and duplicate implementation review** — check for unreachable tools, duplicated policies, unused helpers, inconsistent names, or documentation that describes behavior not actually wired.
- [ ] **Release readiness** — after all required checks pass, update PR out of draft only when safe; do not merge while any P0 is unresolved.

## Verification notes

- Worker environment isolation was changed to an explicit allowlist in `hackbrowser-subprocess/worker-environment.ts`; Bedrock/Vertex credential variables are forwarded only for the matching provider. Focused tests were added, but have not been run in this review environment.
- `TargetMemory.addNote` now sanitizes titles, content, source labels/URLs, and tags at the persistence boundary; this closes the prior bypass where the CLI could skip the agent-tool-only redactor. A regression test was added, and a V8-level check of the regex showed no leakage for tested multi-word quoted values. This is not a substitute for the package test suite.
- AuthVault now validates each stored record’s identity/origin/purpose/timestamps and AES-GCM payload structure, and rejects duplicate IDs before exposing records. Writes enforce a private data-directory mode, clean up temporary files, and serialize in-process save/remove read-modify-write operations. Multi-process locking and runtime verification remain open.
- Target workspace creation now walks each directory component with `lstat`, rejects symbolic links/non-directories, and verifies the resolved path stays under the active project root. Target metadata files are checked for symlinks before use. A regression test creates a symlink at the target slug and expects workspace initialization to reject it; the test is not run yet.
- The Chromium path/installer subprocess now uses `execFileSync` argument arrays, a minimal environment, and ordinary TLS verification; this removes shell-string execution and the previous `NODE_TLS_REJECT_UNAUTHORIZED=0` override. Installer behavior requires runtime validation.
- Gmail OAuth token refresh, Gmail API requests, and complete OTP search now have explicit request deadlines; the Hackbrowser IPC handler has a 15-second abort and returns a manual-fallback response instead of holding the sole stdout reader indefinitely. This is statically reviewed but not tested against live Gmail or a mocked stalled network.
- Saved-password consent is requested before consuming `CYBERSTRIKE_AUTH_PASSWORD`, and the local reference is cleared in a `finally` path. Validation tool output now uses actual line breaks for target-note status.
- The feature branch was reported by GitHub compare as 183 commits ahead and 4 behind `main`; it must be reconciled carefully.
- The test workflow was expanded to run `bun turbo test`, `bun turbo typecheck`, and `bun turbo build`; the required status depends on all three. GitHub still reports no combined status entries or PR-associated workflow runs for the newest inspected head commit, so these commands have not been proven to execute or pass. Real Gmail OAuth and end-to-end browser login also remain unverified.

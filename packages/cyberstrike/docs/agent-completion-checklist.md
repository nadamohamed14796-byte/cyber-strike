# CyberStrike Agent Completion Checklist

Branch under review: `feat/target-memory-foundation`
Target branch: `main`
Purpose: track concrete runtime, integration, security, and test gaps. A box is checked only after the change is committed and its available verification is recorded. Code review alone is not a passing runtime test.

## P0 — must be resolved before merge

- [ ] **Worker environment isolation** — stop passing the entire parent environment to Hackbrowser; provide only required runtime/platform variables and provider-specific credentials required for the selected model. Never pass AuthVault encryption keys, website-password handoff variables, Gmail OAuth client secret/refresh token, or unrelated application secrets.
- [ ] **Branch/PR divergence review** — examine the whole PR diff and the four commits on `main` not present on the feature branch; reconcile safely without force-pushing or writing directly to `main`.
- [ ] **Automated verification** — run package-level unit tests, typecheck, and build in an environment with the required Bun/toolchain; record exact commands and outcomes. No test is marked passed from file existence or static inspection.
- [ ] **CI status** — inspect PR workflow runs and resolve any failing or missing checks before merge.

## P1 — feature wiring and data integrity

- [ ] **CLI and tool registration** — verify target, research, update, auth-manager, Gmail, JavaScript correlation, and finding-validation features are reachable through their documented entry points and the expected registry/commands.
- [ ] **Target workspace lifecycle** — verify create/load/list, normalized target identity, workspace paths, SQLite rows, notes, and duplicate handling work together across project/worktree boundaries.
- [ ] **Database migrations** — validate migration ordering, idempotent startup behavior, existing-install upgrade, new-install initialization, foreign keys/indexes, and compatibility with current schema.
- [ ] **Research ingestion to learning** — verify source discovery, safe fetching, filtering, dedupe, queue claim/retry/recovery, redaction, extraction, and persistence; ensure weak/non-bug-bounty content does not dominate useful knowledge.
- [ ] **Research retrieval during hunting** — prove agent prompts/tools call the shared knowledge store on meaningful observed signals and clearly distinguish external hypotheses from current-target evidence.
- [ ] **JavaScript-to-endpoint correlation** — verify captured JS assets, extracted routes, requests/responses, target and session provenance, dedupe, and findings analysis use the same identifiers and persisted records.
- [ ] **Finding-validation lifecycle** — verify exactly ten checks, evidence requirements, verdict rubric, SQLite persistence, existing-finding lookup/update, and target-note linkage; no unsupported confirmation.
- [ ] **Cross-target isolation and scope** — verify stored accounts, notes, learned global methodology, requests, and outputs cannot silently cross-bind between targets or expand allowed scope.
- [ ] **AuthVault correctness** — test encrypted-at-rest persistence, permissions, corruption/wrong-key handling, overwrite/remove/list, target binding, atomic writes, and concurrent update behavior.
- [ ] **Auth-manager consent and secret lifecycle** — check permission prompts occur before sensitive side effects, secrets are cleared in all success/failure paths, summaries/tool output/logs contain no passwords, and index failures are reported accurately.
- [ ] **Hackbrowser saved login and MFA** — verify exact-origin guard, target workspace binding, visible login, OTP IPC timeout/fallback, manual MFA, abort/worker cleanup, and no secrets in logs/arguments.
- [ ] **Documentation and user-facing flow** — make CLI help, `/update` behavior, environment setup, migration/upgrade guidance, limitations, and troubleshooting match actual behavior.

## P2 — hardening and quality

- [ ] **Regression and negative tests** — add/verify tests for malformed stored data, duplicate IDs, concurrent writes, queue crashes, hostile research HTML/redirects, secret redaction, and failed permission/IPC paths.
- [ ] **Dead paths and duplicate implementation review** — check for unreachable tools, duplicated policies, unused helpers, inconsistent names, or documentation that describes behavior not actually wired.
- [ ] **Release readiness** — after all required checks pass, update PR out of draft only when safe; do not merge while any P0 is unresolved.

## Verification notes

- Initial static review found `hackbrowser-launcher.ts` spawning the worker with `env: { ...process.env }`, which can inherit application secrets. This is a confirmed code-level issue pending repair.
- The feature branch was reported by GitHub compare as 183 commits ahead and 4 behind `main`; it must be reconciled carefully.
- Unit tests, typecheck, build, real Gmail OAuth, and browser login have not yet been verified as passing in this review.

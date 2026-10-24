- To regenerate the JavaScript SDK, run `./packages/sdk/js/script/build.ts`.
- ALWAYS USE PARALLEL TOOLS WHEN APPLICABLE.
- The default branch in this repo is `main`.
- Use `main` or `origin/main` for diffs against the default branch.
- Prefer automation: execute requested actions without confirmation unless blocked by missing info or safety/irreversibility.

## Style Guide

### General Principles

- Keep things in one function unless composable or reusable
- Avoid `try`/`catch` where possible
- Avoid using the `any` type
- Prefer single word variable names where possible
- Use Bun APIs when possible, like `Bun.file()`
- Rely on type inference when possible; avoid explicit type annotations or interfaces unless necessary for exports or clarity
- Prefer functional array methods (flatMap, filter, map) over for loops; use type guards on filter to maintain type inference downstream

### Naming

Prefer single word names for variables and functions. Only use multiple words if necessary.

```ts
// Good
const foo = 1
function journal(dir: string) {}

// Bad
const fooBar = 1
function prepareJournal(dir: string) {}
```

Reduce total variable count by inlining when a value is only used once.

```ts
// Good
const journal = await Bun.file(path.join(dir, "journal.json")).json()

// Bad
const journalPath = path.join(dir, "journal.json")
const journal = await Bun.file(journalPath).json()
```

### Destructuring

Avoid unnecessary destructuring. Use dot notation to preserve context.

```ts
// Good
obj.a
obj.b

// Bad
const { a, b } = obj
```

### Variables

Prefer `const` over `let`. Use ternaries or early returns instead of reassignment.

```ts
// Good
const foo = condition ? 1 : 2

// Bad
let foo
if (condition) foo = 1
else foo = 2
```

### Control Flow

Avoid `else` statements. Prefer early returns.

```ts
// Good
function foo() {
  if (condition) return 1
  return 2
}

// Bad
function foo() {
  if (condition) return 1
  else return 2
}
```

### Schema Definitions (Drizzle)

Use snake_case for field names so column names don't need to be redefined as strings.

```ts
// Good
const table = sqliteTable("session", {
  id: text().primaryKey(),
  project_id: text().notNull(),
  created_at: integer().notNull(),
})

// Bad
const table = sqliteTable("session", {
  id: text("id").primaryKey(),
  projectID: text("project_id").notNull(),
  createdAt: integer("created_at").notNull(),
})
```

## Testing

- Avoid mocks as much as possible
- Test actual implementation, do not duplicate logic into tests
- Tests cannot run from repo root (guard: `do-not-run-tests-from-root`); run from package dirs like `packages/cyberstrike`.


## Mandatory target workspace and artifact handling

When a request contains a target, program scope, scope file, domain/subdomain list, reconnaissance/hunting task, or target-specific output request, use the `target-workspace-workflow` skill and the structured target tools. This is required behavior, not optional advice.

1. Before recon/testing, call `target_workspace(action="init", target_url="<stable root/program target>")`, then use only the absolute workspace path it returns for target-specific outputs. Workspace initialization is not authorization.
2. Review the official program/customer policy before `target_workspace(action="configure_scope", ...)`. Preserve exclusions and record the official HTTPS reference. Call `scope_check` exactly once during initial setup for the canonical target/workspace and reuse the saved decision throughout recon and testing. A follow-up user message/turn for the same workspace with unchanged target and policy is a continuation, not a new run, and must not trigger another check. Start a new setup check only when a genuinely new run starts or the canonical target/policy configuration changes. Do not manually re-check each discovered host, endpoint, request, phase, or delegated tester. Active request tools independently enforce the persisted policy for each exact request. Missing, invalid, or inconclusive authorization means no active testing.
3. Store technical observations tied to session evidence with `target_note`. Use `target_workspace(action="record_summary")` for verified run/scope/checkpoint summaries so `notes.md` is updated even before a target request is captured. Save inventories/logs/JSON/CSV/evidence references with `target_artifact`; for a local file, use `source_path` to copy it without loading every line into model context. Do not send target-specific data into generic project memory or the global research knowledge base.
4. For large scope files, persist the original input beneath the root workspace and process the input directly using the existing checkpoint and normalized inventories. Keep discovered candidates and confirmed assets in the root inventories by default; create a nested child workspace only when the operator explicitly requests a separate investigation workspace for that specific authorized asset. Never create one workspace per candidate or host during ordinary recon.
5. Never write target outputs to an invented folder such as /root/targets or the current shell directory by default. A failed/missing workspace or failed save is not success; report the exact failure and do not claim the artifact exists.
6. Keep the root notes.md as a concise program summary. Store ordinary discovered assets, hosts, URLs, and endpoints in the root workspace inventories; only assets explicitly attached for an independent investigation get their own child workspace and child notes/evidence. Validate final artifact paths, sizes, counts, and run status before saying work is complete.

## CyberStrike agent instruction ownership

Keep one authority per responsibility; do not add another inventory, source list, phase ledger, or helper merely to restate an existing contract.

- Recon workflow guidance: `packages/cyberstrike/src/command/template/recon.txt`; progress tracking and artifact verification: registered `recon_checkpoint` runtime/schema in `packages/cyberstrike/src/tool/recon-checkpoint.ts`. Ordinary recon tool use is not blocked by stale or incomplete phase order.
- Recon phase outputs and completion criteria: `.cyberstrike/skill/RECON_PHASE_TOOL_MATRIX.md`.
- Shared tools, APIs, CLIs, helper scripts, and preflight: `.cyberstrike/skill/TOOLING_CATALOG.md`. A per-source subdomain ledger is optional supporting evidence, not a gate.
- Technique-specific procedures: load the relevant specialist `SKILL.md`; do not copy global tool/helper lists into skills.
- Global public-research ingestion: `.cyberstrike/commands/update.md` and `packages/cyberstrike/src/research/sources.ts`.
- Target-specific observations and normalized inventories belong in the existing target workspace via the registered target tools. Preserve the one-workspace, canonical-artifact, resume, and verification rules above.


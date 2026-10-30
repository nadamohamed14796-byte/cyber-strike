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


## Single workflow ownership

Use one source of truth for each responsibility. Keep shared behavior here rather than copying variants across prompts, commands, and skills.

1. **Runtime target workflow:** `packages/cyberstrike/src/agent/prompt/methodology/target-workflow.txt` is the single authority for scope, workspace, checkpoint/resume, tool choice, skill chaining, artifact handling, loop avoidance, and reporting. `packages/cyberstrike/src/session/prompt.ts` injects it for target-related work. Do not duplicate or override these rules in `cyberstrike.txt` or `common-methodology.txt`.

2. **Recon execution:** `packages/cyberstrike/src/command/template/recon.txt` owns the practical recon steps and checkpoint workflow. `.cyberstrike/skill/recon-methodology/RECON_PHASE_TOOL_MATRIX.md` describes phase outputs; `packages/cyberstrike/src/tool/recon-checkpoint.ts` owns checkpoint behavior and schema. Phase lists and `.cyberstrike/skill/community-tool-selection/TOOLING_CATALOG.md` are references, not tool allowlists; if the catalog is absent, continue with registered-tool discovery.

3. **Message and event delivery:** `docs/agent-message-flow.md` documents the end-to-end contract. Event schemas live in `packages/cyberstrike/src/session/message-v2.ts`; persistence lives in `session/index.ts`; stream processing lives in `session/processor.ts`; bus dispatch lives in `src/bus`; client state updates live in `packages/app/src/context/global-sync/event-reducer.ts`. Keep generated SDK event types synchronized with the schemas; regenerate the JavaScript SDK with `./packages/sdk/js/script/build.ts`.

4. **Skills and chaining:** each specialist `SKILL.md` owns its technique-specific procedure. Load the next skill only when evidence creates a concrete need. Pass verified observations, evidence/artifact IDs, prerequisites, constraints, and unresolved questions between agents. Do not copy global tool lists into individual skills or create parallel chain/inventory ledgers.

5. **Research ingestion:** `.cyberstrike/commands/update.md` and `packages/cyberstrike/src/research/sources.ts` own the global public-research ingestion workflow.

6. **Artifacts:** use structured target tools and the existing canonical root workspace for target-specific notes, inventories, checkpoints, and files. Do not guess output paths, create a workspace per host, or claim success until saved paths and counts are verified.

7. **Agent identity and invocation:** the key in the Agent registry is the stable invocation ID. Configured `name` values are display labels only and may be renamed or duplicated. Any routing, task permission check, delegation argument, resume lookup, or cross-agent reference must use the stable registry key. Use `Agent.entries()` when both the key and metadata are needed; use `Agent.get()` for key lookup (or a unique display-name compatibility lookup). Never build Task tool choices from display labels. Keep agent prompts, permissions, skill references, and registered tool names aligned, and cover cross-registry links with regression tests.


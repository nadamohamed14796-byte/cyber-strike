import { expect, test } from "bun:test"
import { initialReconRun, invalidateReconDownstreamPhases, parseReconRun, reconPhaseExecutionDecision, reconPhaseStartDecision, reconScopeFingerprint } from "../../src/target/recon-gate"
import {
  reconRunID,
  reconBeginDisposition,
  RECON_PHASE_ARTIFACT_AREAS,
  missingRequiredReconArtifacts,
  validateCanonicalInventoryContent,
  unresolvedReconPrerequisites,
  reconcileReconTodoChecklist,
  type ReconPhase,
  type ReconPhaseRecord,
} from "../../src/tool/recon-checkpoint"

const phases: ReconPhase[] = [
  "scope_validation",
  "workspace_setup",
  "asset_discovery",
  "live_hosts_ports",
  "url_collection",
  "javascript_analysis",
  "parameter_discovery",
  "directory_fuzzing",
  "endpoint_inventory",
  "parameter_fuzzing",
  "vulnerability_testing",
  "reporting",
]

function records(status: ReconPhaseRecord["status"] = "pending"): Record<ReconPhase, ReconPhaseRecord> {
  return Object.fromEntries(phases.map((phase) => [phase, { status }])) as Record<ReconPhase, ReconPhaseRecord>
}

test("phase transitions require a resolved earlier phase, but partial handoff unlocks progress", () => {
  const state = records("complete")
  state.url_collection = { status: "running" }
  const waiting = reconPhaseStartDecision("javascript_analysis", state)
  expect(waiting.allowed).toBe(false)
  expect(waiting.unresolved).toEqual(["url_collection"])

  state.url_collection = { status: "partial", reason: "one collector timed out after alternate source was tried" }
  expect(reconPhaseStartDecision("javascript_analysis", state).allowed).toBe(true)

  state.scope_validation = { status: "pending" }
  expect(reconPhaseStartDecision("javascript_analysis", state).unresolved).toContain("scope_validation")

  state.scope_validation = { status: "complete" }
  state.workspace_setup = { status: "pending" }
  expect(reconPhaseStartDecision("javascript_analysis", state).unresolved).toEqual(["workspace_setup"])

  state.workspace_setup = { status: "complete" }
  state.endpoint_inventory = { status: "pending" }
  expect(reconPhaseStartDecision("vulnerability_testing", state).unresolved).toContain("endpoint_inventory")

  state.endpoint_inventory = { status: "complete" }
  state.javascript_analysis = { status: "failed", reason: "one source failed" }
  expect(reconPhaseStartDecision("vulnerability_testing", state).unresolved).toContain("javascript_analysis")
  state.javascript_analysis = { status: "partial", reason: "saved evidence and resume point" }
  expect(reconPhaseStartDecision("vulnerability_testing", state).allowed).toBe(true)
})

test("the recon checklist is checkpoint-driven, ordered, and preserves unrelated todos", () => {
  const state = records("pending")
  state.scope_validation = { status: "complete" }
  state.workspace_setup = { status: "complete" }
  state.asset_discovery = { status: "complete" }
  state.live_hosts_ports = { status: "running" }

  const result = reconcileReconTodoChecklist([
    { content: "Unrelated user task", status: "pending", priority: "medium" },
    { content: "[recon:asset_discovery] old wording", status: "pending", priority: "low" },
    { content: "[recon:javascript_analysis] old wording", status: "in_progress", priority: "low" },
  ], state, "live_hosts_ports")

  expect(result[0]).toEqual({
    content: "[recon:scope_validation] 1. Verify saved scope and exclusions",
    status: "completed",
    priority: "high",
  })
  expect(result.find((item) => item.content.startsWith("[recon:workspace_setup]") )?.status).toBe("completed")
  expect(result.find((item) => item.content.startsWith("[recon:asset_discovery]") )?.status).toBe("completed")
  expect(result.find((item) => item.content.startsWith("[recon:live_hosts_ports]") )?.status).toBe("in_progress")
  expect(result.find((item) => item.content.startsWith("[recon:javascript_analysis]") )?.status).toBe("pending")
  expect(result.some((item) => item.content.startsWith("[recon:parameter_fuzzing]"))).toBe(false)
  expect(result.at(-1)).toEqual({ content: "Unrelated user task", status: "pending", priority: "medium" })
  expect(result.filter((item) => item.content.startsWith("[recon:asset_discovery]"))).toHaveLength(1)
})

test("partial handoffs stay visible without keeping the todo queue stuck on that phase", () => {
  const state = records("complete")
  state.javascript_analysis = { status: "partial", reason: "one source is still unavailable" }
  const result = reconcileReconTodoChecklist([], state, null)
  const item = result.find((todo) => todo.content.startsWith("[recon:javascript_analysis]"))
  expect(item?.status).toBe("cancelled")
  expect(item?.content).toContain("partial handoff; revisit when useful")
  expect(unresolvedReconPrerequisites("parameter_discovery", state)).toEqual([])
})

test("optional active-testing checklist items appear only when requested or already present", () => {
  const state = records("pending")
  const defaultList = reconcileReconTodoChecklist([], state, null)
  expect(defaultList.some((item) => item.content.startsWith("[recon:vulnerability_testing]"))).toBe(false)

  const requested = reconcileReconTodoChecklist([], state, "vulnerability_testing", ["vulnerability_testing"])
  expect(requested.some((item) => item.content.startsWith("[recon:vulnerability_testing]"))).toBe(true)
  expect(requested.some((item) => item.content.startsWith("[recon:parameter_fuzzing]"))).toBe(false)

  const kept = reconcileReconTodoChecklist([
    { content: "[recon:parameter_fuzzing] existing", status: "completed", priority: "low" },
  ], state, null)
  expect(kept.find((item) => item.content.startsWith("[recon:parameter_fuzzing]"))?.status).toBe("pending")
})

test("recon run identity is stable across session resumes", () => {
  expect(reconRunID("target-root-1")).toBe(reconRunID("target-root-1"))
  expect(reconRunID("target-root-1")).not.toBe(reconRunID("different-target"))
})

test("begin resumes running phases and does not restart resolved work", () => {
  expect(reconBeginDisposition("running", "url_collection")).toBe("resume_existing")
  expect(reconBeginDisposition("complete", "url_collection")).toBe("already_resolved")
  expect(reconBeginDisposition("unavailable", "url_collection")).toBe("start")
  expect(reconBeginDisposition("unavailable", "scope_validation")).toBe("start")
  expect(reconBeginDisposition("unavailable", "workspace_setup")).toBe("start")
  expect(reconBeginDisposition("pending", "url_collection")).toBe("start")
  expect(reconBeginDisposition("failed", "url_collection")).toBe("start")
  expect(reconBeginDisposition("blocked", "url_collection")).toBe("start")
  expect(reconBeginDisposition("partial", "javascript_analysis")).toBe("start")
  expect(reconBeginDisposition("deferred", "vulnerability_testing")).toBe("start")
})

test("reopening unavailable work invalidates downstream completion", () => {
  const state = records("complete")
  state.url_collection = { status: "unavailable", reason: "crawler unavailable" }
  const invalidated = invalidateReconDownstreamPhases("url_collection", state, "source/tool availability changed")
  expect(invalidated).toContain("javascript_analysis")
  expect(state.javascript_analysis.status).toBe("pending")
  expect(state.reporting.status).toBe("pending")
})

test("recon phases cannot skip pending prerequisites", () => {
  const state = records()
  expect(unresolvedReconPrerequisites("asset_discovery", state)).toEqual([
    "scope_validation",
    "workspace_setup",
  ])
})

test("scope must be completed, not unavailable, before discovery or testing", () => {
  const state = records("complete")
  state.scope_validation = { status: "unavailable", reason: "Could not verify policy" }
  expect(unresolvedReconPrerequisites("asset_discovery", state)).toContain("scope_validation")
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toContain("scope_validation")
})

test("phase order follows collection, JavaScript, parameters, path discovery, and final endpoint correlation", () => {
  expect(phases.indexOf("javascript_analysis")).toBe(phases.indexOf("url_collection") + 1)
  expect(phases.indexOf("parameter_discovery")).toBe(phases.indexOf("javascript_analysis") + 1)
  expect(phases.indexOf("directory_fuzzing")).toBe(phases.indexOf("parameter_discovery") + 1)
  expect(phases.indexOf("endpoint_inventory")).toBe(phases.indexOf("directory_fuzzing") + 1)
  expect(phases.indexOf("parameter_fuzzing")).toBe(phases.indexOf("endpoint_inventory") + 1)
})

test("unfinished phases remain required until completed or explicitly handed off", () => {
  const state = records("complete")
  state.javascript_analysis = { status: "pending" }
  expect(unresolvedReconPrerequisites("parameter_discovery", state)).toContain("javascript_analysis")
  state.javascript_analysis = { status: "partial", reason: "source map still pending" }
  expect(unresolvedReconPrerequisites("parameter_discovery", state)).toEqual([])

  state.parameter_discovery = { status: "pending" }
  expect(unresolvedReconPrerequisites("directory_fuzzing", state)).toContain("parameter_discovery")
  state.parameter_discovery = { status: "partial", reason: "one parameter tool unavailable" }
  expect(unresolvedReconPrerequisites("directory_fuzzing", state)).toEqual([])

  state.directory_fuzzing = { status: "running" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toContain("directory_fuzzing")
  state.directory_fuzzing = { status: "partial", reason: "wordlist branch timed out" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toEqual([])

  state.endpoint_inventory = { status: "complete" }
  state.parameter_fuzzing = { status: "pending" }
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toEqual([])
})

test("workspace setup cannot be bypassed by marking it unavailable", () => {
  const state = records("complete")
  state.workspace_setup = { status: "unavailable", reason: "workspace files missing" }
  expect(unresolvedReconPrerequisites("asset_discovery", state)).toContain("workspace_setup")
})

test("failed phases need an explicit handoff before later checkpoints start", () => {
  const state = records("complete")
  state.javascript_analysis = { status: "unavailable", reason: "No JavaScript assets were observed" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toEqual([])
  state.live_hosts_ports = { status: "failed", reason: "Scanner failed" }
  expect(unresolvedReconPrerequisites("url_collection", state)).toContain("live_hosts_ports")
  state.live_hosts_ports = { status: "partial", reason: "alternate source was tried" }
  expect(unresolvedReconPrerequisites("url_collection", state)).toEqual([])
})

test("parameter discovery must be resolved or handed off before endpoint inventory", () => {
  const state = records("complete")
  state.parameter_discovery = { status: "pending" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toContain("parameter_discovery")
  state.parameter_discovery = { status: "complete", summary: "parameter inventory saved" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toEqual([])
  state.parameter_discovery = { status: "partial", reason: "secondary source unavailable" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toEqual([])
})

test("endpoint inventory cannot be bypassed with unavailable status", () => {
  const state = records("complete")
  state.endpoint_inventory = { status: "unavailable", reason: "inventory tool missing" }
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toContain("endpoint_inventory")
})

test("parameter fuzzing is opt-in and requires a complete endpoint inventory", () => {
  const state = records("complete")
  state.parameter_fuzzing = { status: "deferred", reason: "Active testing not requested" }
  expect(reconPhaseExecutionDecision("parameter_fuzzing", state).allowed).toBe(false)
  state.parameter_fuzzing = { status: "running" }
  state.endpoint_inventory = { status: "unavailable", reason: "Inventory incomplete" }
  expect(reconPhaseExecutionDecision("parameter_fuzzing", state).allowed).toBe(false)
  state.endpoint_inventory = { status: "complete" }
  expect(reconPhaseExecutionDecision("parameter_fuzzing", state).allowed).toBe(true)
})

test("a fully resolved inventory allows the vulnerability phase", () => {
  const state = records("complete")
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toEqual([])
})

test("recon can reach reporting while vulnerability testing is explicitly deferred", () => {
  const state = records("complete")
  state.vulnerability_testing = { status: "deferred", reason: "Awaiting user request" }
  expect(unresolvedReconPrerequisites("reporting", state)).toEqual([])
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toEqual([])
})

test("reopening a phase marks downstream outputs stale without losing their evidence links", () => {
  const state = records("complete")
  state.reporting = {
    status: "complete",
    startedAt: "2026-10-20T09:00:00.000Z",
    finishedAt: "2026-10-20T09:01:00.000Z",
    summary: "Old pre-testing report",
    counts: { endpoints: 12 },
    artifacts: ["reports/recon-final.md"],
  }
  const reason = "Regenerate this downstream checkpoint after vulnerability_testing was explicitly reopened."
  expect(invalidateReconDownstreamPhases("vulnerability_testing", state, reason)).toEqual(["reporting"])
  expect(state.reporting).toEqual({
    status: "pending",
    startedAt: undefined,
    finishedAt: undefined,
    summary: "Old pre-testing report",
    counts: { endpoints: 12 },
    artifacts: ["reports/recon-final.md"],
    reason,
  })
})

test("active parameter fuzzing can be deferred so recon-only reporting can finish", () => {
  const state = records("complete")
  state.parameter_fuzzing = { status: "deferred", reason: "Active tests not requested" }
  expect(unresolvedReconPrerequisites("reporting", state)).toEqual([])
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toEqual([])
})

test("old workflow checkpoints preserve discovery but reopen JavaScript and downstream phases", () => {
  const old = initialReconRun("https://example.com", "target-root-1", "session-1")
  delete old.phaseOrderVersion
  old.phases.asset_discovery = { status: "complete", artifacts: ["subdomains.txt"] }
  old.phases.live_hosts_ports = { status: "complete", artifacts: ["live-hosts.txt"] }
  old.phases.url_collection = { status: "complete", artifacts: ["urls.txt"] }
  old.phases.javascript_analysis = { status: "complete", artifacts: ["javascript-analysis.md", "endpoints.txt"] }
  old.phases.parameter_discovery = { status: "complete", artifacts: ["parameters.txt"] }
  old.phases.directory_fuzzing = { status: "complete", artifacts: ["directories/path-discovery.md"] }
  old.phases.endpoint_inventory = { status: "complete", artifacts: ["endpoints.txt"] }
  old.phases.parameter_fuzzing = { status: "deferred", reason: "Old recon-only run" }
  old.phases.vulnerability_testing = { status: "deferred", reason: "Old recon-only run" }
  old.phases.reporting = { status: "complete", artifacts: ["reports/recon-final.md"] }

  const migrated = parseReconRun(JSON.stringify(old), "target-root-1", "https://example.com")
  expect(migrated.phaseOrderVersion).toBe(2)
  expect(migrated.currentPhase).toBe("javascript_analysis")
  expect(migrated.phases.asset_discovery.status).toBe("complete")
  expect(migrated.phases.live_hosts_ports.status).toBe("complete")
  expect(migrated.phases.url_collection.status).toBe("complete")
  expect(migrated.phases.javascript_analysis.status).toBe("pending")
  expect(migrated.phases.parameter_discovery.status).toBe("pending")
  expect(migrated.phases.directory_fuzzing.status).toBe("pending")
  expect(migrated.phases.endpoint_inventory.status).toBe("pending")
  expect(migrated.phases.parameter_fuzzing.status).toBe("pending")
  expect(migrated.phases.vulnerability_testing.status).toBe("pending")
  expect(migrated.phases.reporting.status).toBe("pending")
})

test("deferred is accepted as a persisted checkpoint status", () => {
  const run = initialReconRun("https://example.com", "target-root-1", "session-1")
  run.phases.vulnerability_testing = { status: "deferred", reason: "Recon-only handoff" }
  const parsed = parseReconRun(JSON.stringify(run), "target-root-1", "https://example.com")
  expect(parsed.phases.vulnerability_testing.status).toBe("deferred")
})

test("legacy manifests migrate to require parameter discovery and revalidate downstream phases", () => {
  const legacy = initialReconRun("https://example.com", "target-root-1", "session-1")
  delete (legacy.phases as Partial<Record<ReconPhase, ReconPhaseRecord>>).directory_fuzzing
  delete (legacy.phases as Partial<Record<ReconPhase, ReconPhaseRecord>>).parameter_discovery
  delete (legacy.phases as Partial<Record<ReconPhase, ReconPhaseRecord>>).parameter_fuzzing
  legacy.phases.parameter_discovery = { status: "complete", summary: "old parameter list" }
  legacy.phases.javascript_analysis = { status: "complete", summary: "old JS analysis" }
  legacy.phases.endpoint_inventory = { status: "complete", summary: "old endpoint inventory", artifacts: ["endpoints/old.json"] }
  legacy.phases.vulnerability_testing = { status: "complete", summary: "old tests", artifacts: ["testing/old.json"] }
  legacy.phases.reporting = { status: "complete", summary: "old report", artifacts: ["reports/old.md"] }

  const migrated = parseReconRun(JSON.stringify(legacy), "target-root-1", "https://example.com")
  expect(migrated.phases.directory_fuzzing.status).toBe("pending")
  expect(migrated.phases.parameter_discovery.status).toBe("pending")
  expect(migrated.phases.parameter_fuzzing.status).toBe("pending")
  expect(migrated.phases.javascript_analysis.status).toBe("pending")
  expect(migrated.phases.endpoint_inventory.status).toBe("pending")
  expect(migrated.phases.vulnerability_testing.status).toBe("pending")
  expect(migrated.phases.reporting.status).toBe("pending")
  expect(migrated.phases.endpoint_inventory.artifacts).toEqual(["endpoints/old.json"])
})


test("JavaScript correlation artifacts can be checkpointed in their canonical areas", () => {
  const areas = RECON_PHASE_ARTIFACT_AREAS.javascript_analysis
  expect(areas).toEqual(["javascript", "endpoints", "testing"])
  expect(areas?.some((area) => "javascript/example-graph.json".startsWith(area + "/"))).toBe(true)
  expect(areas?.some((area) => "endpoints/example-candidates.json".startsWith(area + "/"))).toBe(true)
  expect(areas?.some((area) => "testing/tester-survey-example.json".startsWith(area + "/"))).toBe(true)
  expect(areas?.some((area) => "reports/example.md".startsWith(area + "/"))).toBe(false)
})

test("vulnerability testing artifacts must be saved in a testing, findings, or evidence area", () => {
  const areas = RECON_PHASE_ARTIFACT_AREAS.vulnerability_testing
  expect(areas).toEqual(["testing", "findings", "evidence"])
  expect(areas?.some((area) => "findings/issue-1.json".startsWith(area + "/"))).toBe(true)
  expect(areas?.some((area) => "evidence/request-1.txt".startsWith(area + "/"))).toBe(true)
  expect(areas?.some((area) => "reports/random.md".startsWith(area + "/"))).toBe(false)
})


test("core discovery phases require canonical root inventories", () => {
  expect(missingRequiredReconArtifacts("asset_discovery", ["assets/subdomains-raw.txt"])).toEqual(["subdomains.txt"])
  expect(missingRequiredReconArtifacts("asset_discovery", ["subdomains.txt"])).toEqual([])
  expect(missingRequiredReconArtifacts("live_hosts_ports", ["recon/raw/httpx-output.txt"])).toEqual(["live-hosts.txt"])
  expect(missingRequiredReconArtifacts("live_hosts_ports", ["live-hosts.txt"])).toEqual([])
  expect(missingRequiredReconArtifacts("url_collection", ["urls/raw/katana.txt"])).toEqual(["urls.txt"])
  expect(missingRequiredReconArtifacts("url_collection", ["urls.txt"])).toEqual([])
  expect(missingRequiredReconArtifacts("parameter_discovery", ["parameters/observed.txt"])).toEqual(["parameters.txt"])
  expect(missingRequiredReconArtifacts("parameter_discovery", ["parameters.txt"])).toEqual([])
})

test("canonical inventories reject empty, failure-only, and log-shaped output", () => {
  expect(validateCanonicalInventoryContent("live_hosts_ports", "").valid).toBe(false)
  expect(validateCanonicalInventoryContent("live_hosts_ports", "[FAILED] https://example.com").valid).toBe(false)
  expect(validateCanonicalInventoryContent("url_collection", "ERROR: command not found").valid).toBe(false)
  expect(validateCanonicalInventoryContent("url_collection", "https://example.com/a\nhttps://example.com/b")).toEqual({
    valid: true,
    entries: 2,
  })
  expect(validateCanonicalInventoryContent("asset_discovery", "status: zero-results").valid).toBe(true)
  expect(validateCanonicalInventoryContent("parameter_discovery", "incomplete: source timed out").valid).toBe(true)
})

test("partial JavaScript analysis does not block parameter discovery or truthful closeout", () => {
  const state = records("complete")
  state.javascript_analysis = { status: "partial", reason: "remaining source map is unavailable" }
  expect(unresolvedReconPrerequisites("parameter_discovery", state)).toEqual([])
  expect(unresolvedReconPrerequisites("reporting", state)).toEqual([])
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toEqual([])
})

test("ordinary recon tools are allowed when no checkpoint is actively running", () => {
  const state = records("complete")
  const decision = reconPhaseExecutionDecision("url_collection", state)
  expect(decision.allowed).toBe(true)
  expect(decision.reason).toContain("not restricted by checkpoint phase")
})

test("ordinary recon tools are not restricted to the active checkpoint", () => {
  const state = records("complete")
  state.asset_discovery = { status: "running" }
  const decision = reconPhaseExecutionDecision("url_collection", state)
  expect(decision.allowed).toBe(true)
  expect(decision.reason).toContain("not restricted by checkpoint phase")
})

test("ordinary recon tools remain allowed with any checkpoint combination", () => {
  for (const activePhase of phases) {
    const state = records("complete")
    state[activePhase] = { status: "running" }
    const decision = reconPhaseExecutionDecision("asset_discovery", state)
    expect(decision.allowed).toBe(true)
  }
})

test("ordinary recon tools are not blocked when multiple checkpoints are running", () => {
  const state = records("complete")
  state.url_collection = { status: "running" }
  state.asset_discovery = { status: "running" }
  const decision = reconPhaseExecutionDecision("url_collection", state)
  expect(decision.allowed).toBe(true)
})

test("ordinary recon tools are not blocked by failed earlier phase status", () => {
  const state = records("complete")
  state.url_collection = { status: "running" }
  state.live_hosts_ports = { status: "failed", reason: "scanner failed" }
  const decision = reconPhaseExecutionDecision("asset_discovery", state)
  expect(decision.allowed).toBe(true)
})

test("vulnerability-testing tools remain blocked outside the explicit testing checkpoint", () => {
  const state = records("complete")
  state.url_collection = { status: "running" }
  const decision = reconPhaseExecutionDecision("vulnerability_testing", state)
  expect(decision.allowed).toBe(false)
  expect(decision.reason).toContain("Vulnerability testing is opt-in")
})

test("active-testing tools reject an earlier failed phase until it is handed off", () => {
  const state = records("complete")
  state.vulnerability_testing = { status: "running" }
  state.javascript_analysis = { status: "failed", reason: "source map parser failed" }
  expect(reconPhaseExecutionDecision("vulnerability_testing", state).allowed).toBe(false)
  state.javascript_analysis = { status: "partial", reason: "saved evidence and resume point" }
  expect(reconPhaseExecutionDecision("vulnerability_testing", state).allowed).toBe(true)
})

test("vulnerability-testing tools require an explicit testing checkpoint and completed handoff", () => {
  const state = records("complete")
  state.vulnerability_testing = { status: "running" }
  const decision = reconPhaseExecutionDecision("vulnerability_testing", state)
  expect(decision).toEqual({
    allowed: true,
    reason: "explicit vulnerability-testing checkpoint and prerequisites passed",
  })
})

test("ordinary recon tool choice is independent of the active phase", () => {
  const state = records("complete")
  state.url_collection = { status: "running" }
  const decision = reconPhaseExecutionDecision("asset_discovery", state)
  expect(decision).toEqual({
    allowed: true,
    reason: "ordinary reconnaissance tools are not restricted by checkpoint phase or prerequisite status",
  })
})

test("ordinary recon remains available when checkpoint state is missing or pending", () => {
  const state = records("pending")
  expect(reconPhaseExecutionDecision("asset_discovery", state).allowed).toBe(true)
  expect(reconPhaseExecutionDecision("url_collection", state).allowed).toBe(true)
  expect(reconPhaseExecutionDecision("javascript_analysis", state).allowed).toBe(true)
  expect(reconPhaseExecutionDecision("vulnerability_testing", state).allowed).toBe(false)
})


test("scope fingerprint ignores item ordering but changes with effective authorization data", () => {
  const base = {
    targetURL: "https://program.example.test",
    status: "configured" as const,
    scopeItems: ["api.example.net", "*.example.net"],
    excludedItems: ["admin.example.net"],
    authorizationSource: "Unit test policy",
    authorizationReference: "https://program.example.test/policy",
  }
  expect(reconScopeFingerprint(base)).toBe(reconScopeFingerprint({
    ...base,
    scopeItems: [...base.scopeItems].reverse(),
    excludedItems: [...base.excludedItems].reverse(),
  }))
  expect(reconScopeFingerprint(base)).not.toBe(reconScopeFingerprint({
    ...base,
    excludedItems: [...base.excludedItems, "private.example.net"],
  }))
  expect(reconScopeFingerprint(base)).not.toBe(reconScopeFingerprint({
    ...base,
    authorizationReference: "https://program.example.test/updated-policy",
  }))
})

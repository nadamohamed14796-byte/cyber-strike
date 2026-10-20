import { expect, test } from "bun:test"
import { initialReconRun, invalidateReconDownstreamPhases, parseReconRun } from "../../src/target/recon-gate"
import {
  reconRunID,
  reconBeginDisposition,
  RECON_PHASE_ARTIFACT_AREAS,
  unresolvedReconPrerequisites,
  type ReconPhase,
  type ReconPhaseRecord,
} from "../../src/tool/recon-checkpoint"

const phases: ReconPhase[] = [
  "scope_validation",
  "workspace_setup",
  "asset_discovery",
  "live_hosts_ports",
  "url_collection",
  "directory_fuzzing",
  "parameter_discovery",
  "parameter_fuzzing",
  "javascript_analysis",
  "endpoint_inventory",
  "vulnerability_testing",
  "reporting",
]

function records(status: ReconPhaseRecord["status"] = "pending"): Record<ReconPhase, ReconPhaseRecord> {
  return Object.fromEntries(phases.map((phase) => [phase, { status }])) as Record<ReconPhase, ReconPhaseRecord>
}

test("recon run identity is stable across session resumes", () => {
  expect(reconRunID("target-root-1")).toBe(reconRunID("target-root-1"))
  expect(reconRunID("target-root-1")).not.toBe(reconRunID("different-target"))
})

test("begin resumes running phases and does not restart resolved work", () => {
  expect(reconBeginDisposition("running", "url_collection")).toBe("resume_existing")
  expect(reconBeginDisposition("complete", "url_collection")).toBe("already_resolved")
  expect(reconBeginDisposition("unavailable", "url_collection")).toBe("already_resolved")
  expect(reconBeginDisposition("unavailable", "scope_validation")).toBe("start")
  expect(reconBeginDisposition("unavailable", "workspace_setup")).toBe("start")
  expect(reconBeginDisposition("pending", "url_collection")).toBe("start")
  expect(reconBeginDisposition("failed", "url_collection")).toBe("start")
  expect(reconBeginDisposition("blocked", "url_collection")).toBe("start")
  expect(reconBeginDisposition("deferred", "vulnerability_testing")).toBe("start")
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

test("phase order separates directory and parameter fuzzing from passive discovery", () => {
  expect(phases.indexOf("directory_fuzzing")).toBe(phases.indexOf("url_collection") + 1)
  expect(phases.indexOf("parameter_discovery")).toBe(phases.indexOf("directory_fuzzing") + 1)
  expect(phases.indexOf("parameter_fuzzing")).toBe(phases.indexOf("parameter_discovery") + 1)
  expect(phases.indexOf("javascript_analysis")).toBe(phases.indexOf("parameter_fuzzing") + 1)
  expect(phases.indexOf("endpoint_inventory")).toBe(phases.indexOf("javascript_analysis") + 1)
})

test("directory and parameter fuzzing are ordered prerequisites", () => {
  const state = records("complete")
  state.directory_fuzzing = { status: "pending" }
  expect(unresolvedReconPrerequisites("parameter_discovery", state)).toContain("directory_fuzzing")
  state.directory_fuzzing = { status: "complete" }
  state.parameter_fuzzing = { status: "pending" }
  expect(unresolvedReconPrerequisites("javascript_analysis", state)).toContain("parameter_fuzzing")
  state.parameter_fuzzing = { status: "complete" }
  expect(unresolvedReconPrerequisites("javascript_analysis", state)).toEqual([])
})

test("workspace setup cannot be bypassed by marking it unavailable", () => {
  const state = records("complete")
  state.workspace_setup = { status: "unavailable", reason: "workspace files missing" }
  expect(unresolvedReconPrerequisites("asset_discovery", state)).toContain("workspace_setup")
})

test("unavailable non-scope phases are explicit terminal checkpoints", () => {
  const state = records("complete")
  state.javascript_analysis = { status: "unavailable", reason: "No JavaScript assets were observed" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toEqual([])
  state.live_hosts_ports = { status: "failed", reason: "Scanner failed" }
  expect(unresolvedReconPrerequisites("url_collection", state)).toContain("live_hosts_ports")
})

test("parameter discovery is a distinct prerequisite before endpoint inventory", () => {
  const state = records("complete")
  state.parameter_discovery = { status: "pending" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toContain("parameter_discovery")
  state.parameter_discovery = { status: "complete", summary: "parameter inventory saved" }
  expect(unresolvedReconPrerequisites("endpoint_inventory", state)).toEqual([])
})

test("endpoint inventory cannot be bypassed with unavailable status", () => {
  const state = records("complete")
  state.endpoint_inventory = { status: "unavailable", reason: "inventory tool missing" }
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toContain("endpoint_inventory")
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

test("reopening deferred vulnerability testing clears stale downstream reports", () => {
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
  expect(state.reporting).toEqual({ status: "pending", reason })
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

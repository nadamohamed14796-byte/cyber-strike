import { expect, test } from "bun:test"
import { initialReconRun, parseReconRun } from "../../src/target/recon-gate"
import {
  reconRunID,
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
  "parameter_discovery",
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

test("legacy manifests migrate to require parameter discovery and revalidate downstream phases", () => {
  const legacy = initialReconRun("https://example.com", "target-root-1", "session-1")
  delete (legacy.phases as Partial<Record<ReconPhase, ReconPhaseRecord>>).parameter_discovery
  legacy.phases.endpoint_inventory = { status: "complete", summary: "old endpoint inventory", artifacts: ["endpoints/old.json"] }
  legacy.phases.vulnerability_testing = { status: "complete", summary: "old tests", artifacts: ["testing/old.json"] }
  legacy.phases.reporting = { status: "complete", summary: "old report", artifacts: ["reports/old.md"] }

  const migrated = parseReconRun(JSON.stringify(legacy), "target-root-1", "https://example.com")
  expect(migrated.phases.parameter_discovery.status).toBe("pending")
  expect(migrated.phases.endpoint_inventory.status).toBe("pending")
  expect(migrated.phases.vulnerability_testing.status).toBe("pending")
  expect(migrated.phases.reporting.status).toBe("pending")
  expect(migrated.phases.endpoint_inventory.artifacts).toEqual(["endpoints/old.json"])
})

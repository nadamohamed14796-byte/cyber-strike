import { expect, test } from "bun:test"
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

test("endpoint inventory cannot be bypassed with unavailable status", () => {
  const state = records("complete")
  state.endpoint_inventory = { status: "unavailable", reason: "inventory tool missing" }
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toContain("endpoint_inventory")
})

test("a fully resolved inventory allows the vulnerability phase", () => {
  const state = records("complete")
  expect(unresolvedReconPrerequisites("vulnerability_testing", state)).toEqual([])
})

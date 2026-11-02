import { describe, expect, test } from "bun:test"
import { batchAllowedToolIDs } from "../../src/tool/batch"
import { PermissionNext } from "../../src/permission/next"

describe("batch tool permission parity", () => {
  const permission: PermissionNext.Ruleset = [
    { permission: "bash", pattern: "*", action: "deny" },
    { permission: "edit", pattern: "*", action: "deny" },
    { permission: "task", pattern: "*", action: "deny" },
  ]

  test("honors user-disabled tools and the caller agent's deny rules", () => {
    const allowed = batchAllowedToolIDs({
      toolIDs: ["read", "grep", "bash", "edit", "write", "task"],
      agentID: "cyberstrike",
      agentMode: "primary",
      permission,
      userTools: { read: false },
    })

    expect([...allowed].sort()).toEqual(["grep"])
  })

  test("preserves only the narrow internal Impact Hunter task exception", () => {
    const proxyTester = batchAllowedToolIDs({
      toolIDs: ["task", "read"],
      agentID: "proxy-tester-idor",
      agentMode: "subagent",
      permission,
    })
    expect([...proxyTester].sort()).toEqual(["read", "task"])

    const primary = batchAllowedToolIDs({
      toolIDs: ["task", "read"],
      agentID: "cyberstrike",
      agentMode: "primary",
      permission,
    })
    expect([...primary]).toEqual(["read"])

    const impactHunter = batchAllowedToolIDs({
      toolIDs: ["task", "read"],
      agentID: "impact-hunter",
      agentMode: "subagent",
      permission,
    })
    expect([...impactHunter]).toEqual(["read"])
  })

  test("an explicit user disable always wins over the internal task exception", () => {
    const allowed = batchAllowedToolIDs({
      toolIDs: ["task", "read"],
      agentID: "proxy-tester-idor",
      agentMode: "subagent",
      permission,
      userTools: { task: false },
    })
    expect([...allowed]).toEqual(["read"])
  })
})

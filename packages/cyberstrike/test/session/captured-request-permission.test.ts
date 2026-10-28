import { describe, expect, test } from "bun:test"
import { PermissionNext } from "../../src/permission/next"
import { proxyAnalyzerTaskPermission } from "../../src/session/captured-request-permission"

describe("proxy-analyzer task permission for captured requests", () => {
  const defaultAllow: PermissionNext.Ruleset = [
    { permission: "*", pattern: "*", action: "deny" },
    { permission: "task", pattern: "*", action: "allow" },
  ]

  test("allows the required analyzer when the effective rule allows it", () => {
    expect(proxyAnalyzerTaskPermission(defaultAllow)).toBe("allow")
  })

  test("respects a later targeted deny even when a task allow exists", () => {
    const rules = [
      ...defaultAllow,
      { permission: "task", pattern: "proxy-analyzer", action: "deny" as const },
    ]
    expect(proxyAnalyzerTaskPermission(rules)).toBe("deny")
  })

  test("respects a later global deny that overrides the built-in allow", () => {
    const rules = [
      ...defaultAllow,
      { permission: "*", pattern: "*", action: "deny" as const },
    ]
    expect(proxyAnalyzerTaskPermission(rules)).toBe("deny")
  })

  test("does not treat an approval-gated task as enabled for unattended processing", () => {
    const rules = [
      ...defaultAllow,
      { permission: "task", pattern: "proxy-analyzer", action: "ask" as const },
    ]
    expect(proxyAnalyzerTaskPermission(rules)).toBe("ask")
  })

  test("returns ask when no permission rule matches", () => {
    expect(proxyAnalyzerTaskPermission([])).toBe("ask")
  })
})

import { describe, expect, test } from "bun:test"
import { shouldInjectMethodologyContext } from "../../src/session/methodology-context-routing"

describe("Proxy Agent methodology isolation", () => {
  test("does not inject Recon methodology context into the Proxy Agent", () => {
    expect(shouldInjectMethodologyContext("proxy-agent")).toBe(false)
  })

  test("keeps methodology context enabled for other agents", () => {
    for (const agent of ["cyberstrike", "proxy-analyzer", "web-application", undefined]) {
      expect(shouldInjectMethodologyContext(agent)).toBe(true)
    }
  })
})

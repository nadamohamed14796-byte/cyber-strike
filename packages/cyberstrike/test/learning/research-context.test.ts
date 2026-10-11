import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { ResearchContext } from "../../src/learning/research-context"
import { tmpdir } from "../fixture/fixture"

test("global research retrieval guidance is available even before target signals exist", async () => {
  await using dir = await tmpdir()
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const context = ResearchContext.generate("ses_research_baseline_test")
      expect(context).toContain("Global Research Memory — Signal-Triggered Use")
      expect(context).toContain("shared across agents and targets")
      expect(context).toContain("research_knowledge")
      expect(context).toContain("not evidence about the current target")
      await Instance.dispose()
    },
  })
})

test("request-derived global research signals are pattern-based and do not assert a vulnerability", async () => {
  const { requestResearchSignals } = await import("../../src/learning/research-context")
  expect(requestResearchSignals({ method: "GET", path: "/api/v2/orders/123", contentType: "application/json", status: 403 })).toEqual(
    expect.arrayContaining(["api-endpoint", "authorization-boundary", "object-identifier"]),
  )
  expect(requestResearchSignals({ method: "POST", path: "/checkout", contentType: "application/json", status: 200 })).toEqual(
    expect.arrayContaining(["api-endpoint", "business-logic"]),
  )
  expect(requestResearchSignals({ method: "GET", path: "/about", contentType: "text/html", status: 200 })).not.toContain("authorization-boundary")
})

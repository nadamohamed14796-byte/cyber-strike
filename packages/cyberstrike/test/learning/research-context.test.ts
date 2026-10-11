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

test("signal-triggered shared context includes richer report/writeup extraction", async () => {
  const { ReportKnowledge } = await import("../../src/learning/report-knowledge")
  await using dir = await tmpdir()
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      ReportKnowledge.ingestExternalDetailed({
        title: "Express API IDOR report with remediation",
        severity: "high",
        vulnerabilityClass: "idor",
        sourceURL: "https://research.example.test/reports/express-api-idor",
        lesson: "Compare owner and non-owner access to the same object.",
        attackVector: "Change the object identifier in an authenticated API request.",
        reproduction: "Replay the request using a second controlled account.",
        sourceTrust: 80,
        tags: ["api-endpoint", "idor", "authorization-boundary"],
        metadata: {
          source_trust: 80,
          excerpt: "A public report describes an Express API object authorization flaw.",
          extracted: {
            retrieval_signals: ["api-endpoint", "idor", "authorization-boundary"],
            affected_versions: "Express versions before 4.18.3",
            technology_stack: "Node.js Express middleware",
            remediation: "Enforce object-level authorization for each request.",
            attack_chain: "The exposed route enabled access to another account's record.",
            negative_evidence: "A public object identifier alone did not prove unauthorized access.",
          },
        },
      })
      const context = ResearchContext.generate("ses_research_global_fields")
      expect(context).toContain("Affected versions reported")
      expect(context).toContain("Technology/framework clues")
      expect(context).toContain("Remediation described by source")
      expect(context).toContain("Attack-chain notes")
      expect(context).toContain("Negative/failed evidence")
      expect(context).toContain("https://research.example.test/reports/express-api-idor")
      await Instance.dispose()
    },
  })
})

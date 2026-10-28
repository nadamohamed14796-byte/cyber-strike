import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Intel } from "../../src/methodology/intel"
import { Chain } from "../../src/methodology/chain"
import { Vulnerability } from "../../src/session/vulnerability"
import { GenerateReportTool } from "../../src/tool/generate-report"

function toolContext(sessionID: string) {
  return {
    sessionID,
    messageID: undefined,
    agent: "cyberstrike",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => undefined,
  } as any
}

test("generate_report exposes INFO-to-INFO chain hypotheses and their linked findings without promoting them", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        Intel.add({ sessionID: session.id, data: {
          type: "configuration",
          severity: "info",
          title: "Internal service metadata",
          detail: "Deployment configuration names internal-api.staging.example.com",
          asset: "app.example.com",
          source: "test",
          confidenceLevel: "high",
          tags: ["internal-service"],
        }})
        Intel.add({ sessionID: session.id, data: {
          type: "api_schema",
          severity: "info",
          title: "OpenAPI route metadata",
          detail: "Public API schema lists internal account-management routes",
          asset: "app.example.com",
          source: "test",
          confidenceLevel: "high",
          tags: ["route-disclosure"],
        }})

        const chains = Chain.detectAndPersist(session.id)
        const chain = chains.find((item) => item.pattern === "information_amplification")
        expect(chain).toBeDefined()
        if (!chain) throw new Error("Expected the informational chain hypothesis")

        const source = Vulnerability.add({
          sessionID: session.id,
          data: { severity: "low", title: "Finding A", description: "Independent finding A evidence" },
        })
        const target = Vulnerability.add({
          sessionID: session.id,
          data: { severity: "low", title: "Finding B", description: "Independent finding B evidence" },
        })
        const linked = Chain.linkFindings({
          sessionID: session.id,
          chainID: chain.id,
          sourceFindingID: source.id,
          targetFindingID: target.id,
          relation: "enables",
        })
        expect(linked.ok).toBe(true)

        const tool = await GenerateReportTool.init()
        const result = await tool.execute({ include_sections: ["chains"] }, toolContext(session.id))
        expect(result.output).toContain("Chain Hypotheses")
        expect(result.output).toContain("not counted as confirmed findings")
        expect(result.output).toContain("information_amplification")
        expect(result.output).toContain("POTENTIAL_INTERNAL_API_OR_SERVICE_EXPOSURE")
        expect(result.output).toContain(source.id)
        expect(result.output).toContain(target.id)
        expect(result.output).toContain("Explicit finding link; combined impact still requires validation")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

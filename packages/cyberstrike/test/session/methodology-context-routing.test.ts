import { describe, expect, test } from "bun:test"
import { shouldInjectMethodologyContext } from "../../src/session/methodology-context-routing"

describe("methodology is not an agent dispatch gate", () => {
  test("does not inject methodology context into any agent", () => {
    for (const agent of [
      "cyberstrike",
      "proxy-agent",
      "proxy-analyzer",
      "web-application",
      "proxy-tester-idor",
      "impact-hunter",
      "cloud-security",
      "internal-network",
      "unknown-agent",
      undefined,
    ]) {
      expect(shouldInjectMethodologyContext(agent)).toBe(false)
    }
  })

  test("session prompting retains no phase-dependent agent context", async () => {
    const promptSource = await Bun.file(`${import.meta.dir}/../../src/session/prompt.ts`).text()
    expect(promptSource).not.toContain("MethodologyContext.generate")
  })

  test("captured requests are sent to the Proxy Agent without a Recon-phase precondition", async () => {
    const routeSource = await Bun.file(`${import.meta.dir}/../../src/server/routes/session.ts`).text()
    const brokerStart = routeSource.indexOf("async function getOrCreateProxyBrokerSession")
    const analyzeStart = routeSource.indexOf("async function analyzeCapturedRequest", brokerStart)
    expect(brokerStart).toBeGreaterThanOrEqual(0)
    expect(analyzeStart).toBeGreaterThan(brokerStart)
    const brokerSource = routeSource.slice(brokerStart, analyzeStart)
    expect(brokerSource).not.toContain("Methodology.computeState")
    expect(brokerSource).not.toContain("MethodologyContext.generate")

    const analyzeEnd = routeSource.indexOf("\\nasync function ", analyzeStart + 1)
    const analysisSource = routeSource.slice(analyzeStart, analyzeEnd < 0 ? undefined : analyzeEnd)
    expect(analysisSource).toContain("getOrCreateProxyBrokerSession")
    expect(analysisSource).toContain("SessionPrompt.prompt")
    expect(analysisSource).not.toContain("Methodology.computeState")
    expect(analysisSource).not.toContain("MethodologyContext.generate")
    expect(routeSource).toContain('agent: (await Agent.resolveID(proxyAgent)) ?? agentName')
  })
})

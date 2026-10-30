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
  test("the session prompt applies the routing helper at methodology injection", async () => {
    const promptSource = await Bun.file(`${import.meta.dir}/../../src/session/prompt.ts`).text()
    expect(promptSource).toContain("if (shouldInjectMethodologyContext(lastUser.agent))")
    expect(promptSource).toContain("MethodologyContext.generate(Session.root(sessionID), testerClass(lastUser.agent))")
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
    expect(routeSource).toContain('agent: (await Agent.resolveID(proxyAgent)) ?? agentName')
  })

})

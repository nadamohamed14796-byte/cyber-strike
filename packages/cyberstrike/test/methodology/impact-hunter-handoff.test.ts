import { expect, test } from "bun:test"
import { Agent } from "../../src/agent/agent"
import { Instance } from "../../src/project/instance"
import { Request } from "../../src/session/request"
import { Session } from "../../src/session"
import { TargetMemory } from "../../src/target"
import { Vulnerability } from "../../src/session/vulnerability"
import { isImpactHunterCaller, startImpactHunterHandoff } from "../../src/methodology/impact-hunter-handoff"
import { tmpdir } from "../fixture/fixture"

test("Impact Hunter recursion guard follows its stable ID after a display-name change", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        "impact-hunter": { name: "Hunter Console Label", mode: "subagent" },
      },
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const hunter = await Agent.get("impact-hunter")
      expect(hunter?.name).toBe("Hunter Console Label")
      expect(await isImpactHunterCaller("impact-hunter")).toBe(true)
      expect(await isImpactHunterCaller("Hunter Console Label")).toBe(true)
      expect(await isImpactHunterCaller("cyberstrike")).toBe(false)
    },
  })
})

test("ambiguous display labels never replace stable agent identities", async () => {
  await using tmp = await tmpdir({
    config: {
      agent: {
        "impact-hunter": { name: "Shared display label" },
        worker_a: { name: "Shared display label", mode: "subagent" },
      },
    },
  })

  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      expect(await isImpactHunterCaller("Shared display label")).toBe(false)
      expect(await isImpactHunterCaller("impact-hunter")).toBe(true)
    },
  })
})


test("Impact Hunter proof-gap dispatch is suppressed during recon-only collection", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        await TargetMemory.configureScope("https://example.com", {
          include: ["example.com"],
          authorizationSource: "Impact Hunter dispatch gate fixture",
          authorizationReference: "https://example.com/security",
        })
        const workspace = await TargetMemory.ensure("https://example.com")
        const request = Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/api/search",
          rawRequest: "GET /api/search?q=fixture HTTP/1.1\r\nHost: example.com\r\n\r\n",
          scheme: "https",
          host: "example.com",
          origin: "https://example.com",
        })
        const finding = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "medium",
            title: "Potential reflected HTML injection",
            description: "A captured response contains a reflected marker but no execution PoC.",
            endpoint: "GET https://example.com/api/search",
            target_id: workspace.id,
          },
        })
        expect(request).toBeDefined()
        const result = await startImpactHunterHandoff({
          sessionID: session.id,
          messageID: "msg_impact_hunter_dispatch_gate",
          agent: "cyberstrike",
          abort: new AbortController().signal,
          messages: [],
          ask: async () => {},
          metadata: () => {},
        } as never, finding, "proof_gap")

        expect(result.started).toBe(false)
        expect(result.reason).toContain("explicit vulnerability_testing")
        expect(await Session.children(session.id)).toHaveLength(0)
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

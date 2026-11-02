import { describe, expect, test } from "bun:test"
import path from "path"
import { Agent } from "../../src/agent/agent"
import { AgentPerformance } from "../../src/methodology/performance"
import { Phase } from "../../src/methodology/phase"
import { PermissionNext } from "../../src/permission/next"
import { Instance } from "../../src/project/instance"
import { ToolRegistry } from "../../src/tool/registry"
import { TESTER_VRT_SCOPE, testerClass } from "../../src/tool/vuln-scope"

const repoRoot = path.resolve(import.meta.dir, "../../../..")

describe("runtime agent integration contracts", () => {
  test("all phase and performance agent references resolve to registered runtime agents", async () => {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        const entries = await Agent.entries()
        const registered = new Set(entries.map((entry) => entry.id))

        expect(registered.size).toBeGreaterThan(0)
        for (const phase of Phase.ALL) {
          for (const agentName of phase.agents) {
            expect(registered.has(agentName), phase.id + " references missing runtime agent " + agentName).toBe(true)
          }
        }
        for (const agentName of AgentPerformance.allAgentNames()) {
          expect(registered.has(agentName), "AgentPerformance references missing runtime agent " + agentName).toBe(true)
        }
      },
    })
  })

  test("every proxy tester has exactly one matching VRT lane and tester-class resolver", async () => {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        const entries = await Agent.entries()
        const testerIds = entries
          .map((entry) => entry.id)
          .filter((id) => id.startsWith("proxy-tester-"))
          .sort()
        const laneIds = Object.keys(TESTER_VRT_SCOPE).map((lane) => "proxy-tester-" + lane).sort()

        expect(testerIds).toEqual(laneIds)
        for (const [lane, allowedCategories] of Object.entries(TESTER_VRT_SCOPE)) {
          const id = "proxy-tester-" + lane
          expect(allowedCategories.length, id + " must declare its supported VRT categories").toBeGreaterThan(0)
          expect(testerClass(id)).toBe(lane)
          expect(await Agent.get(id), id + " must be loadable by the runtime registry").toBeDefined()
        }
      },
    })
  })

  test("every enabled agent tool permission resolves to a registered tool", async () => {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        const toolIds = new Set(await ToolRegistry.ids())
        const entries = await Agent.entries()
        const nonToolPermissions = new Set(["external_directory", "doom_loop"])

        for (const entry of entries) {
          const info = await Agent.get(entry.id)
          expect(info, "missing agent info for " + entry.id).toBeDefined()
          for (const rule of info!.permission) {
            if (rule.action === "deny" || rule.permission === "*" || nonToolPermissions.has(rule.permission)) continue
            // Question is a client-conditional UI capability, not a universal CLI tool.
            if (rule.permission === "question" && !toolIds.has("question")) continue
            expect(
              toolIds.has(rule.permission),
              entry.id + " grants " + rule.permission + " but no matching runtime tool is registered",
            ).toBe(true)
          }
        }
      },
    })
  })

  test("every skill-enabled runtime agent receives shared runtime discovery guidance", async () => {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        const entries = await Agent.entries()
        for (const entry of entries) {
          const info = await Agent.get(entry.id)
          expect(info, "missing agent info for " + entry.id).toBeDefined()
          if (PermissionNext.evaluate("skill", "*", info!.permission).action === "deny") continue
          expect(
            info!.prompt,
            entry.id + " has skill access but is missing the shared runtime skill/tool discovery guidance",
          ).toContain("Runtime capability, skill, and signal routing")
        }
      },
    })
  })

  test("vulnerability testers receive skill discovery and obey the structural off-lane handoff", async () => {
    await Instance.provide({
      directory: repoRoot,
      fn: async () => {
        const entries = await Agent.entries()
        for (const entry of entries.filter((item) => item.id.startsWith("proxy-tester-"))) {
          const info = await Agent.get(entry.id)
          expect(info, entry.id).toBeDefined()
          expect(
            PermissionNext.evaluate("skill", "*", info!.permission).action,
            entry.id + " must be allowed to discover and load relevant skills",
          ).not.toBe("deny")
          expect(info!.prompt, entry.id + " must receive shared runtime routing guidance").toContain(
            "Runtime capability, skill, and signal routing",
          )
        }

        const commonPrompt = await Bun.file(path.resolve(import.meta.dir, "../../src/agent/prompt/vuln/common-prompt.txt")).text()
        expect(commonPrompt).toContain("Never call either tool for an off-class observation")
        expect(commonPrompt).toContain("vulnerability_hint")
        expect(commonPrompt).not.toContain("still `report_vulnerability` it")
      },
    })
  })

  test("skill runtime explains how to recover when large skill output is truncated", async () => {
    const prompt = await Bun.file(path.resolve(import.meta.dir, "../../src/agent/prompt/runtime-discovery.txt")).text()
    expect(prompt).toContain("exact saved-output path in the truncation notice")
    expect(prompt).toContain("returned `<skill_files>` manifest")
  })
})

import { expect, test } from "bun:test"
import { Agent } from "../../src/agent/agent"
import { Instance } from "../../src/project/instance"
import { isImpactHunterCaller } from "../../src/methodology/impact-hunter-handoff"
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

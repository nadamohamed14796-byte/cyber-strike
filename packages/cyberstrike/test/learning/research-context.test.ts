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

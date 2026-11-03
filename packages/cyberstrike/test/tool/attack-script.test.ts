import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { AttackScriptTool } from "../../src/tool/attack-script"
import { tmpdir } from "../fixture/fixture"

test("network attack scripts require persisted scope and an active vulnerability-testing checkpoint", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const target = "https://script-gate.example.test"
      await TargetMemory.configureScope(target, {
        include: ["script-gate.example.test"],
        authorizationSource: "Attack script phase-gate fixture",
        authorizationReference: "https://script-gate.example.test/security",
      })
      const tool = await AttackScriptTool.init()
      const result = await tool.execute({
        script: "race_tester",
        args: [target + "/api/checkout"],
        timeout_seconds: 5,
      } as never)

      expect(result.metadata.testingDenied).toBe(true)
      expect(result.metadata.exitCode).toBe(-1)
      expect(result.output).toContain("No script was executed.")
      expect(result.output).toContain("vulnerability_testing")
    },
  })
})

test("Wayback active probing is refused until each archived URL can be scope-checked", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const tool = await AttackScriptTool.init()
      const result = await tool.execute({
        script: "wayback_endpoints",
        args: ["example.test", "--probe"],
        timeout_seconds: 5,
      } as never)

      expect(result.metadata.blocked).toBe(true)
      expect(result.metadata.exitCode).toBe(-1)
      expect(result.output).toContain("Wayback --probe is disabled")
      expect(result.output).toContain("No script was executed.")
    },
  })
})

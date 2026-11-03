import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { AttackScriptTool } from "../../src/tool/attack-script"
import { tmpdir } from "../fixture/fixture"

const testContext = {
  sessionID: "test_session",
  messageID: "test_message",
  agent: "test",
  abort: new AbortController().signal,
  messages: [],
  ask: async () => {},
  metadata: () => {},
} as never

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
      } as never, testContext)

      expect(result.metadata.testingDenied).toBe(true)
      expect(result.metadata.exitCode).toBe(-1)
      expect(result.output).toContain("No script was executed.")
      expect(result.output).toContain("vulnerability_testing")
    },
  })
})

test("cloud storage enumeration cannot probe generated third-party bucket hosts outside scope", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      await TargetMemory.configureScope("https://cloud-gate.example.test", {
        include: ["cloud-gate.example.test"],
        authorizationSource: "Cloud storage scope fixture",
        authorizationReference: "https://cloud-gate.example.test/security",
      })
      const tool = await AttackScriptTool.init()
      const result = await tool.execute({
        script: "cloud_storage_enum",
        args: ["cloud-gate.example.test"],
        timeout_seconds: 5,
      } as never, testContext)

      expect(result.metadata.scopeDenied).toBe(true)
      expect(result.metadata.exitCode).toBe(-1)
      expect(result.output).toContain("No script was executed.")
      expect(result.output).toContain("s3.amazonaws.com")
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
      } as never, testContext)

      expect(result.metadata.blocked).toBe(true)
      expect(result.metadata.exitCode).toBe(-1)
      expect(result.output).toContain("Wayback --probe is disabled")
      expect(result.output).toContain("No script was executed.")
    },
  })
})

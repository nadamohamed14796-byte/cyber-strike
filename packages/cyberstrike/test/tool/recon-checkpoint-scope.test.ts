import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { ReconCheckpointTool } from "../../src/tool/recon-checkpoint"
import { tmpdir } from "../fixture/fixture"

test("program-root scope can authorize a separate domain without requiring the root hostname itself in scope", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const root = await TargetMemory.configureScope("https://mercadolibre-program.test", {
        include: ["https://fullbarhomologa.modoblackfullbar.com.br"],
        authorizationSource: "Authorized program scope fixture",
        authorizationReference: "https://program.example.test/policy",
      })

      const rootDecision = await TargetMemory.checkURLScope(root.workspace.targetURL)
      const assetDecision = await TargetMemory.checkURLScope("https://fullbarhomologa.modoblackfullbar.com.br/")
      expect(rootDecision.allowed).toBe(false)
      expect(assetDecision.allowed).toBe(true)

      const tool = await ReconCheckpointTool.init()
      const ctx = {
        sessionID: "ses_recon_program_root_scope",
        messageID: "msg_recon_program_root_scope",
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => undefined,
        ask: async () => {},
      } as never
      const execute = (action: "begin" | "complete", phase: "scope_validation" | "workspace_setup" | "asset_discovery", summary?: string) =>
        tool.execute({ action, target_url: root.workspace.targetURL, phase, summary }, ctx)

      expect((await execute("begin", "scope_validation")).metadata.saved).toBe(true)
      expect((await execute("complete", "scope_validation", "Reviewed and persisted the program policy scope.")).metadata.saved).toBe(true)
      expect((await execute("begin", "workspace_setup")).metadata.saved).toBe(true)
      expect((await execute("complete", "workspace_setup", "Canonical workspace files and directories verified.")).metadata.saved).toBe(true)

      const discovery = await execute("begin", "asset_discovery")
      expect(discovery.metadata.saved).toBe(true)
      expect(discovery.title).not.toContain("blocked by persisted scope")
    },
  })
})

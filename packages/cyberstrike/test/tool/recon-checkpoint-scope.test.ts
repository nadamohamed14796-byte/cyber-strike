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


test("user-confirmed exact scope without an external policy URL passes the recon scope checkpoint", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
        const root = await TargetMemory.configureScope("https://program-root.example.test", {
          include: ["https://authorized-app.example.net"],
          authorizationSource: "User-confirmed in conversation",
          userConfirmed: true,
        })
        const persisted = await TargetMemory.getScope(root.workspace.targetURL)
        expect(persisted?.status).toBe("configured")
        expect(persisted?.authorizationReference).toBeNull()
        expect(persisted?.authorizationSource).toContain("User-confirmed in conversation")

        const tool = await ReconCheckpointTool.init()
        const ctx = {
          sessionID: "ses_recon_user_confirmed_scope",
          messageID: "msg_recon_user_confirmed_scope",
          agent: "cyberstrike",
          abort: new AbortController().signal,
          messages: [],
          metadata: () => undefined,
          ask: async () => {},
        } as never
        const begin = await tool.execute({
          action: "begin",
          target_url: root.workspace.targetURL,
          phase: "scope_validation",
        }, ctx)
        expect(begin.metadata.saved).toBe(true)
        const complete = await tool.execute({
          action: "complete",
          target_url: root.workspace.targetURL,
          phase: "scope_validation",
          summary: "The operator explicitly confirmed the exact application and the confirmation provenance is persisted.",
        }, ctx)
        expect(complete.metadata.saved).toBe(true)
      } finally {
        await Instance.dispose()
      }
    },
  })
})

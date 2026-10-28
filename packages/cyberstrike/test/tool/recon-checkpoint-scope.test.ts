import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { ReconCheckpointTool, reconRunID } from "../../src/tool/recon-checkpoint"
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
      const execute = (action: "begin" | "complete", phase: "scope_validation" | "workspace_setup" | "asset_discovery", summary?: string, scopeValidationTarget?: string) =>
        tool.execute({ action, target_url: root.workspace.targetURL, phase, summary, scope_validation_target: scopeValidationTarget }, ctx)

      expect((await execute("begin", "scope_validation")).metadata.saved).toBe(true)
      const rejected = await execute("complete", "scope_validation", "Reviewed and persisted the program policy scope.", "https://not-authorized.example.net/")
      expect(rejected.metadata.saved).toBe(false)
      expect(rejected.metadata.reason).toBe("scope_validation_target_out_of_scope")
      expect((await execute("complete", "scope_validation", "Reviewed and persisted the program policy scope.", "https://fullbarhomologa.modoblackfullbar.com.br/")).metadata.saved).toBe(true)
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

        const runPath = path.join(root.workspace.workspacePath, "runs", "recon-" + reconRunID(root.workspace.id) + ".json")
        const firstResume = await tool.execute({ action: "status", target_url: root.workspace.targetURL }, ctx)
        let phases = firstResume.metadata.phases as Record<string, { status: string; scopeValidationTarget?: string; scopeFingerprint?: string }>
        expect(phases.scope_validation.status).toBe("complete")
        expect(phases.scope_validation.scopeValidationTarget).toBe("https://authorized-app.example.net/")
        expect(phases.scope_validation.scopeFingerprint).toBeTruthy()

        // Simulate an older checkpoint written before target/fingerprint fields existed.
        const legacy = JSON.parse(await fs.readFile(runPath, "utf-8"))
        delete legacy.phases.scope_validation.scopeValidationTarget
        delete legacy.phases.scope_validation.scopeFingerprint
        await TargetMemory.writeWorkspaceFile(root.workspace, path.join("runs", path.basename(runPath)), JSON.stringify(legacy, null, 2) + "\n")

        const resumed = await tool.execute({ action: "status", target_url: root.workspace.targetURL }, ctx)
        phases = resumed.metadata.phases as Record<string, { status: string; scopeValidationTarget?: string; scopeFingerprint?: string }>
        expect(phases.scope_validation.status).toBe("complete")
        expect(phases.scope_validation.scopeValidationTarget).toBe("https://authorized-app.example.net/")
        expect(phases.scope_validation.scopeFingerprint).toBeTruthy()
      } finally {
        await Instance.dispose()
      }
    },
  })
})


test("scope manifest changes invalidate resumable recon checkpoints even when the starting asset remains allowed", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://program-fingerprint.example.test"
      const startingAsset = "https://api.fingerprint-scope.example.net/"
      const authorizationSource = "Scope fingerprint regression fixture"
      const authorizationReference = "https://program-fingerprint.example.test/policy"
      const root = await TargetMemory.configureScope(targetURL, {
        include: ["api.fingerprint-scope.example.net"],
        authorizationSource,
        authorizationReference,
      })
      const tool = await ReconCheckpointTool.init()
      const ctx = {
        sessionID: "ses_recon_scope_fingerprint",
        messageID: "msg_recon_scope_fingerprint",
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => undefined,
        ask: async () => {},
      } as never
      const execute = (action: "status" | "begin" | "complete", phase?: "scope_validation" | "workspace_setup", summary?: string) =>
        tool.execute({
          action,
          target_url: root.workspace.targetURL,
          phase,
          summary,
          scope_validation_target: startingAsset,
        }, ctx)

      expect((await execute("begin", "scope_validation")).metadata.saved).toBe(true)
      expect((await execute("complete", "scope_validation", "Persisted scope and starting asset verified.")).metadata.saved).toBe(true)
      expect((await execute("begin", "workspace_setup")).metadata.saved).toBe(true)
      expect((await execute("complete", "workspace_setup", "Workspace integrity verified.")).metadata.saved).toBe(true)
      expect((await TargetMemory.checkURLScope(startingAsset)).allowed).toBe(true)

      await TargetMemory.configureScope(targetURL, {
        include: ["api.fingerprint-scope.example.net", "new-api.fingerprint-scope.example.net"],
        authorizationSource,
        authorizationReference,
      })
      // The old starting asset still passes, so only a comparison of the persisted
      // scope fingerprint can detect that prior phases need revalidation.
      expect((await TargetMemory.checkURLScope(startingAsset)).allowed).toBe(true)
      const status = await execute("status")
      expect(status.metadata.saved).toBe(true)
      const phases = status.metadata.phases as Record<string, { status: string; reason?: string }>
      expect(phases.scope_validation.status).toBe("pending")
      expect(phases.scope_validation.reason).toContain("scope or exclusions changed")
      expect(phases.workspace_setup.status).toBe("pending")
    },
  })
})


test("resume fingerprints an asset's full inherited scope chain, not only the program root", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://program-chain.example.test"
      const assetURL = "https://api.scope-chain.example.net"
      const root = await TargetMemory.configureScope(targetURL, {
        include: ["*.scope-chain.example.net"],
        authorizationSource: "Root scope chain fixture",
        authorizationReference: "https://program-chain.example.test/policy",
      })
      const attached = await TargetMemory.attachAsset(root.workspace.targetURL, assetURL, "api")
      await TargetMemory.configureScope(attached.asset.targetURL, {
        include: ["api.scope-chain.example.net"],
        authorizationSource: "Child API scope fixture",
        authorizationReference: "https://api.scope-chain.example.net/security",
      })

      const tool = await ReconCheckpointTool.init()
      const ctx = {
        sessionID: "ses_recon_scope_chain_fingerprint",
        messageID: "msg_recon_scope_chain_fingerprint",
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => undefined,
        ask: async () => {},
      } as never
      const execute = (action: "status" | "begin" | "complete", phase?: "scope_validation" | "workspace_setup", summary?: string) =>
        tool.execute({
          action,
          target_url: root.workspace.targetURL,
          phase,
          summary,
          scope_validation_target: assetURL + "/",
        }, ctx)

      const before = await TargetMemory.checkURLScope(assetURL + "/")
      expect(before.allowed).toBe(true)
      expect(before.workspace?.id).toBe(attached.asset.id)
      expect((await execute("begin", "scope_validation")).metadata.saved).toBe(true)
      expect((await execute("complete", "scope_validation", "Effective child and parent scope verified.")).metadata.saved).toBe(true)
      expect((await execute("begin", "workspace_setup")).metadata.saved).toBe(true)
      expect((await execute("complete", "workspace_setup", "Workspace integrity verified.")).metadata.saved).toBe(true)

      await TargetMemory.configureScope(attached.asset.targetURL, {
        include: ["api.scope-chain.example.net", "*.api.scope-chain.example.net"],
        authorizationSource: "Child API scope fixture",
        authorizationReference: "https://api.scope-chain.example.net/security",
      })
      expect((await TargetMemory.checkURLScope(assetURL + "/")).allowed).toBe(true)
      const status = await execute("status")
      expect(status.metadata.saved).toBe(true)
      const phases = status.metadata.phases as Record<string, { status: string; reason?: string }>
      expect(phases.scope_validation.status).toBe("pending")
      expect(phases.scope_validation.reason).toContain("scope or exclusions changed")
      expect(phases.workspace_setup.status).toBe("pending")
    },
  })
})

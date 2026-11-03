import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import {
  initialReconRun,
  reconRunID,
  reconScopeFingerprintForWorkspace,
} from "../../src/target/recon-gate"
import { ReconCheckpointTool } from "../../src/tool/recon-checkpoint"
import { tmpdir } from "../fixture/fixture"

test("concurrent duplicate checkpoint begins preserve one serialized phase transition", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://program-checkpoint-lock.example.test"
      const startingAsset = "https://api.checkpoint-lock.example.net/"
      const root = await TargetMemory.configureScope(targetURL, {
        include: ["api.checkpoint-lock.example.net"],
        authorizationSource: "Checkpoint lock regression fixture",
        authorizationReference: "https://program-checkpoint-lock.example.test/policy",
      })
      const scopeDecision = await TargetMemory.checkURLScope(startingAsset)
      expect(scopeDecision.allowed).toBe(true)
      expect(scopeDecision.workspace?.id).toBe(root.workspace.id)
      const fingerprint = await reconScopeFingerprintForWorkspace(scopeDecision.workspace!, root.workspace.id)

      const run = initialReconRun(root.workspace.targetURL, root.workspace.id, "ses_recon_checkpoint_concurrency")
      run.phases.scope_validation = {
        status: "complete",
        scopeValidationTarget: startingAsset,
        scopeFingerprint: fingerprint,
      }
      run.phases.workspace_setup = { status: "complete" }
      const relativePath = "runs/recon-" + reconRunID(root.workspace.id) + ".json"
      await TargetMemory.writeWorkspaceFile(root.workspace, relativePath, JSON.stringify(run, null, 2) + "\n")

      const tool = await ReconCheckpointTool.init()
      const ctx = {
        sessionID: "ses_recon_checkpoint_concurrency",
        messageID: "msg_recon_checkpoint_concurrency",
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => undefined,
        ask: async () => {},
      } as never
      const [first, duplicate] = await Promise.all([
        tool.execute({ action: "begin", target_url: targetURL, phase: "asset_discovery" }, ctx),
        tool.execute({ action: "begin", target_url: targetURL, phase: "asset_discovery" }, ctx),
      ])
      expect([first.metadata.saved, duplicate.metadata.saved].filter(Boolean)).toHaveLength(1)
      expect([first.metadata.reason, duplicate.metadata.reason]).toContain("phase_already_running")

      const persisted = JSON.parse(await fs.readFile(path.join(root.workspace.workspacePath, relativePath), "utf-8"))
      expect(persisted.phases.asset_discovery.status).toBe("running")
      expect(persisted.phases.live_hosts_ports.status).toBe("pending")
      const index = JSON.parse(await fs.readFile(path.join(root.workspace.workspacePath, "runs", "index.json"), "utf-8"))
      expect(index.runs.filter((item: { runID: string }) => item.runID === reconRunID(root.workspace.id))).toHaveLength(1)
    },
  })
})

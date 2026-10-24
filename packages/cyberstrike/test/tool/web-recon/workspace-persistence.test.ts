import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../../fixture/fixture"
import { Instance } from "../../../src/project/instance"
import { TargetMemory } from "../../../src/target"
import { WebReconTool } from "../../../src/tool/web-recon"
import { ReconCheckpointTool } from "../../../src/tool/recon-checkpoint"

test("web_recon persists results and synchronizes target notes in the canonical workspace", async () => {
  await using tmp = await tmpdir()
  const requests: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push(new URL(request.url).pathname)
      return new Response("User-agent: *\nDisallow: /private\n", {
        status: 200,
        headers: { "content-type": "text/plain" },
      })
    },
  })

  try {
    await Instance.provide({
      directory: tmp.path,
      async fn() {
      try {
        const target = "http://127.0.0.1:" + server.port
        const workspace = await TargetMemory.ensure(target)
        await TargetMemory.configureScope(target, {
          include: [target],
          exclude: [],
          authorizationSource: "Local unit-test fixture",
          authorizationReference: "https://example.test/security-policy",
        })
        const checkpointContext = {
          sessionID: "ses_web_recon_workspace_persistence",
          messageID: "msg_web_recon_workspace_persistence",
          agent: "test",
          abort: new AbortController().signal,
          messages: [],
          ask: async () => {},
          metadata: () => {},
        } as never
        const checkpointTool = await ReconCheckpointTool.init()
        const checkpoint = async (
          action: "begin" | "complete" | "unavailable",
          phase: "scope_validation" | "workspace_setup" | "asset_discovery" | "live_hosts_ports" | "url_collection",
          summary?: string,
          reason?: string,
          scopeValidationTarget?: string,
        ) => checkpointTool.execute({ action, target_url: target, phase, summary, reason, scope_validation_target: scopeValidationTarget }, checkpointContext)
        for (const phase of ["scope_validation", "workspace_setup"] as const) {
          expect((await checkpoint("begin", phase)).metadata.saved).toBe(true)
          expect((await checkpoint(
            "complete",
            phase,
            phase + " verified for local fixture",
            undefined,
            phase === "scope_validation" ? target : undefined,
          )).metadata.saved).toBe(true)
        }
        for (const phase of ["asset_discovery", "live_hosts_ports"] as const) {
          expect((await checkpoint("begin", phase)).metadata.saved).toBe(true)
          expect((await checkpoint("unavailable", phase, undefined, "Not applicable to the localhost fixture")).metadata.saved).toBe(true)
        }
        expect((await checkpoint("begin", "url_collection")).metadata.saved).toBe(true)
        const legacyCompletedAt = "2026-10-22T17:00:00.000Z"
        const legacyPath = path.join(workspace.workspacePath, "recon", "header_audit-2026-10-22T17-00-00-000Z.json")
        await fs.writeFile(legacyPath, JSON.stringify({
          schemaVersion: 1,
          recordType: "web-recon-result",
          program: "header_audit",
          requestedTarget: target,
          canonicalTarget: workspace.targetURL,
          workspaceID: workspace.id,
          workspacePath: workspace.workspacePath,
          sessionID: "ses_legacy_recon",
          completedAt: legacyCompletedAt,
          result: { output: "Legacy redacted header finding snapshot", findings: [] },
        }, null, 2) + "\n")
        const tool = await WebReconTool.init()
        const result = await tool.execute({
          program: "robots_scan",
          target,
          args: [],
          timeout_seconds: 2,
        }, {
          sessionID: "ses_web_recon_workspace_persistence",
          messageID: "msg_web_recon_workspace_persistence",
          agent: "test",
          abort: new AbortController().signal,
          messages: [],
          ask: async () => {},
          metadata: () => {},
        } as never)

        expect(requests).toEqual(["/robots.txt"])
        expect(result.metadata.artifact_saved).toBe(true)
        expect(result.metadata.notes_saved).toBe(true)
        expect(result.metadata.target_workspace).toBe(workspace.workspacePath)
        expect(result.metadata.artifact_path).toBe(path.join(workspace.workspacePath, "recon", "web-recon-results.json"))
        const artifactPath = result.metadata.artifact_path as string
        const saved = JSON.parse(await fs.readFile(artifactPath, "utf-8"))
        expect(saved.recordType).toBe("web-recon-results")
        expect(saved.workspaceID).toBe(workspace.id)
        expect(saved.observations).toHaveLength(2)
        const currentObservation = saved.observations.find((item: { program: string }) => item.program === "robots_scan")
        const migratedObservation = saved.observations.find((item: { program: string }) => item.program === "header_audit")
        expect(currentObservation.result.output).toContain("robots.txt found")
        expect(migratedObservation.result.output).toBe("Legacy redacted header finding snapshot")
        expect(migratedObservation.attempts).toEqual([{ completedAt: legacyCompletedAt, sessionID: "ses_legacy_recon" }])
        expect(await fs.readdir(path.join(workspace.workspacePath, "recon"))).toEqual(["web-recon-results.json"])

        const repeated = await tool.execute({
          program: "robots_scan",
          target,
          args: [],
          timeout_seconds: 2,
        }, {
          sessionID: "ses_web_recon_workspace_persistence",
          messageID: "msg_web_recon_workspace_persistence_repeat",
          agent: "test",
          abort: new AbortController().signal,
          messages: [],
          ask: async () => {},
          metadata: () => {},
        } as never)
        expect(requests).toEqual(["/robots.txt", "/robots.txt"])
        expect(repeated.metadata.artifact_path).toBe(artifactPath)
        const afterRepeat = JSON.parse(await fs.readFile(artifactPath, "utf-8"))
        expect(afterRepeat.observations).toHaveLength(2)
        const repeatedObservation = afterRepeat.observations.find((item: { program: string }) => item.program === "robots_scan")
        expect(repeatedObservation.occurrences).toBe(2)
        expect(repeatedObservation.attempts).toHaveLength(2)

        await Promise.all([1, 2].map((n) => tool.execute({
          program: "robots_scan",
          target,
          args: [],
          timeout_seconds: 2,
        }, {
          sessionID: "ses_web_recon_workspace_persistence",
          messageID: "msg_web_recon_workspace_concurrent_" + n,
          agent: "test",
          abort: new AbortController().signal,
          messages: [],
          ask: async () => {},
          metadata: () => {},
        } as never)))
        const afterConcurrent = JSON.parse(await fs.readFile(artifactPath, "utf-8"))
        expect(afterConcurrent.observations).toHaveLength(2)
        const concurrentObservation = afterConcurrent.observations.find((item: { program: string }) => item.program === "robots_scan")
        expect(concurrentObservation.occurrences).toBe(4)
        expect(concurrentObservation.attempts).toHaveLength(4)
        expect(await fs.readdir(path.join(workspace.workspacePath, "recon"))).toEqual(["web-recon-results.json"])

        const notes = await fs.readFile(path.join(workspace.workspacePath, "notes.md"), "utf-8")
        expect(notes).toContain("Recon run: robots_scan")
        expect(notes).toContain("recon/web-recon-results.json")
        } finally { await Instance.dispose() }
    },
    })
  } finally {
    server.stop(true)
  }
})

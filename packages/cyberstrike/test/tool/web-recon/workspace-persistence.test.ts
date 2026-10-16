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
          include: ["127.0.0.1"],
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
        ) => checkpointTool.execute({ action, target_url: target, phase, summary, reason }, checkpointContext)
        for (const phase of ["scope_validation", "workspace_setup"] as const) {
          expect((await checkpoint("begin", phase)).metadata.saved).toBe(true)
          expect((await checkpoint("complete", phase, phase + " verified for local fixture")).metadata.saved).toBe(true)
        }
        for (const phase of ["asset_discovery", "live_hosts_ports"] as const) {
          expect((await checkpoint("begin", phase)).metadata.saved).toBe(true)
          expect((await checkpoint("unavailable", phase, undefined, "Not applicable to the localhost fixture")).metadata.saved).toBe(true)
        }
        expect((await checkpoint("begin", "url_collection")).metadata.saved).toBe(true)
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
        expect(result.metadata.artifact_path).toContain(path.join(workspace.workspacePath, "recon", "robots_scan-"))
        const artifactPath = result.metadata.artifact_path as string
        const saved = JSON.parse(await fs.readFile(artifactPath, "utf-8"))
        expect(saved.program).toBe("robots_scan")
        expect(saved.workspaceID).toBe(workspace.id)
        expect(saved.result.output).toContain("robots.txt found")
        const notes = await fs.readFile(path.join(workspace.workspacePath, "notes.md"), "utf-8")
        expect(notes).toContain("Recon run: robots_scan")
        expect(notes).toContain("recon/robots_scan-")
        } finally { await Instance.dispose() }
    },
    })
  } finally {
    server.stop(true)
  }
})

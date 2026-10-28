import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { TargetArtifactTool } from "../../src/tool/target-artifact"

test("target_artifact writes canonical root inventories and still protects generated manifests", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
        const target = "https://example.com"
        const workspace = await TargetMemory.ensure(target)
        const tool = await TargetArtifactTool.init()
        const ctx = {
          sessionID: "ses_target_artifact_root_test",
          messageID: "msg_target_artifact_root_test",
          agent: "test",
          abort: new AbortController().signal,
          messages: [],
          ask: async () => undefined,
          metadata: () => undefined,
        } as never

        const saved = await tool.execute({
          target_url: target,
          area: "root",
          filename: "subdomains.txt",
          content: "api.example.com\n",
        }, ctx)

        const expectedPath = path.join(workspace.workspacePath, "subdomains.txt")
        expect(saved.metadata.saved).toBe(true)
        expect(saved.metadata.path).toBe(expectedPath)
        expect(await fs.readFile(expectedPath, "utf-8")).toBe("api.example.com\n")

        const reserved = await tool.execute({
          target_url: target,
          area: "root",
          filename: "workspace.json",
          content: "{}",
        }, ctx)
        expect(reserved.metadata.saved).toBe(false)
        expect(reserved.metadata.reason).toBe("reserved_file")

        const urls = await tool.execute({
          target_url: target,
          area: "urls",
          filename: "collected.txt",
          content: "https://example.com/account\n",
        }, ctx)
        const compactURLPath = path.join(workspace.workspacePath, "recon", "urls-collected.txt")
        expect(urls.metadata.saved).toBe(true)
        expect(urls.metadata.path).toBe(compactURLPath)
        expect(await fs.readFile(compactURLPath, "utf-8")).toBe("https://example.com/account\n")
        await expect(fs.stat(path.join(workspace.workspacePath, "urls"))).rejects.toThrow()

        const endpointDetails = await tool.execute({
          target_url: target,
          area: "endpoints",
          filename: "correlations.json",
          content: '{"candidate_count":1}',
        }, ctx)
        const compactEndpointPath = path.join(workspace.workspacePath, "recon", "endpoints-correlations.json")
        expect(endpointDetails.metadata.saved).toBe(true)
        expect(endpointDetails.metadata.path).toBe(compactEndpointPath)
        expect(await fs.readFile(compactEndpointPath, "utf-8")).toBe('{"candidate_count":1}')
        await expect(fs.stat(path.join(workspace.workspacePath, "endpoints"))).rejects.toThrow()

        const evidence = await tool.execute({
          target_url: target,
          area: "evidence",
          filename: "request.json",
          content: '{"status":200}',
        }, ctx)
        const compactEvidencePath = path.join(workspace.workspacePath, "findings", "evidence-request.json")
        expect(evidence.metadata.saved).toBe(true)
        expect(evidence.metadata.path).toBe(compactEvidencePath)
        expect(await fs.readFile(compactEvidencePath, "utf-8")).toBe('{"status":200}')
        await expect(fs.stat(path.join(workspace.workspacePath, "evidence"))).rejects.toThrow()
      } finally {
        await Instance.dispose()
      }
    },
  })
})

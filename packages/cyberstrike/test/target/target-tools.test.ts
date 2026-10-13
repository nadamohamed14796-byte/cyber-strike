import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetArtifactTool } from "../../src/tool/target-artifact"
import { TargetWorkspaceTool } from "../../src/tool/target-workspace"

test("target workspace tool initializes, configures scope, and nests authorized child assets", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const tool = await TargetWorkspaceTool.init()
      const init = await tool.execute({ action: "init", target_url: "https://example.com" }, {} as never)
      expect(init.metadata.initialized).toBe(true)
      expect(init.metadata.scope_configured).toBe(false)
      expect(init.metadata.workspace).toBeTruthy()
      const rootPath = init.metadata.workspace!
      expect(await fs.readFile(path.join(rootPath, "notes.md"), "utf-8")).toContain("# Target Notes")
      expect((await fs.readFile(path.join(rootPath, "scope", "scope.json"), "utf-8"))).toContain('"status": "unconfigured"')

      const scope = await tool.execute({
        action: "configure_scope",
        target_url: "https://example.com",
        include: ["example.com", "*.example.com"],
        exclude: ["admin.example.com"],
        authorization_source: "Example authorized disclosure program",
        authorization_reference: "https://hackerone.com/example",
      }, {} as never)
      expect(scope.metadata.saved).toBe(true)
      expect(scope.metadata.scope_configured).toBe(true)

      const child = await tool.execute({
        action: "attach_asset",
        parent_target_url: "https://example.com",
        asset_url: "https://api.example.com",
        asset_type: "api",
      }, {} as never)
      expect(child.metadata.attached).toBe(true)
      expect(child.metadata.workspace).toContain(path.join("assets", ""))
      expect(await fs.readFile(path.join(rootPath, "assets", "registry.json"), "utf-8")).toContain("api.example.com")
      expect(await fs.readFile(path.join(rootPath, "notes.md"), "utf-8")).toContain("Managed Asset Inventory")
    },
  })
})

test("target artifact tool writes only inside an existing workspace and protects reserved files", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const workspaces = await TargetWorkspaceTool.init()
      const artifact = await TargetArtifactTool.init()
      const init = await workspaces.execute({ action: "init", target_url: "https://example.com" }, {} as never)
      const workspace = init.metadata.workspace!
      const saved = await artifact.execute({
        target_url: "https://example.com",
        area: "recon",
        filename: "hosts.txt",
        content: "api.example.com\nAuthorization: Bearer super.secret.token",
        overwrite: false,
      }, {} as never)
      expect(saved.metadata.saved).toBe(true)
      expect(saved.metadata.path).toBe(path.join(workspace, "recon", "hosts.txt"))
      const content = await fs.readFile(saved.metadata.path!, "utf-8")
      expect(content).toContain("api.example.com")
      expect(content).not.toContain("super.secret.token")

      const duplicate = await artifact.execute({
        target_url: "https://example.com",
        area: "recon",
        filename: "hosts.txt",
        content: "should not overwrite",
        overwrite: false,
      }, {} as never)
      expect(duplicate.metadata.saved).toBe(false)
      expect(duplicate.metadata.reason).toBe("already_exists")
      expect(await fs.readFile(path.join(workspace, "recon", "hosts.txt"), "utf-8")).toContain("api.example.com")

      const reserved = await artifact.execute({
        target_url: "https://example.com",
        area: "scope",
        filename: "scope.json",
        content: '{"status":"configured"}',
        overwrite: true,
      }, {} as never)
      expect(reserved.metadata.saved).toBe(false)
      expect(reserved.metadata.reason).toBe("reserved_file")
      expect((await fs.readFile(path.join(workspace, "scope", "scope.json"), "utf-8"))).toContain('"status": "unconfigured"')

      const missing = await artifact.execute({
        target_url: "https://missing.example",
        area: "evidence",
        filename: "proof.json",
        content: '{}',
        overwrite: false,
      }, {} as never)
      expect(missing.metadata.saved).toBe(false)
      expect(missing.metadata.reason).toBe("workspace_missing")
    },
  })
})

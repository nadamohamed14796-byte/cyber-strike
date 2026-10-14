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
      try {
      const tool = await TargetWorkspaceTool.init()
      const init = await tool.execute({ action: "init", target_url: "https://example.com" }, {} as never)
      expect(init.metadata.initialized).toBe(true)
      expect(init.metadata.scope_configured).toBe(false)
      expect(init.metadata.workspace).toBeTruthy()
      const rootPath = init.metadata.workspace!
      expect(await fs.readFile(path.join(rootPath, "notes.md"), "utf-8")).toContain("# Target Notes")
      expect((await fs.readFile(path.join(rootPath, "scope", "scope.json"), "utf-8"))).toContain('"status": "unconfigured"')
      const summary = await tool.execute({
        action: "record_summary",
        target_url: "https://example.com",
        summary_title: "Scope input registered",
        summary_content: "The operator-provided scope list is staged at scope/targets.txt; recon has not started. Local evidence: api_key = \"test-secret-value-12345\".",
        summary_kind: "manual",
        summary_status: "observed",
        summary_source: "orchestrator",
        summary_tags: ["scope", "run-state"],
      }, {} as never)
      expect(summary.metadata.saved).toBe(true)
      expect(summary.metadata.note_id).toBeTruthy()
      expect(await fs.readFile(summary.metadata.notes_file!, "utf-8")).toContain("Scope input registered")
      expect(await fs.readFile(summary.metadata.notes_file!, "utf-8")).toContain("test-secret-value-12345")

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
      } finally { await Instance.dispose() }
    },
  })
})

test("scope-file import persists the source list, configured manifest, and notes in the canonical workspace", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
        const tool = await TargetWorkspaceTool.init()
        const init = await tool.execute({ action: "init", target_url: "https://att.com" }, {} as never)
        const workspace = init.metadata.workspace!
        const inputPath = path.join(tmp.path, "att.com.txt")
        const sourceContents = "# authorized program scope\natt.com\n*.att.com\napi.att.com\n"
        await fs.writeFile(inputPath, sourceContents, "utf-8")

        const imported = await tool.execute({
          action: "configure_scope",
          target_url: "https://att.com",
          scope_file_path: inputPath,
          authorization_source: "Authorized disclosure program",
          authorization_reference: "https://hackerone.com/example",
        }, {} as never)

        expect(imported.metadata.saved).toBe(true)
        expect(imported.metadata.scope_configured).toBe(true)
        expect(imported.metadata.workspace).toBe(workspace)
        expect(imported.metadata.source_scope_entry_count).toBe(3)
        expect(imported.metadata.source_scope_sha256).toMatch(/^[a-f0-9]{64}$/)
        expect(imported.metadata.source_scope_file).toBeTruthy()

        const scope = JSON.parse(await fs.readFile(path.join(workspace, "scope", "scope.json"), "utf-8"))
        expect(scope.status).toBe("configured")
        expect(scope.scopeItems).toEqual(["att.com", "*.att.com", "api.att.com"])
        expect(await fs.readFile(imported.metadata.source_scope_file!, "utf-8")).toBe(sourceContents)
        const notes = await fs.readFile(path.join(workspace, "notes.md"), "utf-8")
        expect(notes).toContain("# Target Notes")
        expect(notes).toContain("Scope file import checkpoint")
        expect(notes).toContain(String(imported.metadata.source_scope_sha256))
        expect((await fs.stat(path.join(workspace, "notes.md"))).size).toBeGreaterThan(0)
      } finally {
        await Instance.dispose()
      }
    },
  })
})

test("target artifact tool writes only inside an existing workspace and protects reserved files", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
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
      expect(content).toContain("super.secret.token")
      const largeInput = path.join(tmp.path, "large-scope.txt")
      await fs.writeFile(largeInput, "api.example.com\n" + "x".repeat(2_100_000) + "\nAuthorization: Bearer source.secret.token\n")
      const copied = await artifact.execute({
        target_url: "https://example.com",
        area: "scope",
        filename: "targets.txt",
        source_path: largeInput,
        overwrite: false,
      }, {} as never)
      expect(copied.metadata.saved).toBe(true)
      expect(copied.metadata.source_sha256).toMatch(/^[a-f0-9]{64}$/)
      const copiedText = await fs.readFile(copied.metadata.path!, "utf-8")
      expect(copiedText.length).toBeGreaterThan(2_000_000)
      expect(copiedText).toContain("api.example.com")
      expect(copiedText).toContain("source.secret.token")

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
      } finally { await Instance.dispose() }
    },
  })
})

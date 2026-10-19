import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { TargetArtifactTool } from "../../src/tool/target-artifact"
import { TargetWorkspaceTool } from "../../src/tool/target-workspace"
import { PermissionNext } from "../../src/permission/next"

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
      expect(JSON.parse(await fs.readFile(path.join(rootPath, "target.json"), "utf-8")).targetURL).toBe("https://example.com")
      expect(JSON.parse(await fs.readFile(path.join(rootPath, "workspace.json"), "utf-8")).targetURL).toBe("https://example.com")
      expect(await fs.readFile(path.join(rootPath, "notes.md"), "utf-8")).toContain("# Target Notes")
      expect((await fs.readFile(path.join(rootPath, "scope", "scope.json"), "utf-8"))).toContain('"status": "unconfigured"')

      const readmePath = path.join(rootPath, "README.md")
      const evidencePolicy = "- Preserve exact discovered values in this private, target-local evidence store when they are relevant evidence or needed for reproduction; mark them as candidates until independently validated."
      const generatedReadme = await fs.readFile(readmePath, "utf-8")
      expect(generatedReadme).toContain(evidencePolicy)
      await fs.writeFile(readmePath, generatedReadme.replace(
        evidencePolicy,
        "- Do not store passwords, cookies, bearer tokens, API keys, or other secrets.",
      ))
      const reopened = await tool.execute({ action: "init", target_url: "https://example.com" }, {} as never)
      expect(reopened.metadata.initialized).toBe(true)
      const migratedReadme = await fs.readFile(readmePath, "utf-8")
      expect(migratedReadme).toContain(evidencePolicy)
      expect(migratedReadme).not.toContain("- Do not store passwords, cookies, bearer tokens, API keys, or other secrets.")
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

      // An operator-confirmed additional asset must merge into the existing manifest,
      // preserving prior includes, exclusions, and authorization provenance.
      const added = await tool.execute({
        action: "configure_scope",
        target_url: "https://example.com",
        include: ["new.example.net"],
        merge_existing: true,
      }, {} as never)
      expect(added.metadata.saved).toBe(true)
      const mergedScope = JSON.parse(await fs.readFile(path.join(rootPath, "scope", "scope.json"), "utf-8"))
      expect(mergedScope.scopeItems).toEqual(["example.com", "*.example.com", "new.example.net"])
      expect(mergedScope.excludedItems).toEqual(["admin.example.com"])
      expect(mergedScope.authorizationSource).toBe("Example authorized disclosure program")
      expect(mergedScope.authorizationReference).toBe("https://hackerone.com/example")
      const confirmedNotes = await fs.readFile(path.join(rootPath, "notes.md"), "utf-8")
      expect(confirmedNotes).toContain("User-confirmed in-scope asset: new.example.net")
      expect(confirmedNotes).toContain("without requesting a separate policy URL or repeated proof")

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
        const permissionRequests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const scopeCtx = {
          sessionID: "test",
          messageID: "",
          agent: "cyberstrike",
          abort: AbortSignal.any([]),
          messages: [],
          metadata: () => {},
          ask: async (request: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            permissionRequests.push(request)
          },
        }

        const imported = await tool.execute({
          action: "configure_scope",
          target_url: "https://att.com",
          scope_file_path: inputPath,
          authorization_source: "Authorized disclosure program",
          authorization_reference: "https://hackerone.com/example",
        }, scopeCtx as never)

        expect(imported.metadata.saved).toBe(true)
        expect(permissionRequests.some((request) => request.permission === "read" && request.patterns.includes(inputPath))).toBe(true)
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
  await using sourceTmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
      const workspaces = await TargetWorkspaceTool.init()
      const artifact = await TargetArtifactTool.init()
      const init = await workspaces.execute({ action: "init", target_url: "https://example.com" }, {} as never)
      const workspace = init.metadata.workspace!
      const permissionRequests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
      const artifactCtx = {
        sessionID: "test",
        messageID: "",
        agent: "cyberstrike",
        abort: AbortSignal.any([]),
        messages: [],
        metadata: () => {},
        ask: async (request: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
          permissionRequests.push(request)
        },
      }
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
      const largeInput = path.join(sourceTmp.path, "large-scope.txt")
      await fs.writeFile(largeInput, "api.example.com\n" + "x".repeat(2_100_000) + "\nAuthorization: Bearer source.secret.token\n")
      const copied = await artifact.execute({
        target_url: "https://example.com",
        area: "scope",
        filename: "targets.txt",
        source_path: largeInput,
        overwrite: false,
      }, artifactCtx as never)
      expect(copied.metadata.saved).toBe(true)
      expect(permissionRequests.some((request) => request.permission === "external_directory")).toBe(true)
      expect(permissionRequests.some((request) => request.permission === "read" && request.patterns.includes(largeInput))).toBe(true)
      expect(copied.metadata.source_sha256).toMatch(/^[a-f0-9]{64}$/)
      const copiedText = await fs.readFile(copied.metadata.path!, "utf-8")
      expect(copiedText.length).toBeGreaterThan(2_000_000)
      expect(copiedText).toContain("api.example.com")
      expect(copiedText).toContain("source.secret.token")

      const symlinkPath = path.join(sourceTmp.path, "linked-scope.txt")
      await fs.symlink(largeInput, symlinkPath)
      const symlinkCopy = await artifact.execute({
        target_url: "https://example.com",
        area: "scope",
        filename: "linked-targets.txt",
        source_path: symlinkPath,
        overwrite: false,
      }, artifactCtx as never)
      expect(symlinkCopy.metadata.saved).toBe(false)
      expect(symlinkCopy.metadata.reason).toBe("unsafe_source_file")

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


test("explicit user confirmation can initialize one exact asset without a policy URL and records useful notes", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
        const tool = await TargetWorkspaceTool.init()
        const init = await tool.execute({ action: "init", target_url: "https://program-root.example.test" }, {} as never)
        const rootPath = init.metadata.workspace!
        const saved = await tool.execute({
          action: "configure_scope",
          target_url: "https://program-root.example.test",
          include: ["https://fullbarhomologa.modoblackfullbar.com.br"],
          user_confirmed_scope: true,
        }, {} as never)

        expect(saved.metadata.saved).toBe(true)
        expect(saved.metadata.scope_configured).toBe(true)
        const scope = await TargetMemory.getScope("https://program-root.example.test")
        expect(scope?.status).toBe("configured")
        expect(scope?.authorizationReference).toBeNull()
        expect(scope?.authorizationSource).toContain("User-confirmed in conversation")
        expect(scope?.scopeItems).toEqual(["https://fullbarhomologa.modoblackfullbar.com.br"])
        const manifest = JSON.parse(await fs.readFile(path.join(rootPath, "scope", "scope.json"), "utf-8"))
        expect(manifest.authorizationReference).toBeNull()
        expect(manifest.authorizationSource).toContain("User-confirmed in conversation")
        const notes = await fs.readFile(path.join(rootPath, "notes.md"), "utf-8")
        expect(notes).toContain("User-confirmed in-scope asset: https://fullbarhomologa.modoblackfullbar.com.br")
        expect(notes).toContain("No wildcard or sibling assets were inferred")
        expect((await TargetMemory.checkURLScope("https://fullbarhomologa.modoblackfullbar.com.br/")).allowed).toBe(true)
        expect((await TargetMemory.checkURLScope("https://unrelated.modoblackfullbar.com.br/")).allowed).toBe(false)

        // A second explicit confirmation extends the same user-confirmed manifest;
        // its missing external policy URL must not turn the continuation into a blocker.
        const added = await tool.execute({
          action: "configure_scope",
          target_url: "https://program-root.example.test",
          include: ["https://api.fullbarhomologa.modoblackfullbar.com.br"],
          merge_existing: true,
        }, {} as never)
        expect(added.metadata.saved).toBe(true)
        const extended = await TargetMemory.getScope("https://program-root.example.test")
        expect(extended?.authorizationReference).toBeNull()
        expect(extended?.scopeItems).toEqual([
          "https://fullbarhomologa.modoblackfullbar.com.br",
          "https://api.fullbarhomologa.modoblackfullbar.com.br",
        ])
        const extendedNotes = await fs.readFile(path.join(rootPath, "notes.md"), "utf-8")
        expect(extendedNotes).toContain("User-confirmed in-scope asset: https://api.fullbarhomologa.modoblackfullbar.com.br")
      } finally {
        await Instance.dispose()
      }
    },
  })
})

test("user-confirmed incremental scope extension cannot override an explicit exclusion", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      try {
        const tool = await TargetWorkspaceTool.init()
        const init = await tool.execute({ action: "init", target_url: "https://program-root.example.test" }, {} as never)
        await tool.execute({
          action: "configure_scope",
          target_url: "https://program-root.example.test",
          include: ["example.test", "*.example.test"],
          exclude: ["admin.example.test"],
          authorization_source: "Example program",
          authorization_reference: "https://hackerone.com/example",
        }, {} as never)

        const blocked = await tool.execute({
          action: "configure_scope",
          target_url: "https://program-root.example.test",
          include: ["admin.example.test"],
          merge_existing: true,
        }, {} as never)
        expect(blocked.metadata.saved).toBe(false)
        expect(blocked.output).toContain("explicit exclusion")
        const scope = await TargetMemory.getScope("https://program-root.example.test")
        expect(scope?.scopeItems).toEqual(["example.test", "*.example.test"])
        expect(scope?.excludedItems).toEqual(["admin.example.test"])
        const notes = await fs.readFile(path.join(init.metadata.workspace!, "notes.md"), "utf-8")
        expect(notes).toContain("Scope confirmation conflicts with a saved exclusion")
        expect(notes).toContain("admin.example.test")
      } finally {
        await Instance.dispose()
      }
    },
  })
})

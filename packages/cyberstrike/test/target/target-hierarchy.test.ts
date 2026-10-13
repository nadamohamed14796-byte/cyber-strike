import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"

describe("target asset hierarchy", () => {
  test("nests authorized observed subdomains, updates registry/notes, and applies parent exclusions", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const configured = await TargetMemory.configureScope("https://example.com", {
          include: ["example.com", "*.example.com"],
          exclude: ["admin.example.com"],
          authorizationSource: "Example authorized program",
          authorizationReference: "https://example.com/security",
        })

        const child = await TargetMemory.registerObservedAsset("https://api.example.com/v1/users", "api")
        expect(child).not.toBeNull()
        expect(child!.parentTargetID).toBe(configured.workspace.id)
        expect(child!.assetType).toBe("api")
        expect(child!.relativePath.startsWith(path.join(configured.workspace.relativePath, "assets"))).toBe(true)
        expect(await fs.stat(child!.workspacePath)).toBeTruthy()

        await TargetMemory.addNote("https://api.example.com", {
          kind: "asset",
          title: "API evidence",
          content: "This note must survive a later scope change.",
          source: "test",
        })
        const repeated = await TargetMemory.registerObservedAsset("https://api.example.com/other/path", "api")
        expect(repeated?.id).toBe(child!.id)
        expect(TargetMemory.children(configured.workspace.id).map((item) => item.id)).toEqual([child!.id])

        const registry = JSON.parse(await fs.readFile(path.join(configured.workspace.workspacePath, "assets", "registry.json"), "utf-8"))
        expect(registry.assets).toHaveLength(1)
        expect(registry.assets[0].targetURL).toBe("https://api.example.com")
        const notes = await fs.readFile(path.join(configured.workspace.workspacePath, "notes.md"), "utf-8")
        expect(notes).toContain("Managed Asset Inventory")
        expect(notes).toContain("https://api.example.com")

        const allowed = await TargetMemory.checkURLScope("https://api.example.com/v1/users")
        expect(allowed.allowed).toBe(true)
        expect(allowed.workspace?.id).toBe(child!.id)
        expect(allowed.scope?.targetURL).toBe(configured.workspace.targetURL)

        expect(await TargetMemory.registerObservedAsset("https://admin.example.com", "application")).toBeNull()
        const denied = await TargetMemory.checkURLScope("https://admin.example.com/login")
        expect(denied.allowed).toBe(false)
        expect(denied.reason).toContain("exclusion")

        // Narrowing the saved scope detaches old children instead of leaving them
        // presented as in-scope under the root; the child data remains on disk.
        await TargetMemory.configureScope("https://example.com", {
          include: ["example.com"],
          authorizationSource: "Example authorized program",
          authorizationReference: "https://example.com/security",
        })
        const detached = await TargetMemory.get("https://api.example.com")
        expect(detached?.id).toBe(child!.id)
        expect(detached?.parentTargetID).toBeNull()
        expect(detached?.workspacePath).toContain(path.join(".cyberstrike", "targets"))
        const detachedNotes = await fs.readFile(path.join(detached!.workspacePath, "notes.md"), "utf-8")
        expect(detachedNotes).toContain("https://api.example.com")
        expect(detachedNotes).toContain("This note must survive a later scope change.")
      },
    })
  })

  test("configuring scope nests earlier standalone workspaces without discarding their notes", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const existing = await TargetMemory.ensure("https://app.example.net")
        await TargetMemory.addNote("https://app.example.net", {
          kind: "manual",
          title: "Keep this note",
          content: "Existing asset research must remain in the same workspace after attachment.",
          source: "test",
        })
        const root = await TargetMemory.configureScope("https://example.net", {
          include: ["example.net", "*.example.net"],
          authorizationSource: "Example authorized program",
          authorizationReference: "https://example.net/security",
        })
        const nested = await TargetMemory.get("https://app.example.net")
        expect(nested?.id).toBe(existing.id)
        expect(nested?.parentTargetID).toBe(root.workspace.id)
        expect(nested?.workspacePath).toContain(path.join(root.workspace.workspacePath, "assets"))
        const notes = await fs.readFile(path.join(nested!.workspacePath, "notes.md"), "utf-8")
        expect(notes).toContain("Keep this note")
        expect(notes).toContain("Existing asset research must remain")
      },
    })
  })
})

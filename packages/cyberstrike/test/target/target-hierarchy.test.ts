import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { Session } from "../../src/session"
import { Intel } from "../../src/methodology/intel"

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

  test("keeps an existing program root out of a descendant wildcard's parent chain", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const root = await TargetMemory.ensure("https://www.mercadolibre.com")
        const domain = await TargetMemory.ensure("https://mercadolibre.com")
        expect(root.parentTargetID).toBeNull()
        expect(domain.parentTargetID).toBeNull()

        await TargetMemory.configureScope("https://mercadolibre.com", {
          include: ["mercadolibre.com", "*.mercadolibre.com"],
          authorizationSource: "Mercado Libre scope hierarchy regression fixture",
          authorizationReference: "https://example.test/policy",
        })

        // The child wildcard now matches www.mercadolibre.com, but must not
        // cause the existing root workspace to be reparented beneath that child.
        const configuredRoot = await TargetMemory.configureScope("https://www.mercadolibre.com", {
          include: ["www.mercadolibre.com", "*.mercadolibre.com"],
          authorizationSource: "Mercado Libre root scope regression fixture",
          authorizationReference: "https://example.test/policy",
        })
        const persistedRoot = await TargetMemory.get("https://www.mercadolibre.com")
        const persistedDomain = await TargetMemory.get("https://mercadolibre.com")

        expect(configuredRoot.workspace.id).toBe(root.id)
        expect(persistedRoot?.parentTargetID).toBeNull()
        expect(persistedDomain?.parentTargetID).toBeNull()
        expect(() => TargetMemory.list()).not.toThrow()
      },
    })
  })

  test("attaches explicitly scoped domains unrelated to the program workspace hostname", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const root = await TargetMemory.configureScope("https://mercadolibre", {
          include: ["https://fullbarhomologa.modoblackfullbar.com.br"],
          authorizationSource: "Authorized program scope fixture",
          authorizationReference: "https://program.example.test/policy",
        })

        const attached = await TargetMemory.attachAsset(
          root.workspace.targetURL,
          "https://fullbarhomologa.modoblackfullbar.com.br",
          "application",
        )
        expect(attached.parent.id).toBe(root.workspace.id)
        expect(attached.asset.targetURL).toBe("https://fullbarhomologa.modoblackfullbar.com.br")
        expect(attached.asset.parentTargetID).toBe(root.workspace.id)

        // Explicit exclusions override wildcard includes for unrelated domains too.
        await TargetMemory.configureScope(root.workspace.targetURL, {
          include: ["*.modoblackfullbar.com.br"],
          exclude: ["fullbarhomologa.modoblackfullbar.com.br"],
          authorizationSource: "Authorized program scope fixture",
          authorizationReference: "https://program.example.test/policy",
        })
        await expect(
          TargetMemory.attachAsset(
            root.workspace.targetURL,
            "https://fullbarhomologa.modoblackfullbar.com.br",
            "application",
          ),
        ).rejects.toThrow(/not unambiguously authorized/i)
      },
    })
  })

  test("explicit parent selection cannot bypass a parent exclusion or ancestor scope", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const root = await TargetMemory.configureScope("https://example.test", {
          include: ["example.test", "*.example.test"],
          exclude: ["admin.example.test"],
          authorizationSource: "Test program",
          authorizationReference: "https://example.test/security",
        })

        await expect(
          TargetMemory.ensure("https://admin.example.test", { parentTargetURL: root.workspace.targetURL }),
        ).rejects.toThrow(/do not authorize this child target/i)

        const denied = await TargetMemory.get("https://admin.example.test")
        expect(denied).toBeNull()
        expect(TargetMemory.children(root.workspace.id)).toHaveLength(0)
      },
    })
  })

  test("supports nested subdomains only when every parent scope authorizes the origin", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const root = await TargetMemory.configureScope("https://example.org", {
          include: ["example.org", "*.example.org"],
          authorizationSource: "Root program",
          authorizationReference: "https://example.org/security",
        })
        const appScope = await TargetMemory.configureScope("https://app.example.org", {
          include: ["app.example.org", "*.app.example.org"],
          exclude: ["admin.app.example.org"],
          authorizationSource: "Nested app scope",
          authorizationReference: "https://app.example.org/security",
        })
        expect(appScope.workspace.parentTargetID).toBe(root.workspace.id)

        const nested = await TargetMemory.registerObservedAsset("https://api.app.example.org/v1", "api")
        expect(nested?.parentTargetID).toBe(appScope.workspace.id)
        const decision = await TargetMemory.checkURLScope("https://api.app.example.org/v1")
        expect(decision.allowed).toBe(true)
        expect(decision.workspace?.id).toBe(nested?.id)

        expect(await TargetMemory.registerObservedAsset("https://admin.app.example.org", "application")).toBeNull()
        const denied = await TargetMemory.checkURLScope("https://admin.app.example.org/")
        expect(denied.allowed).toBe(false)
        expect(denied.reason).toContain("exclusion")
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


test("session target context shows the program root, selected asset, registered tree, and separated notes", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const root = await TargetMemory.configureScope("https://context-example.test", {
        include: ["context-example.test", "*.context-example.test"],
        exclude: ["admin.context-example.test"],
        authorizationSource: "Context hierarchy test program",
        authorizationReference: "https://context-example.test/security",
      })
      const child = await TargetMemory.registerObservedAsset("https://api.context-example.test/v1/users", "api")
      expect(child).not.toBeNull()

      await TargetMemory.addNote(root.workspace.targetURL, {
        kind: "manual",
        title: "Program-wide note",
        content: "Program policy and shared architecture overview.",
        source: "test",
      })
      await TargetMemory.addNote(child!.targetURL, {
        kind: "asset",
        title: "API-specific note",
        content: "The API exposes a versioned user endpoint.",
        source: "test",
      })

      const session = await Session.create({})
      try {
        Intel.add({
          sessionID: session.id,
          data: {
            type: "endpoint",
            title: "Versioned API users endpoint",
            asset: "https://api.context-example.test/v1/users",
            confidenceLevel: "confirmed",
          },
        })
        const context = TargetMemory.contextForSession(session.id)
        expect(context).not.toBeNull()
        expect(context).toContain("Program/root target: https://context-example.test")
        expect(context).toContain("Selected asset: https://api.context-example.test")
        expect(context).toContain("Ancestor chain: https://context-example.test -> https://api.context-example.test")
        expect(context).toContain("[api] https://api.context-example.test")
        expect(context).toContain("Program-wide note")
        expect(context).toContain("API-specific note")
        expect(context).toContain("Every ancestor scope and exclusion also applies")
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

test("refines existing child asset types without downgrading them on later generic observations", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const root = await TargetMemory.configureScope("https://type-example.test", {
        include: ["type-example.test", "*.type-example.test"],
        authorizationSource: "Asset classification test",
        authorizationReference: "https://type-example.test/security",
      })

      const initial = await TargetMemory.registerObservedAsset("https://service.type-example.test", "subdomain")
      expect(initial?.assetType).toBe("subdomain")

      const refined = await TargetMemory.registerObservedAsset("https://service.type-example.test/health", "application")
      expect(refined?.id).toBe(initial?.id)
      expect(refined?.assetType).toBe("application")

      // A later observer may only know the hostname; it must not erase the
      // more specific classification already persisted for this same asset.
      const rediscovered = await TargetMemory.registerObservedAsset("https://service.type-example.test/api")
      expect(rediscovered?.id).toBe(initial?.id)
      expect(rediscovered?.assetType).toBe("application")

      const registry = JSON.parse(await fs.readFile(path.join(root.workspace.workspacePath, "assets", "registry.json"), "utf-8"))
      expect(registry.assets).toHaveLength(1)
      expect(registry.assets[0].type).toBe("application")
    },
  })
})


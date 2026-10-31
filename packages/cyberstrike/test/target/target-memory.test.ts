import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { Database, eq } from "../../src/storage/db"
import { TargetNoteTable, TargetWorkspaceTable } from "../../src/target/target.sql"
import { targetWorkspaceOwnerKey } from "../../src/target/project-key"

describe("target memory normalization", () => {
  test("normalizes a bare hostname and removes query strings and fragments", () => {
    const target = TargetMemory.normalize("EXAMPLE.com/?token=must-not-be-saved#frag")
    expect(target.targetURL).toBe("https://example.com")
    expect(target.targetKey).toBe("https://example.com")
    expect(target.hostname).toBe("example.com")
    expect(target.slug).toMatch(/^example-com-[a-f0-9]{8}$/)
  })

  test("keeps a normalized path while avoiding sensitive URL parameters", () => {
    const target = TargetMemory.normalize("https://Example.com/Api/v1/?key=secret#section")
    expect(target.targetURL).toBe("https://example.com/Api/v1")
    expect(target.targetKey).toBe("https://example.com/Api/v1")
    expect(target.hostname).toBe("example.com")
  })

  test("separates different target paths on the same host", () => {
    const first = TargetMemory.normalize("https://example.com/app-a")
    const second = TargetMemory.normalize("https://example.com/app-b")
    expect(first.targetKey).not.toBe(second.targetKey)
    expect(first.slug).not.toBe(second.slug)
  })

  test("rejects unsupported schemes and credentials", () => {
    expect(() => TargetMemory.normalize("ftp://example.com")).toThrow()
    expect(() => TargetMemory.normalize("https://user:password@example.com")).toThrow()
  })

  test("persists target workspace and notes idempotently in SQLite and notes.md", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const target = await TargetMemory.ensure("https://example.com")
        for (const directory of ["scope", "assets", "runs"]) {
          expect((await fs.stat(path.join(target.workspacePath, directory))).isDirectory()).toBe(true)
        }
        await expect(fs.stat(path.join(target.workspacePath, "javascript"))).rejects.toThrow()
        await expect(fs.stat(path.join(target.workspacePath, "recon"))).rejects.toThrow()
        await TargetMemory.writeWorkspaceFile(target, "javascript/analysis.md", "ok\n")
        expect((await fs.stat(path.join(target.workspacePath, "javascript"))).isDirectory()).toBe(true)
        expect(await fs.readFile(path.join(target.workspacePath, "javascript", "analysis.md"), "utf-8")).toBe("ok\n")
        expect(await fs.readFile(path.join(target.workspacePath, "target.json"), "utf-8")).toContain("example.com")
        const manifest = JSON.parse(await fs.readFile(path.join(target.workspacePath, "workspace.json"), "utf-8"))
        expect(manifest.workspaceID).toBe(target.id)
        expect(manifest.targetURL).toBe("https://example.com")
        const scope = JSON.parse(await fs.readFile(path.join(target.workspacePath, "scope", "scope.json"), "utf-8"))
        expect(scope.status).toBe("unconfigured")
        expect(scope.scopeItems).toEqual([])
        expect(await fs.readFile(path.join(target.workspacePath, "README.md"), "utf-8")).toContain("Active testing requires an explicitly configured")

        const first = await TargetMemory.addNote("https://example.com", {
          kind: "lesson",
          title: "Authorization boundary",
          content: "Compare an authorized owner request with a controlled unauthorized request.",
          source: "test",
          tags: ["idor", "authorization"],
        })
        const duplicate = await TargetMemory.addNote("https://example.com", {
          kind: "lesson",
          title: "Authorization boundary",
          content: "Compare an authorized owner request with a controlled unauthorized request.",
          source: "test",
          tags: ["idor", "authorization"],
        })

        expect(first.created).toBe(true)
        expect(duplicate.created).toBe(false)
        expect(duplicate.note.id).toBe(first.note.id)
        expect(TargetMemory.allNotes(target.id)).toHaveLength(1)
        const notesFile = await fs.readFile(path.join(target.workspacePath, "notes.md"), "utf-8")
        expect(notesFile).toContain("Authorization boundary")
        expect(notesFile).toContain("controlled unauthorized request")
      },
    })
  })
})

test("upserts stable target-note identity instead of accumulating snapshot duplicates", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const targetURL = "https://correlation-notes.example.test"
      const first = await TargetMemory.addNote(targetURL, {
        kind: "javascript",
        title: "JavaScript correlation snapshot - session-root - all assets",
        content: "One source and two endpoint candidates.",
        source: "session:session-root",
        status: "observed",
        tags: ["javascript", "correlation"],
        upsertByIdentity: true,
      })
      const refreshed = await TargetMemory.addNote(targetURL, {
        kind: "javascript",
        title: "JavaScript correlation snapshot - session-root - all assets",
        content: "Two sources and five endpoint candidates.",
        source: "session:session-root",
        status: "observed",
        tags: ["javascript", "correlation"],
        upsertByIdentity: true,
      })
      const notes = TargetMemory.allNotes(first.workspace.id)
      expect(first.created).toBe(true)
      expect(refreshed.created).toBe(false)
      expect(refreshed.updated).toBe(true)
      expect(refreshed.note.id).toBe(first.note.id)
      expect(notes).toHaveLength(1)
      expect(notes[0]?.content).toContain("five endpoint candidates")
      const markdown = await fs.readFile(path.join(first.workspace.workspacePath, "notes.md"), "utf-8")
      expect(markdown.match(/<!-- cyberstrike-target-note:/g) ?? []).toHaveLength(1)
      expect(markdown).toContain("five endpoint candidates")
    },
  })
})


test("upserts endpoint notes by stable path identity across title and source changes", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://identity-path.example.test"
      const first = await TargetMemory.addNote(targetURL, {
        kind: "endpoint",
        title: "GET profile endpoint",
        content: "The endpoint returns a profile-shaped response.",
        source: "session:first",
        identityKey: "endpoint:/api/v1/profile.js:authorization",
        upsertByIdentity: true,
      })
      const refreshed = await TargetMemory.addNote(targetURL, {
        kind: "endpoint",
        title: "Profile endpoint authorization check",
        content: "Anonymous access returned 401; authenticated owner returned 200.",
        source: "session:second",
        identityKey: "endpoint:/api/v1/profile.js:authorization",
        upsertByIdentity: true,
      })
      expect(first.created).toBe(true)
      expect(refreshed.created).toBe(false)
      expect(refreshed.updated).toBe(true)
      expect(refreshed.note.id).toBe(first.note.id)
      expect(TargetMemory.allNotes(first.workspace.id)).toHaveLength(1)
      expect(refreshed.note.content).toContain("authenticated owner returned 200")
      expect(refreshed.note.content).toContain("cyberstrike-note-identity:endpoint:/api/v1/profile.js:authorization")
      await Instance.dispose()
    },
  })
})

test("target observation matching requires exact origin and scoped path", () => {
  expect(TargetMemory.targetObservationMatches("https://app.example.com/portal", "https://app.example.com/portal/api/users")).toBe(true)
  expect(TargetMemory.targetObservationMatches("https://app.example.com/portal", "https://app.example.com/portal/")).toBe(true)
  expect(TargetMemory.targetObservationMatches("https://app.example.com/portal", "https://app.example.com/other-app/api/users")).toBe(false)
  expect(TargetMemory.targetObservationMatches("https://app.example.com/portal", "https://unrelated.example.net/portal/api/users")).toBe(false)
  expect(TargetMemory.targetObservationMatches("https://app.example.com", "https://api.app.example.com/v1/users")).toBe(false)
  expect(TargetMemory.targetObservationMatches("https://app.example.com", "http://app.example.com/v1/users")).toBe(false)
  expect(TargetMemory.targetObservationMatches("https://app.example.com", "https://app.example.com:8443/v1/users")).toBe(false)
  expect(TargetMemory.targetObservationMatches("https://app.example.com", "app.example.com/v1/users")).toBe(false)
})

test("does not associate an existing target workspace with a session that has no observations", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    fn: async () => {
      const workspace = await TargetMemory.ensure("https://example.com")
      expect(TargetMemory.isObservedInSession("ses_no_observations_test", workspace.targetURL)).toBe(false)
      expect(TargetMemory.contextForSession("ses_from_another_project")).toBeNull()
      await Instance.dispose()
    },
  })
})


test("scheme-less URL scope preserves its path and does not authorize sibling paths", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const configured = await TargetMemory.configureScope("https://example.com", {
        include: ["example.com/api"],
        authorizationSource: "URL path scope regression fixture",
        authorizationReference: "https://example.com/security",
      })
      expect(configured.scope.scopeItems).toEqual(["URL: example.com/api"])
      expect((await TargetMemory.checkURLScope("https://example.com/api")).allowed).toBe(true)
      expect((await TargetMemory.checkURLScope("https://example.com/admin")).allowed).toBe(false)
      await expect(TargetMemory.configureScope("https://example.com", {
        include: ["example.com/api?token=secret"],
        authorizationSource: "URL path scope regression fixture",
        authorizationReference: "https://example.com/security",
      })).rejects.toThrow(/queries or fragments/i)
      await Instance.dispose()
    },
  })
})

test("normalizes explicit JavaScript asset URLs as exact file scopes", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const configured = await TargetMemory.configureScope("https://program.example.test", {
        include: ["https://cdn.example.test/assets/app.js?v=123", "URL: https://cdn.example.test/assets/typed.js?v=9", "https://cdn.example.test/assets/raw.js.map?hash=raw", "Source Map: https://cdn.example.test/assets/app.js.map?hash=abc"],
        authorizationSource: "Operator-confirmed JavaScript asset list",
        authorizationReference: "https://program.example.test/policy",
      })
      expect(configured.scope.scopeItems).toEqual([
        "JavaScript: https://cdn.example.test/assets/app.js",
        "JavaScript: https://cdn.example.test/assets/typed.js",
        "Source Map: https://cdn.example.test/assets/raw.js.map",
        "Source Map: https://cdn.example.test/assets/app.js.map",
      ])
      expect((await TargetMemory.checkURLScope("https://cdn.example.test/assets/app.js?v=456")).allowed).toBe(true)
      expect((await TargetMemory.checkURLScope("https://cdn.example.test/assets/typed.js?v=10")).allowed).toBe(true)
      expect((await TargetMemory.checkURLScope("https://cdn.example.test/assets/other.js")).allowed).toBe(false)
      expect((await TargetMemory.checkURLScope("https://cdn.example.test/assets/app.js.map?cache=2")).allowed).toBe(true)
      expect((await TargetMemory.checkURLScope("https://cdn.example.test/assets/raw.js.map?cache=2")).allowed).toBe(true)
      expect((await TargetMemory.checkURLScope("https://cdn.example.test/assets/other.js.map")).allowed).toBe(false)
      await Instance.dispose()
    },
  })
})


test("persists an explicit target scope with authorization provenance and exclusions", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const configured = await TargetMemory.configureScope("https://example.com", {
        include: ["*.Example.com", "example.com", "mercadolibreexperience.com.*"],
        exclude: ["admin.example.com"],
        authorizationSource: "Example disclosure program",
        authorizationReference: "https://hackerone.com/example?secret=must-not-persist",
      })
      expect(configured.scope.status).toBe("configured")
      expect(configured.scope.scopeItems).toEqual(["*.example.com", "example.com", "mercadolibreexperience.com.*"])
      expect(configured.scope.excludedItems).toEqual(["admin.example.com"])
      expect(configured.scope.authorizationReference).toBe("https://hackerone.com/example")
      const saved = await TargetMemory.getScope("https://example.com")
      expect(saved?.scopeItems).toEqual(["*.example.com", "example.com", "mercadolibreexperience.com.*"])
      expect(saved?.authorizationSource).toBe("Example disclosure program")
      // An unrelated workspace on the same protocol/port must not make a wildcard target ambiguous.
      await TargetMemory.ensure("https://unrelated.example.test")
      const suffixWildcardAllowed = await TargetMemory.checkURLScope("https://mercadolibreexperience.com.ar/")
      expect(suffixWildcardAllowed.allowed).toBe(true)
      const suffixWildcardLookalike = await TargetMemory.checkURLScope("https://mercadolibreexperience.com.attacker.test/")
      expect(suffixWildcardLookalike.allowed).toBe(false)
      const allowed = await TargetMemory.checkURLScope("https://api.example.com/v1/users")
      expect(allowed.allowed).toBe(true)
      expect(allowed.workspace?.id).toBe(configured.workspace.id)
      const excluded = await TargetMemory.checkURLScope("https://admin.example.com/v1/users")
      expect(excluded.allowed).toBe(false)
      expect(excluded.reason).toContain("exclusion")
      const wrongPort = await TargetMemory.checkURLScope("https://api.example.com:8443/v1/users")
      expect(wrongPort.allowed).toBe(false)
      // A host wildcard is protocol-independent; the program workspace scheme does not narrow it.
      const wrongScheme = await TargetMemory.checkURLScope("http://api.example.com/v1/users")
      expect(wrongScheme.allowed).toBe(true)
      const wildcardLookalike = await TargetMemory.checkURLScope("http://api.example.com.attacker.test/v1/users")
      expect(wildcardLookalike.allowed).toBe(false)
      const disk = await fs.readFile(path.join(configured.workspace.workspacePath, "scope", "scope.json"), "utf-8")
      expect(disk).not.toContain("must-not-persist")
      await expect(TargetMemory.configureScope("https://example.com", {
        include: ["example.com"],
        exclude: ["example.com"],
        authorizationSource: "Example disclosure program",
        authorizationReference: "https://hackerone.com/example",
      })).rejects.toThrow(/both included and excluded/i)
      await Instance.dispose()
    },
  })
})


test("requires concrete evidence before a target note can be confirmed or disproven", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      await expect(TargetMemory.addNote("https://example.com", {
        kind: "finding",
        content: "A finding without any supporting evidence",
        status: "confirmed",
        source: "test",
      })).rejects.toThrow(/require concrete evidence/i)

      const saved = await TargetMemory.addNote("https://example.com", {
        kind: "finding",
        content: "A finding with a controlled result",
        evidence: "Observed response changed from 403 to 200 for an authorized test account.",
        status: "confirmed",
        source: "test",
      })
      expect(saved.note.status).toBe("confirmed")
      expect(saved.note.content).toContain("Evidence: Observed response changed")
      await Instance.dispose()
    },
  })
})


test("preserves exact secret evidence in private target-local notes for operator validation", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const workspace = await TargetMemory.ensure("https://example.com")
      const secret = "multi word password phrase that must not persist"
      const secondSecret = "another private phrase"
      const result = await TargetMemory.addNote("https://example.com", {
        kind: "manual",
        title: "Login observation",
        content: '{"password":"' + secret + '","client_secret":"' + secondSecret + '"}',
        source: "test",
      })

      expect(result.note.content).toContain(secret)
      expect(result.note.content).toContain(secondSecret)
      const disk = await fs.readFile(path.join(workspace.workspacePath, "notes.md"), "utf-8")
      expect(disk).toContain(secret)
      expect(disk).toContain(secondSecret)
      await Instance.dispose()
    },
  })
})


test("refuses target workspaces that resolve through a symlink", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://example.com"
      const slug = TargetMemory.normalize(targetURL).slug
      const targetsRoot = path.join(tmp.path, ".cyberstrike", "targets")
      const outside = path.join(tmp.path, "outside-target")
      await fs.mkdir(targetsRoot, { recursive: true })
      await fs.mkdir(outside, { recursive: true })
      await fs.symlink(outside, path.join(targetsRoot, slug), "dir")

      await expect(TargetMemory.ensure(targetURL)).rejects.toThrow(/symbolic links/i)
      expect(await fs.readdir(outside)).toEqual([])
      await Instance.dispose()
    },
  })
})


test("refuses symlinked generated workspace outputs", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const workspace = await TargetMemory.ensure("https://example.com")
      expect(TargetMemory.matchesWorkspaceOrigin(workspace.id, "https://example.com/login")).toBe(true)
      expect(TargetMemory.matchesWorkspaceOrigin(workspace.id, "https://sub.example.com/login")).toBe(false)
      expect(TargetMemory.matchesWorkspaceOrigin(workspace.id, "file:///etc/passwd")).toBe(false)
      expect(TargetMemory.matchesWorkspaceOrigin("target-from-another-project", "https://example.com")).toBe(false)
      expect(TargetMemory.notes("target-from-another-project")).toEqual([])
      expect(TargetMemory.allNotes("target-from-another-project")).toEqual([])
      const forgedWorkspace = { ...workspace, projectID: "another-project" }
      await expect(
        TargetMemory.writeWorkspaceFile(forgedWorkspace, "javascript/forged.json", "must not write"),
      ).rejects.toThrow(/active project/i)
      const outsideFile = path.join(tmp.path, "outside-output.json")
      const outputLink = path.join(workspace.workspacePath, "javascript", "graph.json")
      await fs.mkdir(path.dirname(outputLink), { recursive: true })
      await fs.writeFile(outsideFile, "original", "utf-8")
      await fs.symlink(outsideFile, outputLink)

      await expect(TargetMemory.writeWorkspaceFile(workspace, "javascript/graph.json", "overwritten")).rejects.toThrow(/symbolic links/i)
      expect(await fs.readFile(outsideFile, "utf-8")).toBe("original")
      await Instance.dispose()
    },
  })
})



test("isolates persisted target memory across non-Git directories sharing the global project ID", async () => {
  await using firstDir = await tmpdir()
  await using secondDir = await tmpdir()
  const targetURL = "https://owner-isolation.example.test/account"

  const first = await Instance.provide({
    directory: firstDir.path,
    fn: async () => {
      const workspace = await TargetMemory.ensure(targetURL)
      await TargetMemory.addNote(targetURL, {
        kind: "lesson",
        title: "Private first-project note",
        content: "This note must remain confined to the first project directory.",
        source: "test",
      })
      const result = {
        id: workspace.id,
        projectID: workspace.projectID,
        workspacePath: workspace.workspacePath,
      }
      await Instance.dispose()
      return result
    },
  })

  const second = await Instance.provide({
    directory: secondDir.path,
    fn: async () => {
      const workspace = await TargetMemory.ensure(targetURL)
      const notes = TargetMemory.allNotes(workspace.id)
      const result = {
        id: workspace.id,
        projectID: workspace.projectID,
        workspacePath: workspace.workspacePath,
        notes,
      }
      await Instance.dispose()
      return result
    },
  })

  expect(first.projectID).toBe("global")
  expect(second.projectID).toBe("global")
  expect(second.id).not.toBe(first.id)
  expect(second.workspacePath).not.toBe(first.workspacePath)
  expect(second.notes).toEqual([])
})

test("serializes concurrent target-note writes and rebuilds notes.md from SQLite", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://notes-recovery.example.test"
      const workspace = await TargetMemory.ensure(targetURL)
      const added = await Promise.all(
        Array.from({ length: 12 }, (_, index) =>
          TargetMemory.addNote(targetURL, {
            kind: "asset",
            title: "Concurrent observation " + index,
            content: "Persisted note body " + index,
            source: "concurrency-regression-test",
          }),
        ),
      )

      expect(added.every((result) => result.created)).toBe(true)
      expect(TargetMemory.allNotes(workspace.id)).toHaveLength(12)

      const notesPath = path.join(workspace.workspacePath, "notes.md")
      let notesFile = await fs.readFile(notesPath, "utf-8")
      expect(notesFile.match(/<!-- cyberstrike-target-note:/g) ?? []).toHaveLength(12)
      for (let index = 0; index < 12; index++) {
        expect(notesFile).toContain("Concurrent observation " + index)
      }

      // A normal workspace open must preserve manual annotations and avoid duplicate generated entries.
      notesFile += "\n\nManual annotation preserved across reconciliation.\n"
      await fs.writeFile(notesPath, notesFile, "utf-8")
      await TargetMemory.ensure(targetURL)
      notesFile = await fs.readFile(notesPath, "utf-8")
      expect(notesFile).toContain("Manual annotation preserved across reconciliation.")
      expect(notesFile.match(/<!-- cyberstrike-target-note:/g) ?? []).toHaveLength(12)

      // SQLite remains the source of truth if the human-readable companion is lost.
      await fs.rm(notesPath)
      await TargetMemory.ensure(targetURL)
      notesFile = await fs.readFile(notesPath, "utf-8")
      expect(notesFile.match(/<!-- cyberstrike-target-note:/g) ?? []).toHaveLength(12)
      for (let index = 0; index < 12; index++) {
        expect(notesFile).toContain("Concurrent observation " + index)
      }
      await Instance.dispose()
    },
  })
})

test("serializes concurrent asset-registry updates without dropping attached assets or observations", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const configured = await TargetMemory.configureScope("https://asset-registry.example.test", {
        include: ["asset-registry.example.test", "*.asset-registry.example.test"],
        authorizationSource: "Asset registry concurrency regression fixture",
        authorizationReference: "https://asset-registry.example.test/policy",
      })
      const assetURLs = [
        "https://api.asset-registry.example.test",
        "https://cdn.asset-registry.example.test",
        "https://static.asset-registry.example.test",
        "https://auth.asset-registry.example.test",
      ]
      const observedURLs = [
        "https://media.asset-registry.example.test",
        "https://docs.asset-registry.example.test",
        "https://metrics.asset-registry.example.test",
        "https://media.asset-registry.example.test",
      ]

      await Promise.all([
        ...assetURLs.map((assetURL) =>
          TargetMemory.attachAsset(configured.workspace.targetURL, assetURL),
        ),
        ...observedURLs.map((assetURL) =>
          TargetMemory.recordAssetObservation(configured.workspace, assetURL),
        ),
      ])

      const registryPath = path.join(configured.workspace.workspacePath, "assets", "registry.json")
      const registry = JSON.parse(await fs.readFile(registryPath, "utf-8")) as {
        assets: Array<{ targetURL: string; workspaceID: string }>
        observations: Array<{ url: string; type?: string; observedAt?: string; status?: string }>
      }
      expect(registry.assets.map((asset) => asset.targetURL).sort()).toEqual([...assetURLs].sort())
      expect(new Set(registry.assets.map((asset) => asset.workspaceID)).size).toBe(assetURLs.length)
      expect(registry.observations.map((item) => item.url).sort()).toEqual([
        "https://docs.asset-registry.example.test",
        "https://media.asset-registry.example.test",
        "https://metrics.asset-registry.example.test",
      ])
      expect(registry.observations).toHaveLength(3)

      const notes = await fs.readFile(path.join(configured.workspace.workspacePath, "notes.md"), "utf-8")
      for (const assetURL of assetURLs) expect(notes).toContain(assetURL)
      await Instance.dispose()
    },
  })
})

describe("target workspace owner keys", () => {
  test("isolates non-Git project directories that share the global Project ID", () => {
    const first = targetWorkspaceOwnerKey("global", "/tmp/cyberstrike-project-a")
    const second = targetWorkspaceOwnerKey("global", "/tmp/cyberstrike-project-b")
    expect(first).not.toBe(second)
  })

  test("keeps Git project memory stable across worktrees", () => {
    expect(targetWorkspaceOwnerKey("proj_example", "/tmp/repo"))
      .toBe(targetWorkspaceOwnerKey("proj_example", "/tmp/repo-worktree"))
  })
})


test("persists long target notes, evidence, and every supplied tag", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const content = "Detailed investigation evidence. ".repeat(4_200)
      const evidence = "Captured request/response comparison. ".repeat(450)
      const tags = Array.from({ length: 35 }, (_, index) => "evidence-tag-" + index + "-" + "x".repeat(60))
      const saved = await TargetMemory.addNote("https://long-notes.example.test", {
        kind: "evidence",
        title: "Long evidence note",
        content,
        evidence,
        status: "confirmed",
        tags,
      })

      expect(saved.note.content).toContain(content.trim())
      expect(saved.note.content).toContain(evidence.trim())
      expect(saved.note.tags).toHaveLength(35)
      expect(saved.note.tags[34]).toBe(tags[34])
      expect(TargetMemory.notes(saved.workspace.id)).toHaveLength(1)

      const notesFile = await fs.readFile(path.join(saved.workspace.workspacePath, "notes.md"), "utf-8")
      expect(notesFile).toContain(content.trim())
      await Instance.dispose()
    },
  })
})


test("archives prior full note revisions when one living investigation is updated", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://note-revisions.example.test"
      const first = await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Authorization investigation",
        content: "GET /api/profile exposed the user's own profile. The role parameter has not been checked.",
        source: "agent:revision-test",
        identityKey: "endpoint:/api/profile:authorization",
        upsertByIdentity: true,
        status: "observed",
        tags: ["authorization", "baseline"],
      })
      const second = await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Authorization investigation",
        content: "GET /api/profile remains the same endpoint. Added role=admin and role=member comparisons; no cross-user impact was observed.",
        source: "agent:revision-test",
        identityKey: "endpoint:/api/profile:authorization",
        upsertByIdentity: true,
        status: "observed",
        tags: ["authorization", "baseline", "negative-result"],
      })

      expect(second.created).toBe(false)
      expect(second.updated).toBe(true)
      expect(second.note.id).toBe(first.note.id)
      expect(second.note.content).toContain("role=admin")
      expect(second.note.content).not.toContain("has not been checked")

      const active = TargetMemory.allNotes(second.workspace.id)
      expect(active.filter((note) => note.id === first.note.id)).toHaveLength(1)
      expect(active).toHaveLength(1)

      const revisions = TargetMemory.noteRevisions(second.workspace.id, second.note.id)
      expect(revisions).toHaveLength(1)
      expect(revisions[0]?.content).toContain("role parameter has not been checked")
      expect(revisions[0]?.tags).toEqual(["authorization", "baseline"])
      expect(revisions[0]?.status).toBe("observed")

      const historyFile = await fs.readFile(path.join(second.workspace.workspacePath, "notes-history.md"), "utf-8")
      expect(historyFile).toContain("# Target Note History")
      expect(historyFile).toContain("GET /api/profile exposed the user's own profile")
      expect(historyFile).toContain("role parameter has not been checked")
      expect(historyFile).toContain("Current note ID: " + second.note.id)
      await Instance.dispose()
    },
  })
})


test("resumable target context reports note and journal entries omitted by prompt ranking", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://context-notes.example.test"
      await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Current hypothesis A",
        content: "First current investigation conclusion.",
        source: "agent:context-test",
        identityKey: "context-current-a",
        upsertByIdentity: true,
        status: "observed",
      })
      await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Current hypothesis B",
        content: "Second current investigation conclusion.",
        source: "agent:context-test",
        identityKey: "context-current-b",
        upsertByIdentity: true,
        status: "observed",
      })
      await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Journal experiment A",
        content: "First archived experiment.",
        source: "agent:context-test",
        upsertByIdentity: false,
        status: "observed",
        tags: ["journal"],
      })
      await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Journal experiment B",
        content: "Second archived experiment.",
        source: "agent:context-test",
        upsertByIdentity: false,
        status: "observed",
        tags: ["journal"],
      })

      const session = await Session.create({ title: "target-context-note-paging-test" })
      const request = Request.add({
        sessionID: session.id,
        method: "GET",
        normalizedPath: "/api/profile",
        origin: targetURL,
        keyHash: "target-context-note-paging-test-key",
      })
      expect(request).toBeDefined()

      const context = TargetMemory.contextForSession(session.id, 1)
      if (context === null) throw new Error("Expected target memory context for an observed target")
      expect(context).toContain("PARTIAL NOTE SELECTION")
      expect(context).toContain("1 selected-asset current notes")
      expect(context).toContain("1 selected-asset journal entries")
      expect(context).toContain("Use target_notes_read")
      expect([context.includes("First archived experiment."), context.includes("Second archived experiment.")].filter(Boolean)).toHaveLength(1)
      await Session.remove(session.id)
      await Instance.dispose()
    },
  })
})


test("bounds prompt note reads while preserving older confirmed notes", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://bounded-context-notes.example.test"
      const workspace = await TargetMemory.ensure(targetURL)
      const now = Date.now()
      const rows = Array.from({ length: 505 }, (_, index) => ({
        id: "context-preview-note-" + index,
        target_id: workspace.id,
        kind: index === 0 ? "finding" : "manual",
        title: index === 0 ? "Older confirmed authorization finding" : "Context note " + index,
        content: "Context preview fixture note " + index,
        source: "agent:context-preview-test",
        content_hash: "context-preview-hash-" + index,
        status: index === 0 ? "confirmed" : "observed",
        tags: [],
        time_created: now - (505 - index) * 1000,
        time_updated: now - (505 - index) * 1000,
      }))
      Database.use((db) => {
        for (let offset = 0; offset < rows.length; offset += 100) {
          db.insert(TargetNoteTable).values(rows.slice(offset, offset + 100)).run()
        }
      })
      const session = await Session.create({ title: "bounded-target-context-notes-test" })
      const request = Request.add({
        sessionID: session.id,
        method: "GET",
        normalizedPath: "/api/profile",
        origin: targetURL,
        keyHash: "bounded-target-context-notes-test-key",
      })
      expect(request).toBeDefined()

      const context = TargetMemory.contextForSession(session.id)
      if (context === null) throw new Error("Expected target memory context for an observed target")
      expect(context).toContain("Older confirmed authorization finding")
      expect(context).toContain("additional notes outside the bounded prompt preview")
      expect(context).toContain("target_notes_read")
      expect(Database.use((db) => db.select().from(TargetNoteTable).where(eq(TargetNoteTable.target_id, workspace.id)).all())).toHaveLength(505)
      await Session.remove(session.id)
      await Instance.dispose()
    },
  })
})


test("serializes concurrent current-note updates without losing intermediate evidence", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://concurrent-notes.example.test"
      const baseline = await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Concurrent authorization investigation",
        content: "Baseline: role and ownership have not been compared.",
        source: "agent:concurrency-test",
        identityKey: "endpoint:/api/profile:authorization-concurrency",
        upsertByIdentity: true,
        status: "observed",
      })
      const writes = await Promise.all([
        TargetMemory.addNote(targetURL, {
          kind: "manual",
          title: "Concurrent authorization investigation",
          content: "Experiment A: role=admin was compared under the same owner account.",
          source: "agent:concurrency-test",
          identityKey: "endpoint:/api/profile:authorization-concurrency",
          upsertByIdentity: true,
          status: "observed",
        }),
        TargetMemory.addNote(targetURL, {
          kind: "manual",
          title: "Concurrent authorization investigation",
          content: "Experiment B: a second controlled account was used to compare ownership.",
          source: "agent:concurrency-test",
          identityKey: "endpoint:/api/profile:authorization-concurrency",
          upsertByIdentity: true,
          status: "observed",
        }),
      ])
      expect(writes.every((result) => result.note.id === baseline.note.id)).toBe(true)
      const revisions = TargetMemory.noteRevisions(baseline.workspace.id, baseline.note.id)
      const current = TargetMemory.allNotes(baseline.workspace.id).find((note) => note.id === baseline.note.id)
      const persistedStates = [...revisions.map((revision) => revision.content), current?.content ?? ""].join("\\n")
      expect(revisions).toHaveLength(2)
      expect(persistedStates).toContain("Baseline: role and ownership")
      expect(persistedStates).toContain("Experiment A:")
      expect(persistedStates).toContain("Experiment B:")
      await Instance.dispose()
    },
  })
})


test("notes access allows a registered ancestor of an observed asset but not an unrelated workspace", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const parentURL = "https://program.example.test"
      const childURL = "https://api.program.example.test"
      const siblingURL = "https://other-program.example.test"
      const parent = await TargetMemory.ensure(parentURL)
      const child = await TargetMemory.ensure(childURL)
      const sibling = await TargetMemory.ensure(siblingURL)

      // Simulate an already-established asset relationship. This function verifies
      // the persisted parent chain rather than guessing by DNS suffix.
      Database.use((db) => db.update(TargetWorkspaceTable)
        .set({ parent_target_id: parent.id, asset_type: "subdomain" })
        .where(eq(TargetWorkspaceTable.id, child.id))
        .run())

      const session = await Session.create({ title: "ancestor-note-read-test" })
      const request = Request.add({
        sessionID: session.id,
        method: "GET",
        normalizedPath: "/api/profile",
        origin: childURL,
        keyHash: "ancestor-note-read-test-key",
      })
      expect(request).toBeDefined()

      expect(TargetMemory.isObservedOrAncestorInSession(session.id, childURL)).toBe(true)
      expect(TargetMemory.isObservedOrAncestorInSession(session.id, parentURL)).toBe(true)
      expect(TargetMemory.isObservedOrAncestorInSession(session.id, siblingURL)).toBe(false)

      await Session.remove(session.id)
      await Instance.dispose()
    },
  })
})


test("program-root policy workspaces authorize unrelated explicitly scoped domains", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const configured = await TargetMemory.configureScope("https://hackerone.com/programs/example-program", {
        include: ["example.com", "*.example.net", "API: api.example.org:8443"],
        exclude: ["admin.example.com"],
        authorizationSource: "Program policy scope regression fixture",
        authorizationReference: "https://hackerone.com/programs/example-program",
      })
      const apex = await TargetMemory.checkURLScope("https://example.com/")
      const subdomain = await TargetMemory.checkURLScope("https://api.example.net/")
      const excluded = await TargetMemory.checkURLScope("https://admin.example.com/")
      const unrelated = await TargetMemory.checkURLScope("https://not-listed.example.org/")
      const unlistedPort = await TargetMemory.checkURLScope("https://example.com:8443/")
      const typedAPIWithPort = await TargetMemory.checkURLScope("https://api.example.org:8443/")
      const typedAPIWrongPort = await TargetMemory.checkURLScope("https://api.example.org:9443/")

      expect(apex.allowed).toBe(true)
      expect(apex.workspace?.id).toBe(configured.workspace.id)
      expect(subdomain.allowed).toBe(true)
      expect(subdomain.workspace?.id).toBe(configured.workspace.id)
      expect(excluded.allowed).toBe(false)
      expect(excluded.reason).toContain("exclusion")
      expect(unrelated.allowed).toBe(false)
      expect(unlistedPort.allowed).toBe(false)
      expect(typedAPIWithPort.allowed).toBe(true)
      expect(typedAPIWithPort.workspace?.id).toBe(configured.workspace.id)
      expect(typedAPIWrongPort.allowed).toBe(false)
    },
  })
})

test("MercadoPago program root authorizes explicitly listed MercadoLibre wildcard assets in one workspace", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const configured = await TargetMemory.configureScope("https://mercadopago.com", {
        include: ["mercadopago.com", "*.mercadopago.com", "*.mercadolibre.com", "mercadolibreexperience.com.*"],
        authorizationSource: "MercadoPago/MercadoLibre program scope regression fixture",
        authorizationReference: "https://example.test/program-policy",
      })

      const api = await TargetMemory.checkURLScope("https://api.mercadolibre.com/")
      const nested = await TargetMemory.checkURLScope("https://edge.api.mercadolibre.com/v1/items")
      const suffix = await TargetMemory.checkURLScope("https://mercadolibreexperience.com.ar/")
      const lookalike = await TargetMemory.checkURLScope("https://notmercadolibre.com/")

      expect(api.allowed).toBe(true)
      expect(api.workspace?.id).toBe(configured.workspace.id)
      expect(nested.allowed).toBe(true)
      expect(nested.workspace?.id).toBe(configured.workspace.id)
      expect(suffix.allowed).toBe(true)
      expect(suffix.workspace?.id).toBe(configured.workspace.id)
      expect(lookalike.allowed).toBe(false)
      expect(TargetMemory.list().filter((workspace) => workspace.parentTargetID === null)).toHaveLength(1)
    },
  })
})


test("user-confirmed scope without a policy URL must be exactly one asset, not a wildcard or CIDR", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      await expect(TargetMemory.configureScope("https://program-root.example.test", {
        include: ["*.example.net"],
        authorizationSource: "User-confirmed in conversation",
        userConfirmed: true,
      })).rejects.toThrow(/exact hostname/i)

      await expect(TargetMemory.configureScope("https://program-root.example.test", {
        include: ["app.example.net", "api.example.net"],
        authorizationSource: "User-confirmed in conversation",
        userConfirmed: true,
      })).rejects.toThrow(/exact hostname/i)

      await expect(TargetMemory.configureScope("https://program-root.example.test", {
        include: ["192.0.2.0/24"],
        authorizationSource: "User-confirmed in conversation",
        userConfirmed: true,
      })).rejects.toThrow(/exact hostname/i)

      await expect(TargetMemory.configureScope("https://program-root.example.test", {
        include: ["https://app.example.net/*"],
        authorizationSource: "User-confirmed in conversation",
        userConfirmed: true,
      })).rejects.toThrow(/exact hostname/i)
    },
  })
})



test("migrates legacy flattened endpoint evidence without inventing per-source ownership", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://legacy-endpoint-notes.example.test"
      const first = await TargetMemory.mergeCanonicalEndpointRecord({
        targetURL,
        origin: "https://api.example.test",
        path: "/api/legacy/{id}",
        operations: [{
          method: "POST",
          methodEvidenceSources: ["javascript", "traffic"],
          pathParameters: ["id"],
          bodyParameters: ["role"],
          headerNames: ["authorization"],
          authSignals: ["bearer-token"],
          sourceFiles: ["javascript/legacy.js"],
          requestIDs: ["req-legacy-post"],
          observedInTraffic: true,
          confidence: "observed",
        }],
      })

      const endpoint = TargetMemory.allNotes(first.workspace.id).find((note) => note.id === first.note.id)!
      const marker = endpoint.content.match(
        /<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_BEGIN -->\\n([\\s\\S]*?)\\n<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_END -->/,
      )
      expect(marker).not.toBeNull()
      const legacy = JSON.parse(marker![1]!)
      delete legacy.operations[0].evidence
      const legacyContent = endpoint.content.replace(marker![0], [
        "<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_BEGIN -->",
        JSON.stringify(legacy, null, 2),
        "<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_END -->",
      ].join("\\n"))
      Database.use((db) => db.update(TargetNoteTable)
        .set({ content: legacyContent })
        .where(eq(TargetNoteTable.id, endpoint.id))
        .run())

      await TargetMemory.mergeCanonicalEndpointRecord({
        targetURL,
        origin: "https://api.example.test",
        path: "/api/legacy/{userId}",
        operations: [{
          method: "POST",
          methodEvidenceSources: ["javascript"],
          sourceFiles: ["javascript/new-callsite.js"],
          bodyParameters: ["displayName"],
          confidence: "candidate",
        }],
      })

      const migratedNote = TargetMemory.allNotes(first.workspace.id).find((note) => note.id === endpoint.id)!
      const migratedMarker = migratedNote.content.match(
        /<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_BEGIN -->\\n([\\s\\S]*?)\\n<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_END -->/,
      )
      expect(migratedMarker).not.toBeNull()
      const migrated = JSON.parse(migratedMarker![1]!)
      const operation = migrated.operations.find((item: { method: string }) => item.method === "POST")
      const uncertain = operation.evidence.find((item: { source: string }) => item.source === "other")
      const traffic = operation.evidence.find((item: { source: string }) => item.source === "traffic")
      const javascript = operation.evidence.find((item: { source: string }) => item.source === "javascript")

      expect(uncertain.pathParameters).toEqual(["id"])
      expect(uncertain.bodyParameters).toEqual(["role"])
      expect(uncertain.headerNames).toEqual(["authorization"])
      expect(uncertain.authSignals).toEqual(["bearer-token"])
      expect(uncertain.sourceFiles).toEqual(["javascript/legacy.js"])
      expect(uncertain.requestIDs).toEqual([])
      expect(traffic.requestIDs).toEqual(["req-legacy-post"])
      expect(traffic.bodyParameters).toEqual([])
      expect(traffic.headerNames).toEqual([])
      expect(javascript.sourceFiles).toEqual(["javascript/new-callsite.js"])
      expect(javascript.bodyParameters).toEqual(["displayName"])
      expect(operation.bodyParameters).toEqual(["role", "displayName"])
      expect(operation.requestIDs).toEqual(["req-legacy-post"])
    },
  })
})

test("merges JavaScript and captured methods into one canonical endpoint note without mixing contracts", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://endpoint-notes.example.test"
      const first = await TargetMemory.mergeCanonicalEndpointRecord({
        targetURL,
        origin: "https://api.example.test",
        path: "/api/users/{id}",
        sourceFiles: ["javascript/routes.js", "javascript/users.js"],
        operations: [{
          method: "POST",
          methodEvidenceSources: ["javascript"],
          bodyParameters: ["userId", "email"],
          headerNames: ["content-type", "authorization"],
          contentTypes: ["application/json"],
          authSignals: ["bearer-token"],
          sourceFiles: ["javascript/users.js"],
          confidence: "candidate",
        }],
        unattributed: {
          queryParameters: ["route-level-clue"],
          sourceFiles: ["javascript/routes.js"],
        },
      })

      const second = await TargetMemory.mergeCanonicalEndpointRecord({
        targetURL,
        origin: "https://api.example.test",
        path: "/api/users/{userId}",
        operations: [{
          method: "GET",
          methodEvidenceSources: ["traffic"],
          queryParameters: ["include"],
          requestIDs: ["req-get-1"],
          observedInTraffic: true,
          confidence: "observed",
        }],
      })

      const repeatedTraffic = await TargetMemory.mergeCanonicalEndpointRecord({
        targetURL,
        origin: "https://api.example.test",
        path: "/api/users/{anotherId}",
        operations: [{
          method: "GET",
          methodEvidenceSources: ["traffic"],
          requestIDs: ["req-get-2"],
          observedInTraffic: true,
          confidence: "observed",
        }],
      })

      expect(first.created).toBe(true)
      expect(second.created).toBe(false)
      expect(second.note.id).toBe(first.note.id)
      expect(repeatedTraffic.note.id).toBe(first.note.id)
      expect(repeatedTraffic.updated).toBe(false)

      const endpointNotes = TargetMemory.allNotes(first.workspace.id).filter((note) => note.kind === "endpoint")
      expect(endpointNotes).toHaveLength(1)
      const note = endpointNotes[0]!
      const structured = note.content.match(
        /<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_BEGIN -->\n([\s\S]*?)\n<!-- CYBERSTRIKE_CANONICAL_ENDPOINT_V1_END -->/,
      )
      expect(structured).not.toBeNull()
      const record = JSON.parse(structured![1]!)
      expect(record.path).toBe("/api/users/{id}")
      expect(record.operations.map((operation: { method: string }) => operation.method)).toEqual(["GET", "POST"])

      const get = record.operations.find((operation: { method: string }) => operation.method === "GET")
      const post = record.operations.find((operation: { method: string }) => operation.method === "POST")
      expect(get.queryParameters).toEqual(["include"])
      expect(get.bodyParameters).toEqual([])
      expect(get.requestIDs).toEqual(["req-get-1"])
      expect(get.methodEvidenceSources).toContain("traffic")
      expect(get.methodEvidenceSources).not.toContain("javascript")
      expect(get.evidence).toHaveLength(1)
      expect(get.evidence[0]?.source).toBe("traffic")
      expect(get.evidence[0]?.queryParameters).toEqual(["include"])

      expect(post.bodyParameters).toEqual(["userId", "email"])
      expect(post.queryParameters).toEqual([])
      expect(post.headerNames).toEqual(["content-type", "authorization"])
      expect(post.contentTypes).toEqual(["application/json"])
      expect(post.evidence[0]?.contentTypes).toEqual(["application/json"])
      expect(post.authSignals).toEqual(["bearer-token"])
      expect(post.methodEvidenceSources).toContain("javascript")
      expect(post.evidence).toHaveLength(1)
      expect(post.evidence[0]?.source).toBe("javascript")
      expect(post.evidence[0]?.bodyParameters).toEqual(["userId", "email"])

      expect(record.unattributed.queryParameters).toEqual(["route-level-clue"])
      expect(record.unattributed.queryParameters).not.toContain("include")
    },
  })
})

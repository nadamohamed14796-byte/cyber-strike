import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
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
        expect(await fs.stat(path.join(target.workspacePath, "javascript"))).toBeTruthy()
        expect(await fs.stat(path.join(target.workspacePath, "scope"))).toBeTruthy()
        expect(await fs.stat(path.join(target.workspacePath, "recon"))).toBeTruthy()
        expect(await fs.stat(path.join(target.workspacePath, "runs"))).toBeTruthy()
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


test("persists an explicit target scope with authorization provenance and exclusions", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const configured = await TargetMemory.configureScope("https://example.com", {
        include: ["*.Example.com", "example.com"],
        exclude: ["admin.example.com"],
        authorizationSource: "Example disclosure program",
        authorizationReference: "https://hackerone.com/example?secret=must-not-persist",
      })
      expect(configured.scope.status).toBe("configured")
      expect(configured.scope.scopeItems).toEqual(["*.example.com", "example.com"])
      expect(configured.scope.excludedItems).toEqual(["admin.example.com"])
      expect(configured.scope.authorizationReference).toBe("https://hackerone.com/example")
      const saved = await TargetMemory.getScope("https://example.com")
      expect(saved?.scopeItems).toEqual(["*.example.com", "example.com"])
      expect(saved?.authorizationSource).toBe("Example disclosure program")
      // An unrelated workspace on the same protocol/port must not make a wildcard target ambiguous.
      await TargetMemory.ensure("https://unrelated.example.test")
      const allowed = await TargetMemory.checkURLScope("https://api.example.com/v1/users")
      expect(allowed.allowed).toBe(true)
      expect(allowed.workspace?.id).toBe(configured.workspace.id)
      const excluded = await TargetMemory.checkURLScope("https://admin.example.com/v1/users")
      expect(excluded.allowed).toBe(false)
      expect(excluded.reason).toContain("exclusion")
      const wrongPort = await TargetMemory.checkURLScope("https://api.example.com:8443/v1/users")
      expect(wrongPort.allowed).toBe(false)
      const wrongScheme = await TargetMemory.checkURLScope("http://api.example.com/v1/users")
      expect(wrongScheme.allowed).toBe(false)
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

      expect(saved.note.content).toContain(content)
      expect(saved.note.content).toContain(evidence)
      expect(saved.note.tags).toHaveLength(35)
      expect(saved.note.tags[34]).toBe(tags[34])
      expect(TargetMemory.notes(saved.workspace.id)).toHaveLength(1)

      const notesFile = await fs.readFile(path.join(saved.workspace.workspacePath, "notes.md"), "utf-8")
      expect(notesFile).toContain(content)
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
      expect(context).toContain("PARTIAL NOTE SELECTION")
      expect(context).toContain("1 current notes, 1 journal entries")
      expect(context).toContain("Use target_notes_read")
      expect(context).not.toContain("First archived experiment.")
      expect(context).not.toContain("Second archived experiment.")
      await Session.remove(session.id)
      await Instance.dispose()
    },
  })
})

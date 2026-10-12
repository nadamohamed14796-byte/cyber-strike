import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"
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
        expect(await fs.readFile(path.join(target.workspacePath, "target.json"), "utf-8")).toContain("example.com")

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


test("redacts secret-bearing fields at the target-note persistence boundary", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const workspace = await TargetMemory.ensure("https://example.com")
      const secret = "multi word password phrase that must not persist"
      const result = await TargetMemory.addNote("https://example.com", {
        kind: "manual",
        title: "Login observation",
        content: '{"password":"' + secret + '","client_secret":"another private phrase"}',
        source: "test",
      })

      expect(result.note.content).not.toContain(secret)
      expect(result.note.content).not.toContain("another private phrase")
      const disk = await fs.readFile(path.join(workspace.workspacePath, "notes.md"), "utf-8")
      expect(disk).not.toContain(secret)
      expect(disk).not.toContain("another private phrase")
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

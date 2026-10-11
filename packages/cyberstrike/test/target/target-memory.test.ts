import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { TargetMemory } from "../../src/target"

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

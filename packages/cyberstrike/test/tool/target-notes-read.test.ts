import { expect, test } from "bun:test"
import path from "node:path"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Request } from "../../src/session/request"
import { TargetMemory } from "../../src/target"
import { TargetNotesReadTool } from "../../src/tool/target-notes-read"
import type { Tool } from "../../src/tool/tool"

function context(sessionID: string): Tool.Context {
  return {
    sessionID,
    messageID: "",
    callID: "",
    agent: "cyberstrike",
    abort: AbortSignal.any([]),
    messages: [],
    metadata: () => {},
    ask: async () => {},
  } as Tool.Context
}

test("target_notes_read pages through current note bodies and archived revisions", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const targetURL = "https://notes-reader.example.test"
      const identityKey = "endpoint:/api/profile:reader-test"
      const oldBody = "Earlier investigation: owner and non-owner responses were not compared. ".repeat(55)
      const currentBody = "Current investigation: tested role=admin and role=member, no cross-account impact observed. ".repeat(55)
      const first = await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Profile authorization",
        content: oldBody,
        source: "agent:notes-reader-test",
        identityKey,
        upsertByIdentity: true,
        status: "observed",
      })
      const current = await TargetMemory.addNote(targetURL, {
        kind: "manual",
        title: "Profile authorization",
        content: currentBody,
        source: "agent:notes-reader-test",
        identityKey,
        upsertByIdentity: true,
        status: "observed",
      })
      const revision = TargetMemory.noteRevisions(current.workspace.id, current.note.id)[0]
      expect(revision).toBeDefined()

      const session = await Session.create({ title: "target-notes-read-test" })
      const request = Request.add({
        sessionID: session.id,
        method: "GET",
        normalizedPath: "/api/profile",
        origin: targetURL,
        keyHash: "target-notes-read-test-key",
      })
      expect(request).toBeDefined()
      const tool = await TargetNotesReadTool.init()
      const ctx = context(session.id)

      const firstPage = await tool.execute({
        target_url: targetURL,
        note_id: current.note.id,
        content_length: 120,
      }, ctx)
      expect(firstPage.output).toContain("NOTE " + current.note.id)
      expect(firstPage.output).toContain("has_more_content: true")
      expect(firstPage.output).toContain("next_content_offset: 120")
      expect(firstPage.output).toContain(currentBody.slice(0, 80))

      const secondPage = await tool.execute({
        target_url: targetURL,
        note_id: current.note.id,
        content_offset: 120,
        content_length: 120,
      }, ctx)
      expect(secondPage.output).toContain(current.note.content.slice(120, 200))
      expect(secondPage.output).toContain("next_content_offset: 240")

      const historyFirstPage = await tool.execute({
        target_url: targetURL,
        note_id: current.note.id,
        include_history: true,
        revision_id: revision!.id,
        content_length: 120,
      }, ctx)
      expect(historyFirstPage.output).toContain("REVISION " + revision!.id)
      expect(historyFirstPage.output).toContain("has_more_content: true")
      expect(historyFirstPage.output).toContain(oldBody.slice(0, 80))

      const historyNextPage = await tool.execute({
        target_url: targetURL,
        note_id: current.note.id,
        include_history: true,
        revision_id: revision!.id,
        content_offset: 120,
        content_length: 120,
      }, ctx)
      expect(historyNextPage.output).toContain(revision!.content.slice(120, 200))

      const nextNote = await TargetMemory.addNote("https://unrelated-notes.example.test", {
        kind: "manual",
        title: "Unrelated target note",
        content: "This note must never cross target boundaries.",
        source: "agent:notes-reader-test",
      })
      expect(nextNote.note.id).toBeTruthy()
      const denied = await tool.execute({
        target_url: nextNote.workspace.targetURL,
        page_size: 1,
      }, ctx)
      expect(denied.metadata.found).toBe(false)
      expect(denied.metadata.reason).toBe("target_not_observed_or_ancestor")

      await Session.remove(session.id)
      await Instance.dispose()
    },
  })
})

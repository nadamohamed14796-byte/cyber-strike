import z from "zod"
import { Session } from "../session"
import { TargetMemory } from "../target"
import { Tool } from "./tool"

const TargetNotesReadParameters = z.object({
  target_url: z.string().min(1).describe("Exact existing target workspace URL, including path when the workspace is path-scoped"),
  query: z.string().optional().describe("Case-insensitive search across title, content, tags, source, and source URL"),
  note_id: z.string().optional().describe("Read one specific note by its stable note ID"),
  kind: z.enum(["manual", "asset", "endpoint", "javascript", "finding", "evidence", "research", "lesson"]).optional(),
  status: z.enum(["unverified", "observed", "confirmed", "disproven"]).optional(),
  offset: z.number().int().min(0).default(0).describe("Pagination offset among matching notes; use next_offset from the previous result"),
  page_size: z.number().int().min(1).default(20).describe("Number of notes to return in this page. There is no application-defined upper cap; request manageable pages."),
  content_offset: z.number().int().min(0).default(0).describe("Character offset for reading a long note in chunks"),
  content_length: z.number().int().min(1).optional().describe("Characters of each note's content to return from content_offset; omit to return the full note"),
})

export const TargetNotesReadTool = Tool.define<typeof TargetNotesReadParameters, Tool.Metadata>("target_notes_read", {
  description: [
    "Read previously saved target-specific notes from the selected asset's SQLite memory. This is read-only and never sends requests to the target.",
    "Use this tool whenever target context says the notes or asset inventory are partial, before updating a current note, or when a detail is missing. Do not assume that a note omitted from the prompt does not exist.",
    "Search and page through matching notes using query, offset, and page_size. Use next_offset until has_more_notes is false. To read a very long note, supply note_id, content_offset, and content_length and continue from next_content_offset until has_more_content is false. The full saved note remains authoritative; prompt excerpts are only previews.",
    "Target data is isolated: the workspace must already exist and the target must have been observed in this session tree. Do not use this tool to infer authorization or to test the target.",
  ].join("\n"),
  parameters: TargetNotesReadParameters,
  async execute(params, ctx) {
    try {
      const sessionID = Session.root(ctx.sessionID)
      const workspace = await TargetMemory.get(params.target_url)
      if (!workspace) {
        return { title: "Target notes unavailable", output: "No existing workspace matches this target. No data was read.", metadata: { found: false, reason: "workspace_missing" } }
      }
      if (!TargetMemory.isObservedInSession(sessionID, workspace.targetURL)) {
        return { title: "Target notes unavailable", output: "The target was not observed in this session tree. No notes were returned to prevent cross-target contamination.", metadata: { found: false, reason: "target_not_observed" } }
      }
      let notes = TargetMemory.allNotes(workspace.id)
      if (params.note_id) notes = notes.filter((note) => note.id === params.note_id)
      if (params.kind) notes = notes.filter((note) => note.kind === params.kind)
      if (params.status) notes = notes.filter((note) => note.status === params.status)
      if (params.query?.trim()) {
        const query = params.query.trim().toLocaleLowerCase()
        notes = notes.filter((note) =>
          [note.title ?? "", note.content, note.source, note.sourceURL ?? "", ...note.tags]
            .join("\n")
            .toLocaleLowerCase()
            .includes(query),
        )
      }
      const totalMatches = notes.length
      const offset = Math.min(params.offset, totalMatches)
      const page = notes.slice(offset, offset + params.page_size)
      const chunks = page.map((note) => {
        const start = Math.min(params.content_offset, note.content.length)
        const end = params.content_length === undefined
          ? note.content.length
          : Math.min(note.content.length, start + params.content_length)
        return [
          "NOTE " + note.id,
          "Title: " + (note.title ?? "(untitled)"),
          "Kind/status: " + note.kind + "/" + note.status,
          "Created: " + new Date(note.timeCreated).toISOString(),
          "Updated: " + new Date(note.timeUpdated).toISOString(),
          "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
          "Tags: " + (note.tags.join(", ") || "(none)"),
          "Content characters: " + note.content.length + "; returned range: [" + start + ", " + end + ")",
          "Has more content: " + (end < note.content.length),
          ...(end < note.content.length ? ["Next content offset: " + end] : []),
          "",
          note.content.slice(start, end),
        ].join("\n")
      })
      const nextOffset = offset + page.length
      const hasMoreNotes = nextOffset < totalMatches
      return {
        title: "Target notes read",
        output: [
          "Target: " + workspace.targetURL,
          "Workspace: " + workspace.workspacePath,
          "Matched notes: " + totalMatches,
          "Returned notes: " + page.length + " (offset " + offset + ")",
          "Has more notes: " + hasMoreNotes,
          ...(hasMoreNotes ? ["Next offset: " + nextOffset] : []),
          "",
          ...(chunks.length ? chunks : ["No notes match these filters."]),
        ].join("\n"),
        metadata: {
          found: true,
          target_id: workspace.id,
          total_matches: totalMatches,
          returned: page.length,
          offset,
          next_offset: hasMoreNotes ? nextOffset : null,
          has_more_notes: hasMoreNotes,
        },
      }
    } catch (error) {
      return { title: "Target notes read failed", output: error instanceof Error ? error.message : String(error), metadata: { found: false, error: true } }
    }
  },
})

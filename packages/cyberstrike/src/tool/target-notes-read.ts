import z from "zod"
import { Session } from "../session"
import { TargetMemory } from "../target"
import { Tool } from "./tool"

const TargetNotesReadParameters = z.object({
  target_url: z.string().min(1).describe("Exact existing target workspace URL, including path when the workspace is path-scoped"),
  query: z.string().optional().describe("Case-insensitive search across title, content, tags, source, and source URL"),
  note_id: z.string().optional().describe("Read one specific current note by its stable note ID"),
  revision_id: z.string().optional().describe("Read one exact archived revision ID; use with include_history=true to continue a long historical version"),
  kind: z.enum(["manual", "asset", "endpoint", "javascript", "finding", "evidence", "research", "lesson"]).optional(),
  status: z.enum(["unverified", "observed", "confirmed", "disproven"]).optional(),
  offset: z.number().int().min(0).default(0).describe("Pagination offset among matching notes; use next_offset from the previous result"),
  page_size: z.number().int().min(1).default(3).describe("Number of notes to return in this page. There is no application-defined upper cap; use additional pages rather than asking one response to contain the entire memory."),
  content_offset: z.number().int().min(0).default(0).describe("Character offset for reading a long note in chunks"),
  content_length: z.number().int().min(1).default(3000).describe("Characters of each note body to return from content_offset. This is a resumable page size, not a total note limit; continue at next_content_offset until the saved body is complete."),
  include_history: z.boolean().default(false).describe("Include archived previous versions of current notes"),
  revision_offset: z.number().int().min(0).default(0).describe("Pagination offset for archived note versions"),
  revision_page_size: z.number().int().min(1).default(2).describe("Number of archived versions to return when include_history is enabled"),
})

export const TargetNotesReadTool = Tool.define<typeof TargetNotesReadParameters, Tool.Metadata>("target_notes_read", {
  description: [
    "Read previously saved target-specific notes from the selected asset's SQLite memory. This is read-only and never sends requests to the target.",
    "Use this tool whenever target context says the notes or asset inventory are partial, before updating a current note, or when a detail is missing. Do not assume that a note omitted from the prompt does not exist.",
    "Search and page through matching current notes using query, offset, and page_size. Use next_offset until has_more_notes is false. Each returned note body is a chunk starting at content_offset (default 0) and sized by content_length (default 3000 characters); continue using that note's next_content_offset until has_more_content is false. Use note_id when continuing one specific long note, because content_offset applies to all notes in a page. This paginates delivery only; the full saved body is not truncated or overwritten.",
    "When reviewing or replacing a current note, set include_history=true and pass note_id to inspect archived versions too. Use revision_offset and revision_page_size; next_revision_offset is returned when more versions remain. Pass revision_id to continue one historical version by content_offset. Historical versions use the same resumable content chunking and are stored separately from the active note list.",
    "Target data is isolated by workspace/session checks, but note contents are returned into the agent/model context and may be sent to the configured model provider. Exact secret-like values in notes are not private from that provider. If an exact value must remain outside model context, store the evidence as a target_artifact copied with source_path and read only its path/hash metadata; do not call this tool to retrieve that raw artifact content.",
    "The workspace must already exist and the target must have been observed in this session tree. Do not use this tool to infer authorization or to test the target.",
  ].join("\n"),
  parameters: TargetNotesReadParameters,
  async execute(params: z.input<typeof TargetNotesReadParameters>, ctx) {
    const options = {
      offset: params.offset ?? 0,
      page_size: params.page_size ?? 3,
      content_offset: params.content_offset ?? 0,
      content_length: params.content_length ?? 3000,
      include_history: params.include_history ?? false,
      revision_offset: params.revision_offset ?? 0,
      revision_page_size: params.revision_page_size ?? 2,
    }
    try {
      const sessionID = Session.root(ctx.sessionID)
      const workspace = await TargetMemory.get(params.target_url)
      if (!workspace) {
        return { title: "Target notes unavailable", output: "No existing workspace matches this target. No data was read.", metadata: { found: false, reason: "workspace_missing" } }
      }
      if (!TargetMemory.isObservedOrAncestorInSession(sessionID, workspace.targetURL)) {
        return { title: "Target notes unavailable", output: "This workspace is neither observed in the session tree nor a registered ancestor of an observed workspace. No notes were returned to prevent cross-target contamination.", metadata: { found: false, reason: "target_not_observed_or_ancestor" } }
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
      const revisions = options.include_history
        ? TargetMemory.noteRevisions(workspace.id, params.note_id)
            .filter((revision) => !params.revision_id || revision.id === params.revision_id)
            .filter((revision) => !params.kind || revision.kind === params.kind)
            .filter((revision) => !params.status || revision.status === params.status)
            .filter((revision) => {
              if (!params.query?.trim()) return true
              const query = params.query.trim().toLocaleLowerCase()
              return [revision.title ?? "", revision.content, revision.source, revision.sourceURL ?? "", ...revision.tags]
                .join("\n")
                .toLocaleLowerCase()
                .includes(query)
            })
        : []
      const totalRevisions = revisions.length
      const revisionOffset = Math.min(options.revision_offset, totalRevisions)
      const revisionPage = revisions.slice(revisionOffset, revisionOffset + options.revision_page_size)
      const hasMoreRevisions = revisionOffset + revisionPage.length < totalRevisions
      const revisionChunks = revisionPage.map((revision) => {
        const start = Math.min(options.content_offset, revision.content.length)
        const end = options.content_length === undefined
          ? revision.content.length
          : Math.min(revision.content.length, start + options.content_length)
        return [
          "REVISION " + revision.id,
          "Current note ID: " + revision.noteID,
          "Title: " + (revision.title ?? "(untitled)"),
          "Kind/status: " + revision.kind + "/" + revision.status,
          "Archived at: " + new Date(revision.timeCreated).toISOString(),
          "Source: " + revision.source + (revision.sourceURL ? " — " + revision.sourceURL : ""),
          "Tags: " + (revision.tags.join(", ") || "(none)"),
          "Content characters: " + revision.content.length + "; returned range: [" + start + ", " + end + ")",
          "has_more_content: " + (end < revision.content.length),
          ...(end < revision.content.length ? ["next_content_offset: " + end] : []),
          "",
          revision.content.slice(start, end),
        ].join("\n")
      })
      const totalMatches = notes.length
      const offset = Math.min(options.offset, totalMatches)
      const page = notes.slice(offset, offset + options.page_size)
      const chunks = page.map((note) => {
        const start = Math.min(options.content_offset, note.content.length)
        const end = options.content_length === undefined
          ? note.content.length
          : Math.min(note.content.length, start + options.content_length)
        return [
          "NOTE " + note.id,
          "Title: " + (note.title ?? "(untitled)"),
          "Kind/status: " + note.kind + "/" + note.status,
          "Created: " + new Date(note.timeCreated).toISOString(),
          "Updated: " + new Date(note.timeUpdated).toISOString(),
          "Source: " + note.source + (note.sourceURL ? " — " + note.sourceURL : ""),
          "Tags: " + (note.tags.join(", ") || "(none)"),
          "Content characters: " + note.content.length + "; returned range: [" + start + ", " + end + ")",
          "has_more_content: " + (end < note.content.length),
          ...(end < note.content.length ? ["next_content_offset: " + end] : []),
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
          "has_more_notes: " + hasMoreNotes,
          ...(hasMoreNotes ? ["next_offset: " + nextOffset] : []),
          ...(options.include_history ? [
            "",
            "Archived note versions matched: " + totalRevisions,
            "Returned revisions: " + revisionPage.length + " (offset " + revisionOffset + ")",
            "has_more_revisions: " + hasMoreRevisions,
            ...(hasMoreRevisions ? ["next_revision_offset: " + (revisionOffset + revisionPage.length)] : []),
          ] : []),
          "",
          ...(chunks.length ? chunks : ["No current notes match these filters."]),
          ...(options.include_history ? ["", "## Archived revisions", ...(revisionChunks.length ? revisionChunks : ["No archived versions match these filters."])] : []),
        ].join("\n"),
        metadata: {
          found: true,
          target_id: workspace.id,
          total_matches: totalMatches,
          returned: page.length,
          offset,
          next_offset: hasMoreNotes ? nextOffset : null,
          has_more_notes: hasMoreNotes,
          total_revisions: options.include_history ? totalRevisions : undefined,
          returned_revisions: options.include_history ? revisionPage.length : undefined,
          revision_offset: options.include_history ? revisionOffset : undefined,
          next_revision_offset: options.include_history && hasMoreRevisions ? revisionOffset + revisionPage.length : null,
          has_more_revisions: options.include_history ? hasMoreRevisions : false,
        },
      }
    } catch (error) {
      return { title: "Target notes read failed", output: error instanceof Error ? error.message : String(error), metadata: { found: false, error: true } }
    }
  },
})

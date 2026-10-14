import z from "zod"
import { Session } from "../session"
import { TargetMemory, type TargetNoteKind, type TargetNoteStatus } from "../target"
import { Tool } from "./tool"

const TargetNoteParameters = z.object({
    target_url: z.string().min(1).describe("Exact existing target workspace URL, including a path when the workspace is path-scoped"),
    kind: z.enum(["manual", "asset", "endpoint", "javascript", "finding", "evidence", "research", "lesson"]).default("manual"),
    title: z.string().min(1).max(180),
    content: z.string().min(1).max(10000),
    status: z.enum(["unverified", "observed", "confirmed", "disproven"]).default("observed"),
    evidence: z.string().max(5000).optional().describe("Concrete evidence required when status is confirmed or disproven"),
    source_url: z.string().url().optional(),
    tags: z.array(z.string().min(1).max(48)).max(20).optional(),
  })

export const TargetNoteTool = Tool.define<typeof TargetNoteParameters, Tool.Metadata>("target_note", {
  description: [
    "Save a durable target-specific observation in the existing target workspace, SQLite, and notes.md so later agents can reuse it.",
    "This tool only writes notes; it does not test the target. The target workspace must already exist and the target host/path must be present in the current session tree's observed requests or Intel. It will not create a workspace for an unobserved target.",
    "Use concise, factual notes with provenance. Preserve exact discovered values in this private target workspace when they are evidence. Use observed/unverified unless evidence supports a stronger state. A candidate secret is not confirmed until validated." ,
    "Keep public report/writeup methodology in the global research database, not target notes. Use this for current-target assets, endpoints, test conditions, results, limitations, and finding-validation summaries.",
  ].join("\n"),
  parameters: TargetNoteParameters,
  async execute(params, ctx) {
    try {
      const sessionID = Session.root(ctx.sessionID)
      const workspace = await TargetMemory.get(params.target_url)
      if (!workspace) {
        return { title: "Target note not saved", output: "No existing workspace matches this target. Create/open the target workspace explicitly first.", metadata: { saved: false, reason: "workspace_missing" } }
      }
      if (!TargetMemory.isObservedInSession(sessionID, workspace.targetURL)) {
        return { title: "Target note not saved", output: "The target host/path was not found in observed requests or Intel for this session tree. No note was written to avoid cross-target contamination.", metadata: { saved: false, reason: "target_not_observed" } }
      }
      if ((params.status === "confirmed" || params.status === "disproven") && !params.evidence?.trim()) {
        return { title: "Target note not saved", output: "Confirmed/disproven notes require concrete evidence. Use observed or unverified if evidence is incomplete.", metadata: { saved: false, reason: "evidence_required" } }
      }
      const saved = await TargetMemory.addNote(workspace.targetURL, {
        kind: params.kind as TargetNoteKind,
        title: params.title.trim().replaceAll("\\r", " ").replaceAll("\\n", " ").replaceAll("\\t", " ").slice(0, 180),
        content: params.content.trim(),
        evidence: params.evidence?.trim(),
        source: "agent:" + (ctx.agent || "cyberstrike").replaceAll("\\r", " ").replaceAll("\\n", " ").replaceAll("\\t", " ").slice(0, 100),
        sourceURL: params.source_url,
        status: params.status as TargetNoteStatus,
        tags: params.tags?.map((tag) => tag.replaceAll("\\r", " ").replaceAll("\\n", " ").replaceAll("\\t", " ").slice(0, 48)),
      })
      return {
        title: saved.created ? "Target note saved" : saved.updated ? "Target note updated" : "Target note already exists",
        output: [
          "Target: " + saved.workspace.targetURL,
          "Note ID: " + saved.note.id,
          "Status: " + saved.note.status,
          "Workspace: " + saved.workspace.workspacePath,
          "Notes file: " + saved.workspace.workspacePath + "/notes.md",
          "The note is target-specific; global report/writeup knowledge remains in report_knowledge.",
        ].join("\n"),
        metadata: { saved: saved.created || saved.updated, note_id: saved.note.id, target_id: saved.workspace.id, workspace: saved.workspace.workspacePath },
      }
    } catch (error) {
      return { title: "Target note failed", output: error instanceof Error ? error.message : String(error), metadata: { saved: false, error: true } }
    }
  },
})

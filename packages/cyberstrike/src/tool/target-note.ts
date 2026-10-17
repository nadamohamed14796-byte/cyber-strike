import z from "zod"
import { Session } from "../session"
import { TargetMemory, type TargetNoteKind, type TargetNoteStatus } from "../target"
import { Tool } from "./tool"

const TargetNoteParameters = z.object({
    target_url: z.string().min(1).describe("Exact existing target workspace URL, including a path when the workspace is path-scoped"),
    kind: z.enum(["manual", "asset", "endpoint", "javascript", "finding", "evidence", "research", "lesson"]).default("manual"),
    record_mode: z.enum(["current", "journal"]).default("current").describe("current updates the living summary of one investigation; journal appends a meaningful dated experiment/result without replacing earlier history. Use journal only for consequential steps, not every request."),
    title: z.string().min(1).max(180),
    content: z.string().min(1).max(10000),
    status: z.enum(["unverified", "observed", "confirmed", "disproven"]).optional().describe("Optional note status. Omit when updating an existing investigation to preserve its current status; new notes default to observed."),
    evidence: z.string().max(5000).optional().describe("Concrete evidence required when status is confirmed or disproven"),
    source_url: z.string().url().optional(),
    tags: z.array(z.string().min(1).max(48)).max(20).optional(),
    upsert_by_identity: z.boolean().default(true).describe("Update an existing note with the same kind/title/source instead of creating another copy; normally keep enabled."),
    identity_key: z.string().regex(/^[a-zA-Z0-9:._/-]{1,160}$/).optional().describe("Stable identity for a continuing investigation, such as endpoint:/api/me:authorization or finding:123. Reuse it when updating the same line of reasoning."),
  })

export const TargetNoteTool = Tool.define<typeof TargetNoteParameters, Tool.Metadata>("target_note", {
  description: [
    "Save a durable target-specific observation in the existing target workspace, SQLite, and notes.md so later agents can reuse it.",
    "This tool only writes notes; it does not test the target. The target workspace must already exist and the target host/path must be present in the current session tree's observed requests or Intel. It will not create a workspace for an unobserved target.",
    "There are two complementary ways to record one investigation. Use record_mode=current for the evolving, readable picture of what is known now; reuse identity_key and upsert it as evidence changes. Use record_mode=journal for a consequential experiment or change in understanding that must remain in chronological history; journal entries are append-only and must not replace the current summary. A journal entry should explain the experiment and its actual result in context, including a meaningful negative result or changed hypothesis when relevant. Do not journal every request, tool call, repeated payload, or trivial variation. When both a changed conclusion and its historical reason matter, update the current note and add one concise journal entry describing what changed and why. Never fabricate timestamps or observations; the system records creation time.",
    "Write like a thoughtful security researcher keeping field notes for both their future self and another tester. The model—not a fixed template—decides what deserves recording, the order, tone, and length. Use natural prose, short paragraphs, bullets, or a tiny note only when they genuinely fit; do not force headings or repeat the same checklist in every note. A note may be a few lines or a detailed explanation depending on the evidence and complexity. Prefer a durable insight over a transcript: preserve what was actually observed, which request/artifact or condition supports it, why it matters, how confident the interpretation is, what alternative explanation remains, what was tried and failed, and the next test that would distinguish competing hypotheses—but include only the parts relevant to this case. Write negative results and setup limitations when they prevent repeated wasted work. Make the note useful for manual hunting: a human should understand the reasoning and be able to continue from it without reconstructing the whole session. Do not invent evidence, certainty, causal links, or relationships between endpoints. Mark inferred relationships as hypotheses. If new evidence changes an earlier interpretation, explicitly reconcile the old conclusion instead of leaving contradictory notes. Do not save trivial transient details or create a separate note for every request, subdomain, or JavaScript file; consolidate related observations when they form one useful line of reasoning." ,
    "Never label a bug confirmed because a scanner flagged it, a header is missing, an endpoint exists, or a response looks unusual. A missing header is usually informational/low until a concrete exploit path and meaningful impact are demonstrated. Use confirmed only with reproducible evidence of unexpected behavior and security impact; use observed/unverified for candidates." ,
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
      const journalEntry = params.record_mode === "journal"
      const saved = await TargetMemory.addNote(workspace.targetURL, {
        kind: params.kind as TargetNoteKind,
        title: params.title.trim().replaceAll("\r", " ").replaceAll("\n", " ").replaceAll("\t", " ").slice(0, 180),
        content: params.content.trim(),
        evidence: params.evidence?.trim(),
        source: "agent:" + (ctx.agent || "cyberstrike").replaceAll("\r", " ").replaceAll("\n", " ").replaceAll("\t", " ").slice(0, 100),
        sourceURL: params.source_url,
        status: params.status as TargetNoteStatus,
        tags: params.tags?.map((tag) => tag.replaceAll("\r", " ").replaceAll("\n", " ").replaceAll("\t", " ").slice(0, 48)),
        upsertByIdentity: journalEntry ? false : params.upsert_by_identity,
        identityKey: journalEntry ? undefined : params.identity_key,
      })
      return {
        title: journalEntry
          ? (saved.created ? "Target journal entry saved" : "Target journal entry already exists")
          : saved.created ? "Target note saved" : saved.updated ? "Target note updated" : "Target note already exists",
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

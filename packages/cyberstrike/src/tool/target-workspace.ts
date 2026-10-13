import z from "zod"
import { TargetMemory, type TargetAssetType } from "../target"
import { Tool } from "./tool"

const Parameters = z.object({
  action: z.enum(["init", "configure_scope", "attach_asset", "show", "list", "record_summary"]),
  target_url: z.string().optional(),
  include: z.array(z.string().min(1)).optional(),
  exclude: z.array(z.string().min(1)).optional(),
  authorization_source: z.string().optional(),
  authorization_reference: z.string().optional(),
  parent_target_url: z.string().optional(),
  asset_url: z.string().optional(),
  asset_type: z.enum(["subdomain", "application", "api", "host"]).optional(),
  summary_title: z.string().max(180).optional(),
  summary_content: z.string().max(100_000).optional(),
  summary_kind: z.enum(["manual", "research", "lesson"]).optional(),
  summary_status: z.enum(["unverified", "observed", "confirmed", "disproven"]).optional(),
  summary_source: z.string().max(120).optional(),
  summary_source_url: z.string().optional(),
  summary_evidence: z.string().max(100_000).optional(),
  summary_tags: z.array(z.string()).max(30).optional(),
})

type TargetWorkspaceMetadata = {
  initialized?: boolean
  found?: boolean
  attached?: boolean
  saved?: boolean
  target_id?: string
  target_url?: string
  workspace?: string
  notes_file?: string
  scope_file?: string
  scope_configured?: boolean
  parent_target_id?: string | null
  asset_type?: TargetAssetType
  include_count?: number
  exclude_count?: number
  associated_asset_count?: number
  note_count?: number
  child_count?: number
  count?: number
  targets?: Array<{ id: string; url: string; path: string; parent_id: string | null; asset_type: TargetAssetType }>
  note_id?: string
  note_created?: boolean
  note_updated?: boolean
}

function required(value: string | undefined, name: string): string {
  if (!value?.trim()) throw new Error(name + " is required for this action.")
  return value.trim()
}

export const TargetWorkspaceTool = Tool.define("target_workspace", {
  description: [
    "Manage the canonical target workspace before target-specific reconnaissance or testing.",
    "Always initialize the parent/program root with action=init before processing scope files, running recon, or saving artifacts. This creates a project-scoped .cyberstrike/targets/<slug> tree, notes.md, target.json, workspace.json, scope/scope.json and the standard artifact directories.",
    "Workspace creation is NOT authorization. Init leaves scope unconfigured. Only configure scope after reviewing the official program/customer policy and passing its HTTPS reference, include rules and exclusions.",
    "Attach only a child host permitted by the saved parent scope. Child workspaces are nested beneath the parent assets directory. For huge scopes, store the original candidate list in the root workspace and create child workspaces as assets are validated/processed; do not create hundreds of thousands of empty directories.",
    "Use show/list to retrieve canonical absolute paths. Use target_artifact for files and target_note for technical observations tied to session evidence. Use action=record_summary for explicit run/scope/checkpoint summaries after verified tool outcomes; it requires an existing workspace and keeps notes.md synchronized without pretending that unobserved technical behavior was tested. Never invent an alternate output directory.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params) {
    if (params.action === "init") {
      const workspace = await TargetMemory.ensure(required(params.target_url, "target_url"))
      const scope = await TargetMemory.getScope(workspace.targetURL)
      return {
        title: "Target workspace initialized",
        output: [
          "Target: " + workspace.targetURL,
          "Workspace: " + workspace.workspacePath,
          "Parent: " + (workspace.parentTargetID ?? "(root target)"),
          "Asset type: " + workspace.assetType,
          "Scope status: " + (scope?.status ?? "missing"),
          "Notes file: " + workspace.workspacePath + "/notes.md",
          "Scope file: " + workspace.workspacePath + "/scope/scope.json",
          "Authorization: " + (scope?.status === "configured" ? "configured; still check each candidate" : "UNCONFIGURED — do not perform active testing"),
          "Workspace creation does not grant permission to test.",
        ].join("\n"),
        metadata: {
          initialized: true,
          target_id: workspace.id,
          target_url: workspace.targetURL,
          workspace: workspace.workspacePath,
          notes_file: workspace.workspacePath + "/notes.md",
          scope_file: workspace.workspacePath + "/scope/scope.json",
          scope_configured: scope?.status === "configured",
          parent_target_id: workspace.parentTargetID,
        } as TargetWorkspaceMetadata,
      }
    }

    if (params.action === "configure_scope") {
      const result = await TargetMemory.configureScope(required(params.target_url, "target_url"), {
        include: params.include ?? [],
        exclude: params.exclude ?? [],
        authorizationSource: required(params.authorization_source, "authorization_source"),
        authorizationReference: required(params.authorization_reference, "authorization_reference"),
      })
      return {
        title: "Target scope saved",
        output: [
          "Target: " + result.workspace.targetURL,
          "Workspace: " + result.workspace.workspacePath,
          "Scope file: " + result.workspace.workspacePath + "/scope/scope.json",
          "Authorization source: " + result.scope.authorizationSource,
          "Official policy reference: " + result.scope.authorizationReference,
          "Included entries: " + result.scope.scopeItems.length,
          "Excluded entries: " + result.scope.excludedItems.length,
          "Authorized child workspaces attached/reorganized: " + result.associatedAssets.length,
          "Use scope_check before active testing of each candidate.",
        ].join("\n"),
        metadata: {
          saved: true,
          target_id: result.workspace.id,
          target_url: result.workspace.targetURL,
          workspace: result.workspace.workspacePath,
          scope_file: result.workspace.workspacePath + "/scope/scope.json",
          scope_configured: result.scope.status === "configured",
          include_count: result.scope.scopeItems.length,
          exclude_count: result.scope.excludedItems.length,
          associated_asset_count: result.associatedAssets.length,
        } as TargetWorkspaceMetadata,
      }
    }

    if (params.action === "attach_asset") {
      const result = await TargetMemory.attachAsset(
        required(params.parent_target_url, "parent_target_url"),
        required(params.asset_url, "asset_url"),
        params.asset_type as TargetAssetType | undefined,
      )
      return {
        title: "Authorized child workspace attached",
        output: [
          "Parent: " + result.parent.targetURL,
          "Parent workspace: " + result.parent.workspacePath,
          "Asset: " + result.asset.targetURL,
          "Asset type: " + result.asset.assetType,
          "Child workspace: " + result.asset.workspacePath,
          "Child notes: " + result.asset.workspacePath + "/notes.md",
          "Parent asset registry and notes.md inventory synchronized.",
        ].join("\n"),
        metadata: {
          attached: true,
          parent_target_id: result.parent.id,
          parent_workspace: result.parent.workspacePath,
          target_id: result.asset.id,
          target_url: result.asset.targetURL,
          workspace: result.asset.workspacePath,
          asset_type: result.asset.assetType,
        } as TargetWorkspaceMetadata,
      }
    }

    if (params.action === "show") {
      const targetURL = required(params.target_url, "target_url")
      const workspace = await TargetMemory.get(targetURL)
      if (!workspace) {
        return {
          title: "Target workspace not found",
          output: "No workspace matches " + targetURL + ". Initialize the parent target first.",
          metadata: { found: false, target_url: targetURL } as TargetWorkspaceMetadata,
        }
      }
      const scope = await TargetMemory.getScope(workspace.targetURL)
      const notes = TargetMemory.allNotes(workspace.id)
      const children = TargetMemory.children(workspace.id)
      return {
        title: "Target workspace",
        output: [
          "Target: " + workspace.targetURL,
          "Workspace: " + workspace.workspacePath,
          "Asset type: " + workspace.assetType,
          "Parent: " + (workspace.parentTargetID ?? "(root target)"),
          "Scope status: " + (scope?.status ?? "missing"),
          "Included entries: " + (scope?.scopeItems.length ?? 0),
          "Excluded entries: " + (scope?.excludedItems.length ?? 0),
          "Saved notes: " + notes.length,
          "Child workspaces: " + children.length,
          "Notes: " + workspace.workspacePath + "/notes.md",
          "Manifest: " + workspace.workspacePath + "/workspace.json",
        ].join("\n"),
        metadata: {
          found: true,
          target_id: workspace.id,
          target_url: workspace.targetURL,
          workspace: workspace.workspacePath,
          parent_target_id: workspace.parentTargetID,
          scope_configured: scope?.status === "configured",
          include_count: scope?.scopeItems.length ?? 0,
          exclude_count: scope?.excludedItems.length ?? 0,
          note_count: notes.length,
          child_count: children.length,
        } as TargetWorkspaceMetadata,
      }
    }

    if (params.action === "record_summary") {
      const targetURL = required(params.target_url, "target_url")
      const existing = await TargetMemory.get(targetURL)
      if (!existing) {
        return {
          title: "Target summary not saved",
          output: "No existing target workspace matches " + targetURL + ". Initialize it first; no workspace or alternate directory was created.",
          metadata: { saved: false, reason: "workspace_missing", target_url: targetURL } as TargetWorkspaceMetadata,
        }
      }
      const result = await TargetMemory.addNote(existing.targetURL, {
        title: params.summary_title,
        content: required(params.summary_content, "summary_content"),
        evidence: params.summary_evidence,
        kind: params.summary_kind ?? "manual",
        status: params.summary_status ?? "observed",
        source: params.summary_source ?? "target_workspace",
        sourceURL: params.summary_source_url,
        tags: params.summary_tags,
      })
      return {
        title: result.created ? "Target summary saved" : result.updated ? "Target summary updated" : "Target summary already exists",
        output: [
          "Target: " + result.workspace.targetURL,
          "Workspace: " + result.workspace.workspacePath,
          "Notes file: " + result.workspace.workspacePath + "/notes.md",
          "Note ID: " + result.note.id,
          "Status: " + result.note.status,
          "Source: " + result.note.source,
          "Result: " + (result.created ? "created" : result.updated ? "updated" : "deduplicated"),
        ].join("\n"),
        metadata: {
          saved: true,
          target_id: result.workspace.id,
          target_url: result.workspace.targetURL,
          workspace: result.workspace.workspacePath,
          notes_file: result.workspace.workspacePath + "/notes.md",
          note_id: result.note.id,
          note_created: result.created,
          note_updated: result.updated,
          note_count: TargetMemory.allNotes(result.workspace.id).length,
        } as TargetWorkspaceMetadata,
      }
    }

    const targets = TargetMemory.list()
    return {
      title: "Target workspaces (" + targets.length + ")",
      output: targets.length
        ? targets.map((target) => [
          (target.parentTargetID ? "  ↳ " : "") + "[" + target.assetType + "] " + target.targetURL,
          "    Workspace: " + target.workspacePath,
          "    Parent ID: " + (target.parentTargetID ?? "(root)"),
        ].join("\n")).join("\n")
        : "No target workspaces exist in this project. Initialize the program/root target before recon.",
      metadata: {
        count: targets.length,
        targets: targets.map((target) => ({
          id: target.id,
          url: target.targetURL,
          path: target.workspacePath,
          parent_id: target.parentTargetID,
          asset_type: target.assetType,
        })),
      } as TargetWorkspaceMetadata,
    }
  },
})

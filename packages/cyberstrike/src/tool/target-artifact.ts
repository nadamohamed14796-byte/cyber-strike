import path from "node:path"
import z from "zod"
import { TargetMemory } from "../target"
import { redactTargetNoteSecrets } from "../target/redact"
import { Tool } from "./tool"

const AREAS = [
  "scope", "assets", "recon", "urls", "requests", "javascript", "endpoints",
  "testing", "findings", "evidence", "reports", "scans", "runs", "logs",
  "sessions", "research",
] as const

const Parameters = z.object({
  target_url: z.string().min(1).describe("Exact existing target workspace URL. Use the root target for parent inventory and the child origin for per-asset artifacts."),
  area: z.enum(AREAS).describe("Target-local artifact directory. Do not replace authoritative scope/asset/run index files."),
  filename: z.string().min(1).max(120).regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/).describe("Simple filename only, not a path. Use stable inventory names and unique run IDs for evidence."),
  content: z.string().max(2_000_000).describe("Complete UTF-8 text/JSON/CSV content, maximum 2 MB. Secret-like values are redacted before saving."),
  overwrite: z.boolean().default(false).describe("Existing artifacts are immutable by default. Set true only when replacement is intentional."),
})

export const TargetArtifactTool = Tool.define("target_artifact", {
  description: [
    "Persist a text artifact in the exact existing target workspace and return its absolute path.",
    "Use it for recon inventories, live-host results, URL and endpoint lists, JavaScript analysis, request/response references, test logs, evidence indexes, scan manifests, run state, report drafts and target-specific research notes.",
    "The workspace must already exist in the current project. This tool never silently creates another directory or guesses a target path. Call target_workspace first.",
    "Only known artifact folders and safe single-file names are accepted. Generated identity/scope/registry/index files are reserved. Content is redacted for common secrets at the persistence boundary.",
    "For binary or oversized outputs, configure the external tool to write to the exact workspace path returned by target_workspace, then verify the output file. Do not use the shell current directory or /root/targets implicitly.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params) {
    const workspace = await TargetMemory.get(params.target_url)
    if (!workspace) {
      return {
        title: "Target artifact not saved",
        output: "No existing workspace matches " + params.target_url + ". Initialize the root target or attach the authorized asset with target_workspace first. No other directory was created.",
        metadata: { saved: false, reason: "workspace_missing", target_url: params.target_url },
      }
    }

    const filename = params.filename
    const lower = filename.toLowerCase()
    const reserved = ["target.json", "workspace.json", "notes.md"].includes(lower) ||
      (params.area === "scope" && lower === "scope.json") ||
      (params.area === "assets" && lower === "registry.json") ||
      (params.area === "runs" && lower === "index.json")
    if (reserved) {
      return {
        title: "Target artifact not saved",
        output: "Refusing to replace a generated identity, authorization, asset-registry, or run-index file. Use target_workspace or a structured API instead.",
        metadata: { saved: false, reason: "reserved_file", area: params.area, filename },
      }
    }

    const filePath = path.join(workspace.workspacePath, params.area, filename)
    const exists = await Bun.file(filePath).exists()
    if (exists && !params.overwrite) {
      return {
        title: "Target artifact already exists",
        output: "Existing artifact preserved: " + filePath + ". Set overwrite=true only if replacement is intentional.",
        metadata: { saved: false, reason: "already_exists", target_id: workspace.id, path: filePath },
      }
    }
    const safeContent = redactTargetNoteSecrets(params.content)
    const content = safeContent.endsWith("\n") ? safeContent : safeContent + "\n"
    await TargetMemory.writeWorkspaceFile(workspace, params.area + "/" + filename, content)
    return {
      title: "Target artifact saved",
      output: [
        "Target: " + workspace.targetURL,
        "Workspace: " + workspace.workspacePath,
        "Artifact: " + filePath,
        "Bytes: " + Buffer.byteLength(content, "utf-8"),
        "Redaction: applied",
      ].join("\n"),
      metadata: {
        saved: true,
        target_id: workspace.id,
        target_url: workspace.targetURL,
        workspace: workspace.workspacePath,
        area: params.area,
        filename,
        path: filePath,
        bytes: Buffer.byteLength(content, "utf-8"),
      },
    }
  },
})

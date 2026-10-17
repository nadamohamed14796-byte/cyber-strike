import path from "node:path"
import fs from "node:fs/promises"
import { constants as fsConstants } from "node:fs"
import { createHash } from "node:crypto"
import z from "zod"
import { TargetMemory } from "../target"
import { Tool } from "./tool"
import { assertExternalDirectory } from "./external-directory"

const AREAS = [
  "scope", "assets", "recon", "urls", "directories", "parameters", "requests", "javascript", "endpoints",
  "testing", "findings", "evidence", "reports", "scans", "runs", "logs",
  "sessions", "research",
] as const

type TargetArtifactMetadata = {
  saved: boolean
  reason?: string
  target_url?: string
  target_id?: string
  workspace?: string
  area?: (typeof AREAS)[number]
  filename?: string
  path?: string
  bytes?: number
  source_path?: string
  source_sha256?: string
}

const Parameters = z.object({
  target_url: z.string().min(1).describe("Exact existing target workspace URL. Use the root target for parent inventory and the child origin for per-asset artifacts."),
  area: z.enum(AREAS).describe("Target-local artifact directory. Do not replace authoritative scope/asset/run index files."),
  filename: z.string().min(1).max(120).regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/).describe("Simple filename only, not a path. Use stable inventory names and unique run IDs for evidence."),
  content: z.string().max(2_000_000).optional().describe("Complete UTF-8 text/JSON/CSV content, maximum 2 MB. Exact evidence is preserved in this target-local workspace. Provide this OR source_path."),
  source_path: z.string().min(1).optional().describe("Absolute path to an existing user-provided text file on disk. Copies it into the target workspace without returning its contents to the model; files up to 32 MB. Provide this OR content."),
  overwrite: z.boolean().default(false).describe("Existing artifacts are immutable by default. Set true only when replacement is intentional."),
}).refine(
  (value) => (value.content !== undefined) !== (value.source_path !== undefined),
  { message: "Supply exactly one of content or source_path." },
)

export const TargetArtifactTool = Tool.define("target_artifact", {
  description: [
    "Persist text artifacts in the exact existing target workspace and return the absolute output path.",
    "Use for recon inventories, live-host results, URL/endpoint lists, JavaScript analysis, request/response references, test logs, evidence indexes, scan manifests, run state, report drafts and target-specific research notes.",
    "The workspace must already exist in the current project. This tool never silently creates another directory or guesses a target path. Call target_workspace first.",
    "Provide exactly one input: content (up to 2 MB) or source_path (an absolute, existing regular text file up to 32 MB). source_path copies the file into the workspace without returning its contents to the model and reports its SHA-256 hash.",
    "Only known artifact folders and safe single-file names are accepted. Generated identity/scope/registry/index files are reserved. Exact evidence is preserved in this private target workspace; do not copy raw secrets into Git commits or global research.",
    "For binary or outputs larger than 32 MB, configure the external tool to write to the exact workspace path returned by target_workspace, then verify the output file. Do not use the shell current directory or /root/targets implicitly.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params, ctx) {
    const workspace = await TargetMemory.get(params.target_url)
    if (!workspace) {
      return {
        title: "Target artifact not saved",
        output: "No existing workspace matches " + params.target_url + ". Initialize the root target or attach the authorized asset with target_workspace first. No other directory was created.",
        metadata: { saved: false, reason: "workspace_missing", target_url: params.target_url } as TargetArtifactMetadata,
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
        metadata: { saved: false, reason: "reserved_file", area: params.area, filename } as TargetArtifactMetadata,
      }
    }

    const filePath = path.join(workspace.workspacePath, params.area, filename)
    const exists = await Bun.file(filePath).exists()
    if (exists && !params.overwrite) {
      return {
        title: "Target artifact already exists",
        output: "Existing artifact preserved: " + filePath + ". Set overwrite=true only if replacement is intentional.",
        metadata: { saved: false, reason: "already_exists", target_id: workspace.id, path: filePath } as TargetArtifactMetadata,
      }
    }
    let rawContent: string
    let sourceHash: string | undefined
    if (params.source_path !== undefined) {
      if (!path.isAbsolute(params.source_path)) {
        return {
          title: "Target artifact not saved",
          output: "source_path must be an absolute path to an existing user-provided file.",
          metadata: { saved: false, reason: "source_path_not_absolute", target_url: params.target_url } as TargetArtifactMetadata,
        }
      }
      // Match the regular read tool's permission boundary. An absolute source_path
      // is not implicit consent to copy arbitrary local files into target evidence.
      await assertExternalDirectory(ctx, params.source_path)
      await ctx.ask({
        permission: "read",
        patterns: [params.source_path],
        always: ["*"],
        metadata: { purpose: "copy source file into target artifact workspace" },
      })
      try {
        // Open the file once and read through that handle. O_NOFOLLOW prevents a
        // symlink swap on supported platforms; inode/device comparison protects
        // the fallback platforms against a path replacement after open.
        const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0)
        const handle = await fs.open(params.source_path, fsConstants.O_RDONLY | noFollow)
        let bytes: Buffer
        try {
          const openedInfo = await handle.stat()
          const pathInfo = await fs.lstat(params.source_path)
          if (
            !openedInfo.isFile() ||
            pathInfo.isSymbolicLink() ||
            !pathInfo.isFile() ||
            pathInfo.dev !== openedInfo.dev ||
            pathInfo.ino !== openedInfo.ino
          ) {
            return {
              title: "Target artifact not saved",
              output: "Source input must remain the same regular file during open; symbolic links and non-file inputs are refused.",
              metadata: { saved: false, reason: "unsafe_source_file", target_url: params.target_url, source_path: params.source_path } as TargetArtifactMetadata,
            }
          }
          if (openedInfo.size > 32 * 1024 * 1024) {
            return {
              title: "Target artifact not saved",
              output: "Source text file exceeds the 32 MB limit. Configure the producer to write to the exact target workspace path instead.",
              metadata: { saved: false, reason: "source_file_too_large", target_url: params.target_url, source_path: params.source_path } as TargetArtifactMetadata,
            }
          }
          bytes = await handle.readFile()
          if (bytes.byteLength > 32 * 1024 * 1024) {
            return {
              title: "Target artifact not saved",
              output: "Source text file grew beyond the 32 MB limit while being read. Configure the producer to write to the exact target workspace path instead.",
              metadata: { saved: false, reason: "source_file_too_large", target_url: params.target_url, source_path: params.source_path } as TargetArtifactMetadata,
            }
          }
        } finally {
          await handle.close()
        }
        rawContent = bytes.toString("utf-8")
        sourceHash = createHash("sha256").update(bytes).digest("hex")
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code
        if (code === "ELOOP" || code === "EISDIR") {
          return {
            title: "Target artifact not saved",
            output: "Source input must be a regular file; symbolic links and non-file inputs are refused.",
            metadata: { saved: false, reason: "unsafe_source_file", target_url: params.target_url, source_path: params.source_path } as TargetArtifactMetadata,
          }
        }
        return {
          title: "Target artifact not saved",
          output: "Could not read source file: " + (error instanceof Error ? error.message : String(error)),
          metadata: { saved: false, reason: "source_file_read_failed", target_url: params.target_url, source_path: params.source_path } as TargetArtifactMetadata,
        }
      }
    } else {
      rawContent = params.content!
    }

    const content = rawContent.endsWith("\n") ? rawContent : rawContent + "\n"
    await TargetMemory.writeWorkspaceFile(workspace, params.area + "/" + filename, content)
    return {
      title: "Target artifact saved",
      output: [
        "Target: " + workspace.targetURL,
        "Workspace: " + workspace.workspacePath,
        "Artifact: " + filePath,
        "Bytes written: " + Buffer.byteLength(content, "utf-8"),
        ...(params.source_path ? ["Source file: " + params.source_path, "Source SHA-256: " + sourceHash] : []),
        "Evidence preservation: exact content stored in target-local workspace",
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
        source_path: params.source_path,
        source_sha256: sourceHash,
      } as TargetArtifactMetadata,
    }
  },
})

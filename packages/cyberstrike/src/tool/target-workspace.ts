import z from "zod"
import fs from "node:fs/promises"
import { constants as fsConstants } from "node:fs"
import path from "node:path"
import { createHash } from "node:crypto"
import { TargetMemory, type TargetAssetType, USER_CONFIRMED_SCOPE_SOURCE } from "../target"
import { matchingScopeItems } from "../target/scope-index"
import { parseScopeFileContents, resolveScopeFilePath } from "../target/scope-file"
import { Tool } from "./tool"
import { assertExternalDirectory } from "./external-directory"

const Parameters = z.object({
  action: z.enum(["init", "configure_scope", "attach_asset", "show", "list", "record_summary"]),
  target_url: z.string().optional(),
  include: z.array(z.string().min(1)).optional(),
  user_confirmed_scope_list: z.boolean().optional().describe("Set true only when the user explicitly identifies the supplied complete include list or scope file as their authorized scope. Allows the explicitly supplied list, including wildcard entries, without demanding a policy URL. Use merge_existing=true to add the supplied list to a configured manifest; omit it to replace the current include list. Does not infer sibling assets or override exclusions."),
  scope_file_path: z.string().min(1).optional().describe("Path to a UTF-8 scope file. Imports exact entries, preserves a copy under the canonical target workspace, and records an import checkpoint in notes.md."),
  exclude: z.array(z.string().min(1)).optional(),
  merge_existing: z.boolean().optional().describe("Incrementally add exact entries to the configured scope without re-importing the full list. Treat this as the operator-confirmed asset path; preserve existing includes/exclusions/provenance and record the confirmation in notes. Saved exclusions remain authoritative."),
  user_confirmed_scope: z.boolean().optional().describe("Set true only when the user explicitly confirms the exact supplied asset is in scope. Allows an initial exact-asset manifest without demanding an external policy URL; records that provenance in the manifest and notes. Does not override explicit exclusions or authorize related assets."),
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
  source_scope_entry_count?: number
  source_scope_file?: string
  source_scope_sha256?: string
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

const USER_CONFIRMED_SCOPE_PREFIX = "User-confirmed in conversation"
const USER_CONFIRMED_SCOPE_LIST_SOURCE = USER_CONFIRMED_SCOPE_PREFIX + ": complete scope list"

/** Parse one specific incremental asset; never mistake a wildcard or CIDR for an exact confirmation. */
function confirmedScopeCandidate(input: string): URL | undefined {
  const value = input.trim()
  if (!value || /^(?:domain|wildcard|url|cidr|ip address|api|ai model|smart contracts?|source code|executable|hardware(?:\/iot)?|ios|android|other(?: asset)?):/i.test(value)) return undefined
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(value) || /^\[?[0-9a-f:.]+\]?\/\d{1,3}$/i.test(value)) return undefined
  if (/[*{}\\]/.test(value)) return undefined
  if (!/^https?:\/\//i.test(value) && value.includes("/")) return undefined
  let candidateValue = value
  if (!/^https?:\/\//i.test(value)) {
    const rawIPv6 = (value.startsWith("[") || value.split(":").length >= 3)
      ? value.match(/^\[?([0-9a-f:]+)\]?$/i)
      : undefined
    candidateValue = rawIPv6 && value.includes(":")
      ? "https://[" + rawIPv6[1] + "]"
      : "https://" + value
  }
  try {
    const url = new URL(candidateValue)
    if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname || url.hostname.includes("*") || url.username || url.password || url.search || url.hash) return undefined
    return url
  } catch {
    return undefined
  }
}

export const TargetWorkspaceTool = Tool.define("target_workspace", {
  description: [
    "Manage the canonical target workspace before target-specific reconnaissance or testing.",
    "Always initialize the parent/program root with action=init before processing scope files, running recon, or saving artifacts. This creates a project-scoped .cyberstrike/targets/<slug> tree, notes.md, target.json, workspace.json, scope/scope.json and the standard artifact directories.",
    "Workspace creation is NOT authorization. Init leaves scope unconfigured. Use available verified policy metadata for a full policy import. If the user explicitly confirms an exact asset is in scope, trust that confirmation without repeatedly demanding proof: merge only that asset into a configured scope, or configure an initial exact-asset scope with user_confirmed_scope=true when no manifest exists. Record the confirmation in target notes, preserve existing provenance, and never override exclusions or infer related assets.",
    "When the user explicitly confirms a complete supplied list as the scope, accept the list as a unit with user_confirmed_scope_list=true; do not ask them to select entries one by one. Record the list-confirmation provenance, preserve exclusions, and authorize only entries actually supplied.",
    "Attach only a child host permitted by the saved parent scope. Child workspaces are nested beneath the parent assets directory. For huge scopes, store the original candidate list in the root workspace and create child workspaces as assets are validated/processed; do not create hundreds of thousands of empty directories.",
    "Use show/list to retrieve canonical absolute paths. For initial setup or a changed full scope list, use action=configure_scope with scope_file_path; it imports exact entries, stores a copy under the root workspace scope directory, and records the count/source hash in notes.md. For a user-confirmed incremental addition to an already configured scope, use action=configure_scope with only the new include/exclude entries and merge_existing=true; this merges with the saved manifest without reading the original scope file again. Use target_artifact for other target files and target_note for observations tied to evidence. Never invent an alternate output directory.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params, ctx) {
    if (params.action === "init") {
      const workspace = await TargetMemory.ensure(required(params.target_url, "target_url"))
      const scope = await TargetMemory.getScope(workspace.targetURL)
      const requiredFiles = [
        path.join(workspace.workspacePath, "target.json"),
        path.join(workspace.workspacePath, "workspace.json"),
        path.join(workspace.workspacePath, "scope", "scope.json"),
        path.join(workspace.workspacePath, "notes.md"),
      ]
      for (const requiredFile of requiredFiles) {
        const info = await fs.lstat(requiredFile).catch(() => undefined)
        if (!info?.isFile() || info.isSymbolicLink()) {
          throw new Error("Target workspace initialization failed integrity verification: required regular file is missing: " + requiredFile)
        }
      }
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
          "Authorization: " + (scope?.status === "configured" ? "configured; reuse saved scope and let active tools enforce each concrete request" : "UNCONFIGURED — do not perform active testing"),
          "Workspace integrity: metadata, scope manifest, and notes verified.",
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
      const targetURL = required(params.target_url, "target_url")
      let fileEntries: string[] = []
      let sourceContents: string | undefined
      let sourcePath: string | undefined
      let sourceHash: string | undefined
      let sourceFilename: string | undefined
      let sourceArtifactPath: string | undefined

      if (params.scope_file_path) {
        // Do not let a file-path typo silently create a second target workspace.
        const existingWorkspace = await TargetMemory.get(targetURL)
        if (!existingWorkspace) {
          return {
            title: "Scope import stopped: target workspace missing",
            output: "Initialize the canonical program/root with target_workspace(action=\"init\") first. No scope, file copy, or alternate workspace was created.",
            metadata: { saved: false, reason: "workspace_missing", target_url: targetURL } as TargetWorkspaceMetadata,
          }
        }

        sourcePath = resolveScopeFilePath(params.scope_file_path)
        // Scope import reads a local file; require the same filesystem permissions as ReadTool.
        await assertExternalDirectory(ctx, sourcePath)
        await ctx.ask({
          permission: "read",
          patterns: [sourcePath],
          always: ["*"],
          metadata: { purpose: "import target authorization scope file" },
        })
        let bytes: Buffer
        try {
          const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0)
          const handle = await fs.open(sourcePath, fsConstants.O_RDONLY | noFollow)
          try {
            const openedInfo = await handle.stat()
            const pathInfo = await fs.lstat(sourcePath)
            if (
              !openedInfo.isFile() ||
              pathInfo.isSymbolicLink() ||
              !pathInfo.isFile() ||
              pathInfo.dev !== openedInfo.dev ||
              pathInfo.ino !== openedInfo.ino
            ) {
              throw new Error("Scope file must remain the same regular file during open; symbolic links and non-file inputs are refused.")
            }
            if (openedInfo.size > 32 * 1024 * 1024) {
              throw new Error("Scope file exceeds the 32 MB import limit.")
            }
            bytes = await handle.readFile()
            if (bytes.byteLength > 32 * 1024 * 1024) {
              throw new Error("Scope file grew beyond the 32 MB import limit while being read.")
            }
          } finally {
            await handle.close()
          }
        } catch (error) {
          throw new Error("Could not read scope file " + sourcePath + ": " + (error instanceof Error ? error.message : String(error)))
        }
        sourceContents = bytes.toString("utf-8")
        fileEntries = parseScopeFileContents(sourceContents!)
        sourceHash = createHash("sha256").update(bytes).digest("hex")
        sourceFilename = "source-scope-" + sourceHash.slice(0, 16) + ".txt"
        sourceArtifactPath = path.join(existingWorkspace.workspacePath, "scope", sourceFilename)
        // Persist the input before changing the authorization manifest. If any later
        // validation fails, the source list is still safely preserved in the workspace.
        await TargetMemory.writeWorkspaceFile(existingWorkspace, "scope/" + sourceFilename, sourceContents!)
      }

      let includeEntries = [...(params.include ?? []), ...fileEntries]
      let excludeEntries = params.exclude ?? []
      let authorizationSource = params.authorization_source?.trim()
      let authorizationReference = params.authorization_reference?.trim()
      let previousScopeItems: string[] | undefined
      const userConfirmedScopeList = params.user_confirmed_scope_list === true
      let inheritedUserConfirmedScopeList = false

      // A full replacement of include entries does not implicitly erase prior exclusions.
      // Passing exclude: [] is the explicit way to remove all saved exclusions.
      if (!params.merge_existing && params.exclude === undefined && (params.scope_file_path || userConfirmedScopeList)) {
        const existingWorkspace = await TargetMemory.get(targetURL)
        const existingScope = existingWorkspace ? await TargetMemory.getScope(existingWorkspace.targetURL) : undefined
        if (existingScope?.status === "configured") {
          excludeEntries = [...existingScope.excludedItems]
        }
      }

      if (params.merge_existing) {
        if (params.scope_file_path) {
          throw new Error("merge_existing cannot be combined with scope_file_path. Add individual entries without re-importing the full scope file.")
        }
        const existingWorkspace = await TargetMemory.get(targetURL)
        if (!existingWorkspace) {
          return {
            title: "Scope update stopped: target workspace missing",
            output: "Initialize/open the canonical root and configure its initial scope before adding entries. No scope was changed.",
            metadata: { saved: false, reason: "workspace_missing", target_url: targetURL } as TargetWorkspaceMetadata,
          }
        }
        const existingScope = await TargetMemory.getScope(existingWorkspace.targetURL)
        if (!existingScope || existingScope.status !== "configured" || !existingScope.scopeItems.length || !existingScope.authorizationSource || (!existingScope.authorizationReference && !existingScope.authorizationSource.startsWith(USER_CONFIRMED_SCOPE_PREFIX))) {
          return {
            title: "Scope update stopped: no configured scope to extend",
            output: "No scope was changed because there is no configured manifest to extend. If the operator explicitly confirmed one exact asset, configure that single entry with user_confirmed_scope=true and omit merge_existing; no external policy URL is required. Otherwise, import the official program policy. Do not restart discovery or ask for the same confirmation again.",
            metadata: { saved: false, reason: "scope_not_configured", target_url: existingWorkspace.targetURL } as TargetWorkspaceMetadata,
          }
        }
        inheritedUserConfirmedScopeList = existingScope.authorizationSource.startsWith(USER_CONFIRMED_SCOPE_LIST_SOURCE)
        // Normal updates add exact assets. A separately confirmed complete list may
        // intentionally include multiple explicit entries or wildcards.
        for (const entry of params.include ?? []) {
          const candidate = confirmedScopeCandidate(entry)
          if (!candidate && !userConfirmedScopeList) {
            return {
              title: "Scope extension needs one exact asset",
              output: "No scope changes were made. Incremental scope updates accept a specific hostname, host:port, IP, or explicit HTTP(S) URL per entry, not wildcard hosts, CIDRs, or typed resource categories. Correct only the ambiguous entry; do not restart policy discovery.",
              metadata: { saved: false, reason: "incremental_entry_not_exact", target_url: existingWorkspace.targetURL } as TargetWorkspaceMetadata,
            }
          }
          const excluded = candidate ? matchingScopeItems(candidate, existingScope.excludedItems) : []
          if (excluded.length) {
            const identity = "scope-exclusion-conflict:" + createHash("sha256").update(entry + "\0" + excluded.join("\0")).digest("hex").slice(0, 20)
            try {
              await TargetMemory.addNote(existingWorkspace.targetURL, {
                kind: "manual",
                title: "Scope confirmation conflicts with a saved exclusion",
                content: [
                  "The operator identified this exact asset for an incremental scope update, but the saved manifest explicitly excludes it.",
                  "Requested asset: " + entry,
                  "Matching exclusion(s): " + excluded.join(", "),
                  "No scope entry was changed. Explicit exclusions remain authoritative until the operator explicitly resolves the policy conflict.",
                ].join("\n"),
                source: "user-confirmed-scope-conflict",
                status: "observed",
                tags: ["scope", "exclusion", "blocked"],
                upsertByIdentity: true,
                identityKey: identity,
              })
            } catch { /* The scope conflict remains the result if note persistence is unavailable. */ }
            return {
              title: "Scope extension conflicts with a saved exclusion",
              output: "No scope changes were made. The requested asset " + entry + " matches saved exclusion(s): " + excluded.join(", ") + ". This is the specific blocker, not a request for more proof. If the actual program policy changed, update the exclusion explicitly and resume without repeating discovery.",
              metadata: { saved: false, reason: "explicit_exclusion_conflict", target_url: existingWorkspace.targetURL, excluded_items: excluded } as TargetWorkspaceMetadata,
            }
          }
        }
        previousScopeItems = [...existingScope.scopeItems]
        includeEntries = [...existingScope.scopeItems, ...includeEntries]
        excludeEntries = [...existingScope.excludedItems, ...excludeEntries]
        authorizationSource = authorizationSource || existingScope.authorizationSource
        authorizationReference = authorizationReference || existingScope.authorizationReference || undefined
      }

      const userConfirmedInitialScope = params.user_confirmed_scope === true && !params.merge_existing && !params.scope_file_path
      if (userConfirmedScopeList && includeEntries.length === 0) {
        return {
          title: "Complete scope list is empty",
          output: "No scope was changed because the explicitly confirmed complete list contains no entries.",
          metadata: { saved: false, reason: "empty_confirmed_scope_list", target_url: targetURL } as TargetWorkspaceMetadata,
        }
      }
      if (userConfirmedInitialScope) {
        if (includeEntries.length !== 1 || !confirmedScopeCandidate(includeEntries[0])) {
          return {
            title: "Initial user-confirmed scope needs one exact asset",
            output: "No scope changes were made. A first-time confirmation must name one exact hostname, host:port, IP, or HTTP(S) URL. Do not require a policy link or repeat proof; pass the single asset the operator identified.",
            metadata: { saved: false, reason: "initial_confirmation_not_exact", target_url: targetURL } as TargetWorkspaceMetadata,
          }
        }
        const candidate = confirmedScopeCandidate(includeEntries[0])!
        const excluded = matchingScopeItems(candidate, excludeEntries)
        if (excluded.length) {
          return {
            title: "Initial scope confirmation conflicts with an exclusion",
            output: "No scope changes were made. The exact requested asset matches an explicit exclusion: " + excluded.join(", ") + ". Resolve the policy conflict explicitly; no further proof or scope rediscovery is being requested.",
            metadata: { saved: false, reason: "explicit_exclusion_conflict", target_url: targetURL, excluded_items: excluded } as TargetWorkspaceMetadata,
          }
        }
      }
      const sourceForConfiguration = userConfirmedScopeList && !authorizationReference
        ? USER_CONFIRMED_SCOPE_LIST_SOURCE + (authorizationSource ? ": " + authorizationSource : "")
        : authorizationSource || (userConfirmedInitialScope ? USER_CONFIRMED_SCOPE_SOURCE : undefined)
      const userConfirmedScopeProvenance = Boolean(
        !authorizationReference && sourceForConfiguration?.startsWith(USER_CONFIRMED_SCOPE_PREFIX),
      )
      const result = await TargetMemory.configureScope(targetURL, {
        include: includeEntries,
        exclude: excludeEntries,
        authorizationSource: required(sourceForConfiguration, "authorization_source"),
        authorizationReference,
        userConfirmed: userConfirmedInitialScope || userConfirmedScopeList || userConfirmedScopeProvenance,
        userConfirmedExactEntries: userConfirmedInitialScope
          ? [includeEntries[0]]
          : params.merge_existing && userConfirmedScopeProvenance
            ? (params.include ?? [])
            : undefined,
        userConfirmedScopeList: userConfirmedScopeList || inheritedUserConfirmedScopeList,
      })

      if (sourceContents !== undefined && sourceHash && sourceFilename && sourceArtifactPath) {
        const canonicalSourcePath = path.join(result.workspace.workspacePath, "scope", sourceFilename)
        if (canonicalSourcePath !== sourceArtifactPath) {
          await TargetMemory.writeWorkspaceFile(result.workspace, "scope/" + sourceFilename, sourceContents)
          sourceArtifactPath = canonicalSourcePath
        }
        await TargetMemory.addNote(result.workspace.targetURL, {
          kind: "manual",
          title: "Scope file import checkpoint",
          content: [
            "Imported an explicit scope list from " + path.basename(sourcePath ?? "scope file") + ".",
            "Usable file entries: " + fileEntries.length + ".",
            "Configured unique include entries: " + result.scope.scopeItems.length + ".",
            "Source copy: scope/" + sourceFilename + ".",
            "Source SHA-256: " + sourceHash + ".",
            "Authorization policy: " + result.scope.authorizationReference + ".",
            "No active testing was performed by the import operation.",
          ].join("\n"),
          source: "target_workspace",
          status: "observed",
          tags: ["scope-import", "provenance"],
        })
      }

      if (userConfirmedScopeList) {
        const confirmedListHash = createHash("sha256").update(JSON.stringify({
          include: includeEntries,
          exclude: excludeEntries,
        })).digest("hex").slice(0, 24)
        try {
          await TargetMemory.addNote(result.workspace.targetURL, {
            kind: "manual",
            title: "User-confirmed complete scope list",
            content: [
              "The operator explicitly identified the supplied complete scope list as authorized. The manifest was configured from entries supplied; no sibling assets were inferred.",
              "Input entries supplied: " + ((params.include ?? []).length + fileEntries.length) + ".",
              "Configured unique include entries: " + result.scope.scopeItems.length + ".",
              "Configured exclusions: " + result.scope.excludedItems.length + ".",
              "Mode: " + (params.merge_existing ? "merged supplied list into saved scope" : "configured supplied list as current scope") + ".",
              "Authorization basis: explicit complete-list confirmation in the conversation; no external policy URL was fabricated.",
              "The active-request scope matcher enforces supported web entries and exclusions; unsupported typed assets remain saved as evidence and do not authorize HTTP requests.",
            ].join("\n"),
            source: "user-confirmed-scope-list",
            status: "observed",
            tags: ["scope", "user-confirmed", "complete-list", "authorization-provenance"],
            upsertByIdentity: true,
            identityKey: "user-confirmed-scope-list:" + confirmedListHash,
          })
        } catch {
          // The manifest itself still carries list-confirmation provenance.
        }
      }

      let confirmationNotesSaved = 0
      const confirmationNoteErrors: string[] = []
      const entriesToDocument = params.merge_existing && previousScopeItems
        ? result.scope.scopeItems.filter((entry) => !previousScopeItems!.includes(entry))
        : userConfirmedInitialScope ? result.scope.scopeItems : []
      for (const entry of entriesToDocument) {
        const identityKey = "scope-confirmation:" + createHash("sha256").update(entry).digest("hex").slice(0, 24)
        try {
          await TargetMemory.addNote(result.workspace.targetURL, {
            kind: "manual",
            title: "User-confirmed in-scope asset: " + entry,
            content: [
              "The operator explicitly confirmed this exact asset is in scope. The exact entry was saved to the persisted scope manifest without requesting a separate policy URL or repeated proof.",
              "Exact persisted include entry: " + entry + ".",
              "Existing include entries, exclusions, and authorization provenance were preserved. No wildcard or sibling assets were inferred.",
              "Authorization basis: " + result.scope.authorizationSource + (result.scope.authorizationReference ? " (" + result.scope.authorizationReference + ")" : " (explicit confirmation in the current conversation; no external policy URL was supplied)") + ".",
              "Active request tools still enforce the persisted scope on each concrete URL; explicit exclusions remain authoritative.",
            ].join("\n"),
            source: "user-confirmed-scope",
            status: "observed",
            tags: ["scope", "user-confirmed", "authorization-provenance"],
            upsertByIdentity: true,
            identityKey,
          })
          confirmationNotesSaved++
        } catch (error) {
          confirmationNoteErrors.push(entry + ": " + (error instanceof Error ? error.message : String(error)))
        }
      }

      const requiredFiles = [
        path.join(result.workspace.workspacePath, "workspace.json"),
        path.join(result.workspace.workspacePath, "scope", "scope.json"),
        path.join(result.workspace.workspacePath, "notes.md"),
        ...(sourceArtifactPath ? [sourceArtifactPath] : []),
      ]
      for (const requiredFile of requiredFiles) {
        const info = await fs.lstat(requiredFile).catch(() => undefined)
        if (!info?.isFile() || info.isSymbolicLink()) {
          throw new Error("Scope was configured but workspace integrity verification failed: required regular file is missing: " + requiredFile)
        }
      }

      return {
        title: "Target scope saved",
        output: [
          "Target: " + result.workspace.targetURL,
          "Workspace: " + result.workspace.workspacePath,
          "Notes file: " + result.workspace.workspacePath + "/notes.md",
          "Scope file: " + result.workspace.workspacePath + "/scope/scope.json",
          ...(sourceArtifactPath ? ["Original scope list copy: " + sourceArtifactPath] : []),
          ...(sourceHash ? ["Original scope SHA-256: " + sourceHash] : []),
          ...(sourceContents !== undefined ? ["Usable lines imported: " + fileEntries.length] : []),
          "Authorization source: " + result.scope.authorizationSource,
          "Authorization reference: " + (result.scope.authorizationReference ?? "user-confirmed in conversation; recorded in notes.md"),
          "Included entries: " + result.scope.scopeItems.length,
          "Excluded entries: " + result.scope.excludedItems.length,
          "Workspace integrity: manifests and notes verified",
          "Authorized child workspaces attached/reorganized: " + result.associatedAssets.length,
          params.merge_existing ? (userConfirmedScopeList ? "Scope update mode: merged the explicitly confirmed supplied list; existing entries/exclusions were preserved." : "Scope update mode: merged the supplied exact entries into the saved scope; existing entries/exclusions and policy provenance were preserved.") : userConfirmedScopeList ? "Scope basis: explicit user confirmation of the complete supplied list; only supplied entries were configured." : userConfirmedInitialScope ? "Initial scope basis: explicit operator confirmation; no external policy link was demanded or fabricated." : "Scope configured. Reuse the saved manifest; do not re-import it unless the user provides an updated scope file.",
          ...(entriesToDocument.length ? ["User-confirmation notes saved: " + confirmationNotesSaved] : []),
          ...(confirmationNoteErrors.length ? ["WARNING: scope was saved, but confirmation-note persistence failed for: " + confirmationNoteErrors.join("; ")] : []),
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
          source_scope_entry_count: sourceContents !== undefined ? fileEntries.length : undefined,
          source_scope_file: sourceArtifactPath,
          source_scope_sha256: sourceHash,
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
        upsertByIdentity: Boolean(params.summary_title?.trim()),
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

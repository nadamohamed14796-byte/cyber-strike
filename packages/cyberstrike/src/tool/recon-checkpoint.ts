import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { Session } from "../session"
import { TargetMemory, USER_CONFIRMED_SCOPE_SOURCE } from "../target"
import {
  RECON_PHASES as PHASES,
  invalidateReconDownstreamPhases,
  initialReconRun as initialRun,
  parseReconRun as parseRun,
  reconRunID,
  type ReconPhase,
  type ReconPhaseStatus,
  type ReconRunManifest as ReconRun,
} from "../target/recon-gate"
import { Tool } from "./tool"

export { reconRunID, unresolvedReconPrerequisites } from "../target/recon-gate"
export type { ReconPhase, ReconPhaseRecord, ReconPhaseStatus } from "../target/recon-gate"

function terminal(status: ReconPhaseStatus): boolean {
  return status === "complete" || status === "unavailable" || status === "deferred"
}

export const RECON_PHASE_ARTIFACT_AREAS: Partial<Record<ReconPhase, readonly string[]>> = {
  asset_discovery: ["assets"],
  live_hosts_ports: ["recon"],
  url_collection: ["urls"],
  directory_fuzzing: ["directories"],
  parameter_discovery: ["parameters"],
  parameter_fuzzing: ["parameters"],
  // correlate_javascript atomically writes a source graph, endpoint candidates, and a Tester Survey.
  javascript_analysis: ["javascript", "endpoints", "testing"],
  endpoint_inventory: ["endpoints"],
  vulnerability_testing: ["testing", "findings", "evidence"],
  reporting: ["reports"],
}

export const RECON_PHASE_REQUIRED_FLAT_ARTIFACTS: Partial<Record<ReconPhase, readonly string[]>> = {
  // These are the two canonical handoff files consumed by endpoint_inventory and final reporting.
  javascript_analysis: ["javascript-analysis.md", "endpoints.txt"],
  endpoint_inventory: ["endpoints.txt"],
}

export function missingRequiredReconArtifacts(phase: ReconPhase, reportedPaths: readonly string[]): string[] {
  const normalized = new Set(reportedPaths.map((item) => item.replace(/\\/g, "/").replace(/^\.\/+/, "")))
  return [...(RECON_PHASE_REQUIRED_FLAT_ARTIFACTS[phase] ?? [])].filter((required) => !normalized.has(required))
}

export type ReconBeginDisposition = "start" | "resume_existing" | "already_resolved"

export function reconBeginDisposition(status: ReconPhaseStatus, phase: ReconPhase): ReconBeginDisposition {
  if (status === "running") return "resume_existing"
  if (status === "complete" || (status === "unavailable" && phase !== "scope_validation" && phase !== "workspace_setup")) {
    return "already_resolved"
  }
  return "start"
}

const Parameters = z.object({
  action: z.enum(["status", "begin", "complete", "block", "fail", "unavailable", "defer"]),
  target_url: z.string().min(1).describe("Exact existing root or asset workspace URL"),
  scope_validation_target: z.string().min(1).optional().describe("Absolute HTTP(S) URL of the actual starting asset that passed scope_check; required when completing scope_validation. The program-root workspace URL may be only a policy container."),
  phase: z.enum(PHASES).optional(),
  summary: z.string().max(4000).optional(),
  reason: z.string().max(2000).optional(),
  counts: z.record(z.string(), z.number().finite().nonnegative()).optional(),
  artifacts: z.array(z.string().min(1)).optional(),
})

export const ReconCheckpointTool = Tool.define<typeof Parameters, Tool.Metadata>("recon_checkpoint", {
  description: [
    "Lightweight progress tracking for reconnaissance, not a tool allowlist. Use status when helpful and begin/complete to record progress, but ordinary recon tools are not blocked by stale phase order or missing earlier phase records. If a phase is already running, resume it without beginning it again. Scope checks remain enforced by the runtime.",
    "Suggested workflow: scope_validation → workspace_setup → asset_discovery → live_hosts_ports → url_collection → directory_fuzzing → parameter_discovery → parameter_fuzzing → javascript_analysis → endpoint_inventory → reporting. This is progress guidance, not a gate on ordinary recon tools.",
    "A normal recon run defers vulnerability_testing and proceeds to reporting; only an explicit user request may begin testing after endpoint_inventory. Reopening testing invalidates reporting, which must be regenerated. Never launch scanners/session_scan automatically. Save wordlists/settings/results for directory and parameter phases; link JavaScript sources, request shapes, and correlation evidence for JavaScript analysis. Reporting requires the exact verified artifact reports/recon-final.md.",
    "Keep useful phase records and verified artifact paths, but do not let stale ordinary phase status block reconnaissance. Scope validation and workspace setup remain required; JavaScript and endpoint inventories should be recorded when produced. Vulnerability testing remains opt-in and requires completed endpoint inventory.",
    "This tool enforces phase order, not request authorization. Verify the saved scope; when it is new/changed or unresolved, call scope_check once for the actual starting asset with target_url selecting the canonical program-root workspace. Complete scope_validation only by supplying scope_validation_target with that exact absolute HTTP(S) asset URL; runtime rechecks and persists it, then revalidates it on resume. Do not check the root container merely because it identifies the workspace. Active-request tools still enforce persisted scope for every concrete request.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params, ctx) {
    try {
      const requestedWorkspace = await TargetMemory.get(params.target_url)
      if (!requestedWorkspace) return { title: "Recon checkpoint unavailable", output: "No existing target workspace. Initialize the canonical target with target_workspace first.", metadata: { saved: false, reason: "workspace_missing" } }
      const allWorkspaces = TargetMemory.list()
      const byID = new Map(allWorkspaces.map((item) => [item.id, item]))
      let workspace = requestedWorkspace
      const visitedParents = new Set<string>()
      while (workspace.parentTargetID && !visitedParents.has(workspace.id)) {
        visitedParents.add(workspace.id)
        const parent = byID.get(workspace.parentTargetID)
        if (!parent) break
        workspace = parent
      }

      const sessionID = Session.root(ctx.sessionID)
      // One resumable run per canonical target workspace, including across new root sessions.
      const runID = reconRunID(workspace.id)
      const filename = "recon-" + runID + ".json"
      const relativePath = "runs/" + filename
      const absolutePath = path.join(workspace.workspacePath, relativePath)
      let run: ReconRun
      try {
        run = parseRun(await fs.readFile(absolutePath, "utf-8"), workspace.id, workspace.targetURL)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
        run = initialRun(workspace.targetURL, workspace.id, sessionID)
      }
      // The active root session can change after a stop/resume. Keep the manifest's
      // current owner up to date without creating a duplicate run for this target.
      run.sessionID = sessionID

      // A prior "complete" flag is not authorization evidence by itself. Older
      // checkpoints did not persist the actual asset checked, and saved scope can
      // change between runs. Revalidate the recorded starting asset before trusting
      // this checkpoint or allowing any later phase to proceed.
      if (run.phases.scope_validation.status === "complete") {
        const validatedTarget = run.phases.scope_validation.scopeValidationTarget
        let invalidationReason: string | undefined
        if (!validatedTarget) {
          invalidationReason = "The saved scope_validation checkpoint has no recorded starting asset; scope must be checked again."
        } else {
          try {
            const decision = await TargetMemory.checkURLScope(validatedTarget)
            if (!decision.allowed || !decision.workspace) {
              invalidationReason = "The previously validated starting asset no longer passes persisted scope: " + decision.reason
            }
          } catch (error) {
            invalidationReason = "The previously validated starting asset could not be revalidated: " +
              (error instanceof Error ? error.message : String(error))
          }
        }
        if (invalidationReason) {
          run.phases.scope_validation = {
            ...run.phases.scope_validation,
            status: "pending",
            finishedAt: undefined,
            reason: invalidationReason,
          }
          invalidateReconDownstreamPhases("scope_validation", run.phases, invalidationReason)
          run.currentPhase = "scope_validation"
          run.updatedAt = new Date().toISOString()
          await TargetMemory.writeWorkspaceFile(workspace, relativePath, JSON.stringify(run, null, 2) + "\n")
        }
      }

      if (params.action === "status") {
        const lines = PHASES.map((phase) => {
          const record = run.phases[phase]
          return phase + ": " + record.status +
            (record.summary ? " — " + record.summary : "") +
            (record.reason ? " (reason: " + record.reason + ")" : "") +
            (record.artifacts?.length ? " [artifacts: " + record.artifacts.join(", ") + "]" : "")
        })
        return { title: "Recon run status", output: ["Target: " + run.targetURL, "Manifest: " + absolutePath, "Current phase: " + (run.currentPhase ?? "none"), ...lines].join("\n"), metadata: { saved: true, target_id: workspace.id, run_id: runID, manifest: absolutePath, current_phase: run.currentPhase, phases: run.phases } }
      }

      if (!params.phase) return { title: "Recon checkpoint rejected", output: "phase is required for this action.", metadata: { saved: false, reason: "phase_required" } }
      const phase = params.phase
      const record = run.phases[phase]
      if (params.action === "defer" && phase !== "vulnerability_testing") {
        return { title: "Recon checkpoint rejected", output: "Only the optional vulnerability_testing phase may be deferred. Scope validation, workspace setup, discovery, JavaScript analysis, endpoint inventory, and reporting must not be deferred.", metadata: { saved: false, reason: "phase_not_deferable", phase } }
      }

      if (params.action === "begin") {
        const disposition = reconBeginDisposition(record.status, phase)
        if (disposition === "already_resolved") {
          return {
            title: "Recon phase already resolved",
            output: phase + " is already " + record.status + ". Inspect its artifacts; do not repeat expensive work unless new evidence invalidates this checkpoint.",
            metadata: { saved: false, reason: "phase_already_resolved", phase, status: record.status },
          }
        }
        if (phase !== "scope_validation" && phase !== "workspace_setup") {
          // The root workspace can represent a bug-bounty program/policy container,
          // not an in-scope hostname (for example, a program that authorizes unrelated
          // domains). Validate that its saved authorization manifest is configured;
          // individual candidate URLs must still pass checkURLScope before active use.
          let rootScope
          try {
            rootScope = await TargetMemory.getScope(workspace.targetURL)
          } catch (error) {
            return { title: "Recon phase blocked by persisted scope", output: "Cannot begin " + phase + " because the root authorization manifest could not be loaded: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "persisted_scope_invalid" } }
          }
          if (!rootScope || rootScope.status !== "configured" || rootScope.scopeItems.length === 0) {
            return { title: "Recon phase blocked by persisted scope", output: "Cannot begin " + phase + " because the canonical program workspace has no configured, non-empty authorization scope. Configure and review the official scope before continuing.", metadata: { saved: false, reason: "persisted_scope_unconfigured" } }
          }
        }
        // Ordinary recon phases are progress markers, not hard gates. The agent may
        // use any suitable recon capability when useful evidence becomes available.
        // Keep only the explicit testing handoff gated by completed endpoint inventory.
        if (phase === "vulnerability_testing") {
          const required = ["scope_validation", "workspace_setup", "endpoint_inventory"] as const
          const unresolved = required.filter((item) => run.phases[item].status !== "complete")
          if (unresolved.length) {
            return { title: "Testing checkpoint requires endpoint inventory", output: "Begin vulnerability_testing only after scope validation, workspace setup, and endpoint inventory are complete: " + unresolved.map((item) => item + "=" + run.phases[item].status).join(", "), metadata: { saved: false, reason: "testing_prerequisites_unresolved", unresolved } }
          }
        }
        if (disposition === "resume_existing") {
          return {
            title: "Recon phase already running",
            output: phase + " is already running since " + (record.startedAt ?? "an earlier checkpoint") + ". Do not begin it again. Reconcile existing artifacts and resume only unfinished sources/items; do not repeat successful work. When the phase is genuinely finished, call complete with verified artifacts, or use block/fail with a concrete reason.",
            metadata: { saved: false, reason: "phase_already_running", phase, status: record.status, started_at: record.startedAt, artifacts: record.artifacts ?? [] },
          }
        }
        run.phases[phase] = { ...record, status: "running", startedAt: record.startedAt ?? new Date().toISOString(), finishedAt: undefined, reason: undefined, summary: params.summary ?? record.summary }
        if (phase === "vulnerability_testing" && record.status === "deferred") {
          invalidateReconDownstreamPhases(
            phase,
            run.phases,
            "Regenerate this downstream checkpoint after vulnerability_testing was explicitly reopened.",
          )
        }
        run.currentPhase = phase
      } else {
        if (record.status !== "running") {
          return { title: "Recon checkpoint rejected", output: "Phase " + phase + " is " + record.status + ", not running. Call begin first; the manifest was not changed.", metadata: { saved: false, reason: "phase_not_running", phase, status: record.status } }
        }
        if ((params.action === "block" || params.action === "fail" || params.action === "unavailable" || params.action === "defer") && !params.reason?.trim()) {
          return { title: "Recon checkpoint rejected", output: "A reason is required to mark a phase blocked, failed, unavailable, or deferred.", metadata: { saved: false, reason: "reason_required" } }
        }
        const status: ReconPhaseStatus = params.action === "complete" ? "complete" : params.action === "block" ? "blocked" : params.action === "fail" ? "failed" : params.action === "defer" ? "deferred" : "unavailable"
        if (status === "complete" && !params.summary?.trim()) {
          return { title: "Recon checkpoint rejected", output: "A verified summary is required before a phase can be marked complete.", metadata: { saved: false, reason: "summary_required" } }
        }
        if (status === "complete" && phase === "scope_validation") {
          // Scope validation proves the official policy is saved on the canonical
          // program workspace. The root URL itself need not be in scope: the program
          // may authorize unrelated domains. Recon and testing tools must separately
          // authorize each concrete candidate URL against this manifest.
          let scope
          try {
            scope = await TargetMemory.getScope(workspace.targetURL)
          } catch (error) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation because the saved authorization manifest is invalid: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_manifest_invalid" } }
          }
          const userConfirmedScope = Boolean(
            scope?.authorizationSource?.startsWith(USER_CONFIRMED_SCOPE_SOURCE) &&
            scope.authorizationReference === null,
          )
          if (!scope || scope.status !== "configured" || scope.scopeItems.length === 0 ||
            !scope.authorizationSource?.trim() ||
            (!scope.authorizationReference?.startsWith("https://") && !userConfirmedScope)) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation: configure a non-empty scope manifest with saved authorization provenance. An explicit user-confirmed exact asset is a valid provenance source and does not require a separate policy URL. The root workspace URL itself does not have to be in scope.", metadata: { saved: false, reason: "scope_manifest_unconfigured" } }
          }
          const validationTarget = params.scope_validation_target?.trim()
          if (!validationTarget) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation without scope_validation_target: provide the exact absolute HTTP(S) URL that passed scope_check. The program-root workspace URL may be only a policy container.", metadata: { saved: false, reason: "scope_validation_target_required" } }
          }
          let parsedValidationTarget: URL
          try {
            parsedValidationTarget = new URL(validationTarget)
            if ((parsedValidationTarget.protocol !== "http:" && parsedValidationTarget.protocol !== "https:") ||
                parsedValidationTarget.username || parsedValidationTarget.password) throw new Error("target must be a credential-free absolute HTTP(S) URL")
          } catch (error) {
            return { title: "Scope validation rejected", output: "scope_validation_target is invalid: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_validation_target_invalid" } }
          }
          let targetDecision: Awaited<ReturnType<typeof TargetMemory.checkURLScope>>
          try {
            targetDecision = await TargetMemory.checkURLScope(parsedValidationTarget.href)
          } catch (error) {
            return { title: "Scope validation rejected", output: "The starting asset scope check failed: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_validation_check_failed" } }
          }
          if (!targetDecision.allowed || !targetDecision.workspace) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation: the starting asset is not authorized by the persisted manifest: " + targetDecision.reason, metadata: { saved: false, reason: "scope_validation_target_out_of_scope", target: parsedValidationTarget.href } }
          }
        }
        if (status === "complete" && phase === "workspace_setup") {
          for (const relative of ["target.json", "workspace.json", "notes.md", "scope/scope.json"]) {
            const candidate = path.join(workspace.workspacePath, relative)
            try {
              const info = await fs.lstat(candidate)
              if (!info.isFile() || info.isSymbolicLink()) throw new Error("not a regular file")
            } catch (error) {
              return { title: "Workspace setup rejected", output: "Cannot mark workspace_setup complete; required workspace file is missing or unsafe: " + relative + " (" + (error instanceof Error ? error.message : String(error)) + ")", metadata: { saved: false, reason: "workspace_integrity_failed", file: relative } }
            }
          }
          for (const relative of ["scope", "assets", "recon", "urls", "directories", "parameters", "requests", "javascript", "endpoints", "testing", "findings", "evidence", "reports", "scans", "runs", "logs", "sessions", "research"]) {
            const candidate = path.join(workspace.workspacePath, relative)
            try {
              const info = await fs.lstat(candidate)
              if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("not a regular directory")
            } catch (error) {
              return { title: "Workspace setup rejected", output: "Cannot mark workspace_setup complete; required workspace directory is missing or unsafe: " + relative + " (" + (error instanceof Error ? error.message : String(error)) + ")", metadata: { saved: false, reason: "workspace_integrity_failed", directory: relative } }
            }
          }
        }
        if (status === "complete" && !["scope_validation", "workspace_setup"].includes(phase) && !params.artifacts?.length) {
          return { title: "Recon checkpoint rejected", output: "This phase requires at least one verified artifact path before it can be marked complete. If the source/tool is genuinely unavailable or there were no applicable assets, use unavailable with a reason.", metadata: { saved: false, reason: "artifact_required" } }
        }
        if (status === "complete" && params.artifacts?.length) {
          const realWorkspace = await fs.realpath(workspace.workspacePath)
          let finalReconReportVerified = false
          for (const artifact of params.artifacts) {
            if (artifact.includes("\\") || artifact.split("/").some((part) => part === "..")) {
              return { title: "Recon checkpoint rejected", output: "Artifact path must remain inside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "unsafe_artifact_path" } }
            }
            const candidate = path.isAbsolute(artifact) ? path.resolve(artifact) : path.resolve(realWorkspace, artifact)
            const relative = path.relative(realWorkspace, candidate)
            if (!relative || relative === "." || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
              return { title: "Recon checkpoint rejected", output: "Artifact path must point to a file inside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "artifact_outside_workspace" } }
            }
            const resolvedArtifactPath = relative.split(path.sep).join("/")
            const requiredAreas = RECON_PHASE_ARTIFACT_AREAS[phase]
            const flatArtifacts: Partial<Record<ReconPhase, readonly string[]>> = {
              asset_discovery: ["subdomains.txt"],
              live_hosts_ports: ["live-hosts.txt", "ports.txt"],
              url_collection: ["urls.txt"],
              parameter_discovery: ["parameters.txt"],
              parameter_fuzzing: ["parameter-tests.md"],
              javascript_analysis: RECON_PHASE_REQUIRED_FLAT_ARTIFACTS.javascript_analysis ?? [],
              endpoint_inventory: RECON_PHASE_REQUIRED_FLAT_ARTIFACTS.endpoint_inventory ?? [],
              vulnerability_testing: ["findings.md"],
            }
            const isFlatArtifact = !resolvedArtifactPath.includes("/") &&
              Boolean(flatArtifacts[phase]?.includes(resolvedArtifactPath))
            if (requiredAreas && !isFlatArtifact && !requiredAreas.some((area) => resolvedArtifactPath.startsWith(area + "/"))) {
              return { title: "Recon checkpoint rejected", output: "Phase " + phase + " must save its verified output as a top-level canonical file (" + (flatArtifacts[phase]?.join(", ") ?? "none") + ") or under " + requiredAreas.map((area) => area + "/").join(", ") + "; got " + artifact, metadata: { saved: false, reason: "artifact_in_wrong_area", required_areas: requiredAreas, allowed_flat_artifacts: flatArtifacts[phase] ?? [] } }
            }
            let info
            let realArtifact: string
            try {
              info = await fs.lstat(candidate)
              if (info.isSymbolicLink() || !info.isFile()) throw new Error("not a regular file")
              realArtifact = await fs.realpath(candidate)
            } catch (error) {
              return { title: "Recon checkpoint rejected", output: "Artifact is missing, unsafe, or not a regular file: " + artifact + " (" + (error instanceof Error ? error.message : String(error)) + ")", metadata: { saved: false, reason: "artifact_not_verified" } }
            }
            const resolvedRelative = path.relative(realWorkspace, realArtifact)
            if (resolvedRelative === ".." || resolvedRelative.startsWith(".." + path.sep) || path.isAbsolute(resolvedRelative)) {
              return { title: "Recon checkpoint rejected", output: "Artifact resolves outside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "artifact_symlink_escape" } }
            }
            if (phase === "reporting" && resolvedRelative.split(path.sep).join("/") === "reports/recon-final.md") finalReconReportVerified = true
          }
          if (phase === "reporting" && !finalReconReportVerified) {
            return { title: "Recon report rejected", output: "The reporting phase requires a verified reports/recon-final.md artifact. Include that exact path and complete report before marking Recon finished.", metadata: { saved: false, reason: "final_recon_report_required" } }
          }
          const reportedPaths = new Set(params.artifacts.map((artifact) => {
            const candidate = path.isAbsolute(artifact) ? path.resolve(artifact) : path.resolve(realWorkspace, artifact)
            return path.relative(realWorkspace, candidate).split(path.sep).join("/")
          }))
          const missingRequired = missingRequiredReconArtifacts(phase, [...reportedPaths])
          if (missingRequired.length) {
            return {
              title: "Recon checkpoint rejected",
              output: "Cannot complete " + phase + " without its canonical output file(s): " + missingRequired.join(", ") + ". Create/update these files with verified results, including an explicit zero-result or incomplete status when applicable, then retry.",
              metadata: { saved: false, reason: "canonical_artifact_required", phase, missing_artifacts: missingRequired },
            }
          }
          if (phase === "javascript_analysis") {
            // A non-empty markdown summary alone is not proof that JavaScript was
            // collected and analyzed. Require at least one non-empty source file in
            // the canonical javascript/ directory, or a valid captured-asset index
            // whose referenced files exist inside the same target workspace.
            const javascriptRoot = path.join(realWorkspace, "javascript")
            let hasJavaScriptEvidence = false
            const indexPath = path.join(javascriptRoot, "captured-index.json")
            try {
              const indexInfo = await fs.lstat(indexPath)
              if (!indexInfo.isFile() || indexInfo.isSymbolicLink()) throw new Error("captured index is not a regular file")
              const index = JSON.parse(await fs.readFile(indexPath, "utf-8"))
              if (index?.schemaVersion !== 1 || index?.targetURL !== workspace.targetURL || !Array.isArray(index.assets)) {
                throw new Error("captured index has an invalid schema or target identity")
              }
              for (const asset of index.assets) {
                if (typeof asset?.file !== "string" || asset.file.includes("\\") || asset.file.split("/").some((part: string) => part === "..")) continue
                const candidate = path.resolve(realWorkspace, asset.file)
                const relative = path.relative(realWorkspace, candidate)
                if (!relative || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) continue
                try {
                  const info = await fs.lstat(candidate)
                  if (info.isFile() && !info.isSymbolicLink() && info.size > 0) {
                    hasJavaScriptEvidence = true
                    break
                  }
                } catch {
                  // A missing indexed asset does not count as evidence.
                }
              }
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
                return { title: "JavaScript checkpoint rejected", output: "Cannot verify captured JavaScript evidence: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "javascript_evidence_index_invalid" } }
              }
            }
            if (!hasJavaScriptEvidence) {
              const pending: string[] = [javascriptRoot]
              while (pending.length && !hasJavaScriptEvidence) {
                const directory = pending.pop()!
                let entries
                try {
                  entries = await fs.readdir(directory, { withFileTypes: true })
                } catch {
                  continue
                }
                for (const entry of entries) {
                  const candidate = path.join(directory, entry.name)
                  if (entry.isSymbolicLink()) continue
                  if (entry.isDirectory()) {
                    if (candidate !== javascriptRoot) pending.push(candidate)
                    continue
                  }
                  if (!entry.isFile() || !/\\.(?:m?js|cjs|map)$/i.test(entry.name)) continue
                  try {
                    const info = await fs.lstat(candidate)
                    if (info.isFile() && !info.isSymbolicLink() && info.size > 0) {
                      hasJavaScriptEvidence = true
                      break
                    }
                  } catch {
                    // Ignore files that disappeared while checking.
                  }
                }
              }
            }
            if (!hasJavaScriptEvidence) {
              return {
                title: "JavaScript checkpoint rejected",
                output: "Cannot mark javascript_analysis complete: no non-empty JavaScript/source-map asset was verified under javascript/. Collect and save the in-scope response bodies, then run correlate_javascript. If the target genuinely exposes no JavaScript assets, mark this phase unavailable with that evidence instead of claiming completion.",
                metadata: { saved: false, reason: "javascript_evidence_missing", phase },
              }
            }
          }
          for (const required of RECON_PHASE_REQUIRED_FLAT_ARTIFACTS[phase] ?? []) {
            try {
              const content = await fs.readFile(path.join(realWorkspace, required), "utf-8")
              if (!content.trim()) {
                return {
                  title: "Recon checkpoint rejected",
                  output: "Cannot complete " + phase + ": canonical artifact is empty: " + required + ". Record verified counts or an explicit zero-result/incomplete status.",
                  metadata: { saved: false, reason: "canonical_artifact_empty", phase, artifact: required },
                }
              }
            } catch (error) {
              return {
                title: "Recon checkpoint rejected",
                output: "Cannot read canonical artifact " + required + " for " + phase + ": " + (error instanceof Error ? error.message : String(error)),
                metadata: { saved: false, reason: "canonical_artifact_unreadable", phase, artifact: required },
              }
            }
          }
          // The canonical subdomains inventory is sufficient to record progress.
          // Source-level detail is not a completion gate;
          // an incomplete source must not prevent the rest of recon from continuing.
        }
        run.phases[phase] = {
          ...record,
          status,
          finishedAt: new Date().toISOString(),
          summary: params.summary?.trim() ?? record.summary,
          reason: params.reason?.trim(),
          counts: params.counts ?? record.counts,
          artifacts: params.artifacts ?? record.artifacts,
          scopeValidationTarget: phase === "scope_validation" && status === "complete"
            ? params.scope_validation_target?.trim()
            : record.scopeValidationTarget,
        }
        run.currentPhase = null
      }

      run.updatedAt = new Date().toISOString()
      await TargetMemory.writeWorkspaceFile(workspace, relativePath, JSON.stringify(run, null, 2) + "\n")
      const indexPath = path.join(workspace.workspacePath, "runs", "index.json")
      let index: { schemaVersion: number; targetURL: string; runs: Array<Record<string, unknown>> }
      try {
        const parsed = JSON.parse(await fs.readFile(indexPath, "utf-8"))
        if (parsed?.schemaVersion !== 1 || parsed.targetURL !== workspace.targetURL || !Array.isArray(parsed.runs)) throw new Error("Invalid run index identity or schema.")
        index = parsed
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
        index = { schemaVersion: 1, targetURL: workspace.targetURL, runs: [] }
      }
      const entry = { runID, sessionID, manifest: relativePath, currentPhase: run.currentPhase, updatedAt: run.updatedAt, completedPhases: PHASES.filter((item) => run.phases[item].status === "complete").length, resolvedPhases: PHASES.filter((item) => terminal(run.phases[item].status)).length, totalPhases: PHASES.length }
      const existing = index.runs.findIndex((item) => item.runID === runID)
      if (existing >= 0) index.runs[existing] = entry
      else index.runs.push(entry)
      await TargetMemory.writeWorkspaceFile(workspace, "runs/index.json", JSON.stringify(index, null, 2) + "\n")

      return { title: "Recon checkpoint saved", output: ["Target: " + workspace.targetURL, "Phase: " + phase, "Status: " + run.phases[phase].status, "Manifest: " + absolutePath, "Current phase: " + (run.currentPhase ?? "none"), ...(run.phases[phase].artifacts?.length ? ["Artifacts: " + run.phases[phase].artifacts.join(", ")] : []), ...(run.phases[phase].reason ? ["Reason: " + run.phases[phase].reason] : [])].join("\n"), metadata: { saved: true, target_id: workspace.id, run_id: runID, phase, status: run.phases[phase].status, manifest: absolutePath, current_phase: run.currentPhase } }
    } catch (error) {
      return { title: "Recon checkpoint failed", output: error instanceof Error ? error.message : String(error), metadata: { saved: false, error: true } }
    }
  },
})

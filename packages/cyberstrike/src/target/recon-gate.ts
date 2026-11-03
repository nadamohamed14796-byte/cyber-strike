import fs from "node:fs/promises"
import path from "node:path"
import { createHash } from "node:crypto"
import { TargetMemory, type TargetScope, type Workspace } from "./index"

export const RECON_PHASES = [
  "scope_validation",
  "workspace_setup",
  "asset_discovery",
  "live_hosts_ports",
  "url_collection",
  "javascript_analysis",
  "parameter_discovery",
  "directory_fuzzing",
  "endpoint_inventory",
  "parameter_fuzzing",
  "vulnerability_testing",
  "reporting",
] as const

export type ReconPhase = typeof RECON_PHASES[number]
export type ReconPhaseStatus = "pending" | "running" | "complete" | "partial" | "blocked" | "failed" | "unavailable" | "deferred"

export type ReconPhaseRecord = {
  status: ReconPhaseStatus
  startedAt?: string
  finishedAt?: string
  summary?: string
  reason?: string
  counts?: Record<string, number>
  artifacts?: string[]
  /** Exact starting asset whose persisted scope check justified this checkpoint. */
  scopeValidationTarget?: string
  /** Fingerprint of the authorization rules that were validated for this run. */
  scopeFingerprint?: string
}

export type ReconRunManifest = {
  schemaVersion: 1
  /** Ordered lifecycle version; missing indicates a pre-evidence-first checkpoint. */
  phaseOrderVersion?: number
  targetURL: string
  targetID: string
  sessionID: string
  createdAt: string
  updatedAt: string
  currentPhase: ReconPhase | null
  phases: Record<ReconPhase, ReconPhaseRecord>
}

type ScopeFingerprintInput = Pick<TargetScope,
  "targetURL" | "status" | "scopeItems" | "excludedItems" | "authorizationSource" | "authorizationReference"
>

/** Stable fingerprint of the effective authorization chain; item ordering alone is not a change. */
export function reconScopeFingerprint(input: ScopeFingerprintInput | readonly ScopeFingerprintInput[]): string {
  const scopes: readonly ScopeFingerprintInput[] = Array.isArray(input)
    ? input as readonly ScopeFingerprintInput[]
    : [input as ScopeFingerprintInput]
  const canonical = scopes.map((scope) => ({
    targetURL: scope.targetURL,
    status: scope.status,
    scopeItems: [...scope.scopeItems].sort(),
    excludedItems: [...scope.excludedItems].sort(),
    authorizationSource: scope.authorizationSource,
    authorizationReference: scope.authorizationReference,
  }))
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex")
}


/** Resolve the complete persisted authorization chain for an asset under one canonical program root. */
export async function reconScopeFingerprintForWorkspace(start: Workspace, expectedRootID: string): Promise<string> {
  const byID = new Map(TargetMemory.list().map((item) => [item.id, item]))
  const visited = new Set<string>()
  const scopes: TargetScope[] = []
  let current: Workspace | undefined = start
  let foundExpectedRoot = false
  while (current) {
    if (visited.has(current.id)) throw new Error("target workspace ancestry contains a cycle; scope validation cannot be trusted")
    visited.add(current.id)
    if (current.id === expectedRootID) foundExpectedRoot = true
    const scope = await TargetMemory.getScope(current.targetURL)
    if (!scope || scope.status !== "configured" || scope.scopeItems.length === 0) {
      throw new Error("workspace " + current.targetURL + " has no configured persisted scope")
    }
    scopes.push(scope)
    if (!current.parentTargetID) break
    const parent = byID.get(current.parentTargetID)
    if (!parent) throw new Error("parent target workspace is missing; refusing to weaken inherited scope")
    current = parent
  }
  if (!foundExpectedRoot || current?.id !== expectedRootID) {
    throw new Error("the starting asset resolves to a different canonical program workspace; re-check it under the current root")
  }
  return reconScopeFingerprint(scopes)
}

export function reconRunID(targetID: string): string {
  return createHash("sha256").update(targetID).digest("hex").slice(0, 20)
}

export function initialReconRun(targetURL: string, targetID: string, sessionID: string): ReconRunManifest {
  const phases = Object.fromEntries(RECON_PHASES.map((phase) => [phase, { status: "pending" as const }])) as Record<ReconPhase, ReconPhaseRecord>
  const now = new Date().toISOString()
  return { schemaVersion: 1, phaseOrderVersion: 3, targetURL, targetID, sessionID, createdAt: now, updatedAt: now, currentPhase: null, phases }
}

export function parseReconRun(raw: string, workspaceID: string, targetURL: string): ReconRunManifest {
  const parsed = JSON.parse(raw) as ReconRunManifest
  const phases = parsed?.phases as Partial<Record<ReconPhase, ReconPhaseRecord>> | undefined
  const validStatus = (record: ReconPhaseRecord | undefined) =>
    !!record && ["pending", "running", "complete", "partial", "blocked", "failed", "unavailable", "deferred"].includes(record.status)
  // Three phases were added as explicit checkpoints. Older manifests are migrated
  // in memory, and downstream completion is invalidated from the earliest missing phase.
  const introducedPhases = ["directory_fuzzing", "parameter_discovery", "parameter_fuzzing"] as const
  const stableLegacyPhases = RECON_PHASES.filter((phase) => !(introducedPhases as readonly string[]).includes(phase))
  const hasLegacyPhaseSet = !!phases && stableLegacyPhases.every((phase) => validStatus(phases[phase]))
  const invalidIntroducedPhase = !!phases && introducedPhases.some((phase) =>
    Object.prototype.hasOwnProperty.call(phases, phase) && !validStatus(phases[phase]),
  )
  if (
    parsed?.schemaVersion !== 1 ||
    parsed.targetID !== workspaceID ||
    parsed.targetURL !== targetURL ||
    typeof parsed.sessionID !== "string" ||
    !hasLegacyPhaseSet ||
    invalidIntroducedPhase
  ) throw new Error("Recon run manifest has invalid identity or schema; refusing to overwrite it.")
  if (!phases) throw new Error("Recon run manifest has no phase records; refusing to overwrite it.")

  const missingPhases = introducedPhases.filter((phase) => !Object.prototype.hasOwnProperty.call(phases, phase))
  const needsPhaseOrderMigration = parsed.phaseOrderVersion !== 3
  if (missingPhases.length || needsPhaseOrderMigration) {
    for (const phase of missingPhases) {
      phases[phase] = {
        status: "pending",
        reason: "New required recon phase: " + phase + ". Existing downstream completion must be revalidated.",
      }
    }

    // The evidence-first lifecycle analyzes JavaScript before parameter and path
    // discovery. Old manifests may claim those later phases are complete in the
    // previous order, so preserve their artifacts but reopen from JavaScript.
    const earliestMissing = missingPhases.length
      ? Math.min(...missingPhases.map((phase) => RECON_PHASES.indexOf(phase)))
      : RECON_PHASES.length
    const revalidateFrom = needsPhaseOrderMigration || missingPhases.includes("directory_fuzzing")
      ? RECON_PHASES.indexOf("javascript_analysis")
      : earliestMissing + 1
    const resumeFrom = needsPhaseOrderMigration || missingPhases.includes("directory_fuzzing")
      ? RECON_PHASES.indexOf("javascript_analysis")
      : earliestMissing
    const migrationReason = needsPhaseOrderMigration
      ? "Re-run required after recon phase order migrated to evidence-first version 3."
      : "Re-run required after adding earlier recon phase(s): " + missingPhases.join(", ") + "."
    for (const phase of RECON_PHASES.slice(revalidateFrom)) {
      const previous = phases[phase]
      if (previous && previous.status !== "pending") {
        phases[phase] = {
          ...previous,
          status: "pending",
          startedAt: undefined,
          finishedAt: undefined,
          reason: migrationReason,
        }
      }
    }
    parsed.currentPhase = RECON_PHASES[resumeFrom] ?? null
    parsed.updatedAt = new Date().toISOString()
  }
  parsed.phaseOrderVersion = 3
  parsed.phases = phases as Record<ReconPhase, ReconPhaseRecord>
  return parsed
}

function terminal(status: ReconPhaseStatus): boolean {
  // Failed/blocked phases need a materially changed retry or explicit partial
  // handoff. Their evidence remains preserved, but downstream completion waits.
  return status === "complete" || status === "partial" || status === "unavailable" || status === "deferred"
}

/** Reset downstream checkpoints when a previously deferred phase is explicitly reopened. */
export function invalidateReconDownstreamPhases(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
  reason: string,
): ReconPhase[] {
  const index = RECON_PHASES.indexOf(phase)
  const downstream = RECON_PHASES.slice(index + 1)
  for (const item of downstream) phases[item] = { status: "pending", reason }
  return downstream
}

/** Pure prerequisite check shared by the runtime gate and unit tests. */
export function unresolvedReconPrerequisites(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): ReconPhase[] {
  const index = RECON_PHASES.indexOf(phase)
  const earlier = RECON_PHASES.slice(0, index)
  const unresolved: ReconPhase[] = []

  // Persisted authorization and the canonical workspace are hard prerequisites.
  if (phase !== "scope_validation" && phases.scope_validation.status !== "complete") {
    unresolved.push("scope_validation")
  }
  if (phase !== "scope_validation" && phase !== "workspace_setup" &&
      phases.workspace_setup.status !== "complete") {
    unresolved.push("workspace_setup")
  }

  for (const prior of earlier) {
    if (prior === "scope_validation" || prior === "workspace_setup") continue
    // Parameter fuzzing and vulnerability testing are optional; a pending phase
    // means the user did not request it. Once explicitly started, it must resolve
    // before reporting can close.
    if (phase === "reporting" &&
        (prior === "parameter_fuzzing" || prior === "vulnerability_testing") &&
        phases[prior].status === "pending") continue
    if (phase === "vulnerability_testing" && prior === "parameter_fuzzing" &&
        phases[prior].status === "pending") continue

    // Both active-testing phases require a verified endpoint inventory, not merely
    // a failed/unavailable marker for the inventory phase.
    if ((phase === "parameter_fuzzing" || phase === "vulnerability_testing") &&
        prior === "endpoint_inventory") {
      if (phases.endpoint_inventory.status !== "complete") unresolved.push("endpoint_inventory")
      continue
    }
    if (!terminal(phases[prior].status)) unresolved.push(prior)
  }
  return [...new Set(unresolved)]
}

/** Decide whether a checkpoint phase may begin after earlier phases are verified or handed off. */
export function reconPhaseStartDecision(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): { allowed: boolean; reason: string; unresolved: ReconPhase[] } {
  const unresolved = unresolvedReconPrerequisites(phase, phases)
  if (unresolved.length > 0) {
    return {
      allowed: false,
      reason: "Checklist is waiting for earlier phase(s) to be resolved: " +
        unresolved.map((item) => item + "=" + phases[item].status).join(", "),
      unresolved,
    }
  }
  return { allowed: true, reason: "earlier phases are resolved and hard prerequisites passed", unresolved: [] }
}

/** Pure execution decision used by the runtime gate and unit tests.
 *
 * The checkpoint owns workflow order and prerequisites, not a phase-to-tool
 * allowlist. The phase inferred from a CLI name or tool wrapper is advisory.
 * Normal recon/support tools may contribute to the single active checkpoint;
 * actions classified as active testing still require the matching explicit
 * checkpoint to be active after endpoint inventory is complete.
 */
export function reconPhaseExecutionDecision(
  requiredPhase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): { allowed: boolean; reason: string } {
  // Ordinary recon tools remain independent of checkpoint labels. Only explicit
  // active-testing phases require a running opt-in checkpoint.
  if (requiredPhase !== "parameter_fuzzing" && requiredPhase !== "vulnerability_testing") {
    return {
      allowed: true,
      reason: "ordinary reconnaissance tools are not restricted by checkpoint phase or prerequisite status",
    }
  }

  const label = requiredPhase === "vulnerability_testing" ? "Vulnerability testing" : "Parameter fuzzing"
  if (phases[requiredPhase].status !== "running") {
    return {
      allowed: false,
      reason: label + " is opt-in; explicitly begin " + requiredPhase + " only after endpoint_inventory is complete and the user has requested active testing.",
    }
  }
  const unresolved = unresolvedReconPrerequisites(requiredPhase, phases)
  if (unresolved.length > 0) {
    return {
      allowed: false,
      reason: label + " requires earlier phases to be complete or explicitly handed off: " +
        unresolved.map((item) => item + "=" + phases[item].status).join(", "),
    }
  }
  return { allowed: true, reason: "explicit " + requiredPhase + " checkpoint and prerequisites passed" }
}

/** Checkpoint gate for explicit active-testing tools.
 *
 * Ordinary recon callers must enforce persisted scope for each concrete request;
 * their availability does not depend on a checkpoint file or phase status.
 */
export async function reconPhaseGate(
  workspace: Workspace,
  requiredPhase: ReconPhase,
): Promise<{ allowed: boolean; reason: string; manifestPath: string }> {
  const byID = new Map(TargetMemory.list().map((item) => [item.id, item]))
  let root = workspace
  const seen = new Set<string>()
  while (root.parentTargetID && !seen.has(root.id)) {
    seen.add(root.id)
    const parent = byID.get(root.parentTargetID)
    if (!parent) break
    root = parent
  }
  const manifestPath = path.join(root.workspacePath, "runs", "recon-" + reconRunID(root.id) + ".json")

  // Request-level scope checks happen in each caller before this gate. Ordinary
  // recon collectors do not require a phase manifest; active-testing phases do.
  if (requiredPhase !== "parameter_fuzzing" && requiredPhase !== "vulnerability_testing") {
    return {
      allowed: true,
      reason: "ordinary recon tools are not blocked by checkpoint status; request-level scope checks remain required",
      manifestPath,
    }
  }

  let run: ReconRunManifest
  try {
    run = parseReconRun(await fs.readFile(manifestPath, "utf-8"), root.id, root.targetURL)
  } catch (error) {
    return {
      allowed: false,
      reason: "No valid recon checkpoint manifest exists for the root target (" + (error instanceof Error ? error.message : String(error)) + ").",
      manifestPath,
    }
  }
  if (run.phases.scope_validation.status !== "complete") {
    return {
      allowed: false,
      reason: "Target scope validation must be completed before active testing can run. Ordinary reconnaissance tools are not blocked by this testing checkpoint.",
      manifestPath,
    }
  }
  if (run.phases[requiredPhase].status !== "running") {
    return {
      allowed: false,
      reason: requiredPhase + " is opt-in. The recon handoff leaves active-testing phases deferred; explicitly begin " + requiredPhase + " only after the user requests active testing.",
      manifestPath,
    }
  }

  // A previously completed scope checkpoint is not a permanent authorization
  // grant. Revalidate the exact starting asset and the complete inherited policy
  // chain immediately before active testing, even when that asset still matches
  // the edited policy. Otherwise stale endpoint inventories could outlive a scope
  // change that did not happen to exclude the original seed.
  const scopeValidation = run.phases.scope_validation
  if (!scopeValidation.scopeValidationTarget || !scopeValidation.scopeFingerprint) {
    return {
      allowed: false,
      reason: "The scope checkpoint has no persisted starting-asset fingerprint. Run recon_checkpoint status to migrate/revalidate it, then rebuild any invalidated downstream inventory before active testing.",
      manifestPath,
    }
  }
  try {
    const validationTarget = new URL(scopeValidation.scopeValidationTarget)
    if ((validationTarget.protocol !== "http:" && validationTarget.protocol !== "https:") || validationTarget.username || validationTarget.password) {
      throw new Error("saved scope-validation target is not a credential-free HTTP(S) URL")
    }
    const scopeDecision = await TargetMemory.checkURLScope(validationTarget.href)
    if (!scopeDecision.allowed || !scopeDecision.workspace) {
      return {
        allowed: false,
        reason: "The saved scope-validation starting asset is no longer authorized: " + scopeDecision.reason + ". Revalidate scope and rebuild downstream inventory before active testing.",
        manifestPath,
      }
    }
    const currentFingerprint = await reconScopeFingerprintForWorkspace(scopeDecision.workspace, root.id)
    if (currentFingerprint !== scopeValidation.scopeFingerprint) {
      return {
        allowed: false,
        reason: "The persisted scope or exclusions changed after recon validation. Re-run recon_checkpoint status, revalidate the scope, and rebuild downstream artifacts including endpoint_inventory before active testing.",
        manifestPath,
      }
    }
  } catch (error) {
    return {
      allowed: false,
      reason: "The current authorization chain could not be revalidated; active testing is blocked until scope is repaired: " + (error instanceof Error ? error.message : String(error)),
      manifestPath,
    }
  }

  const decision = reconPhaseExecutionDecision(requiredPhase, run.phases)
  return { ...decision, manifestPath }
}

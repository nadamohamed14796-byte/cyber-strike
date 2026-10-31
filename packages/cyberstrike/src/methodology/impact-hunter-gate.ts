import { Session } from "../session"
import { Request } from "../session/request"
import { Vulnerability } from "../session/vulnerability"
import { TargetMemory } from "../target"
import { FindingValidation, hasCompleteConfirmedValidation } from "./finding-validation"
import { VerificationLedger } from "../session/verification-ledger"

export type ImpactHunterMode = "proof_gap" | "approved_impact"

export interface ImpactHunterGateResult {
  allowed: boolean
  mode: ImpactHunterMode
  reason?: string
  requestIDs: string[]
  baselineValidationID?: string
}

function normalizePath(value: string): string {
  try {
    return new URL(value, "https://cyberstrike.invalid").pathname.replace(new RegExp("/+$"), "") || "/"
  } catch {
    const path = value.split(/[?#]/, 1)[0]?.trim() ?? ""
    return (path.startsWith("/") ? path : "/" + path).replace(new RegExp("/+$"), "") || "/"
  }
}

function endpointParts(endpoint: string): { method?: string; origin?: string; path: string } {
  const trimmed = endpoint.trim()
  const separator = trimmed.indexOf(" ")
  const methodCandidate = separator > 0 ? trimmed.slice(0, separator).toUpperCase() : undefined
  const supportedMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
  const methodMatch = methodCandidate && supportedMethods.includes(methodCandidate)
    ? { method: methodCandidate, url: trimmed.slice(separator + 1).trim() }
    : undefined
  const raw = (methodMatch?.url ?? endpoint).trim()
  try {
    const url = new URL(raw)
    return {
      method: methodMatch?.method,
      origin: url.origin,
      path: normalizePath(url.pathname),
    }
  } catch {
    return {
      method: methodMatch?.method,
      path: normalizePath(raw),
    }
  }
}

/**
 * Resolve request evidence using the exact request identity carried by the
 * calling agent first, then all requests whose method/origin/path match the
 * persisted finding. Do not guess from host-only similarity.
 */
export function supportingRequestIDs(
  finding: Vulnerability.Info,
  sessionID: string,
  preferredRequestIDs: readonly string[] = [],
): string[] {
  const requests = Request.get(Session.root(sessionID))
  const known = new Map(requests.map((request) => [request.id, request]))
  if (!finding.endpoint?.trim()) {
    return [...new Set(preferredRequestIDs.filter((id) => known.has(id)))]
  }

  const expected = endpointParts(finding.endpoint)
  const matchesEndpoint = (request: Request.Info) => {
    if (expected.method && request.method !== expected.method) return false
    const actualPath = normalizePath(request.normalized_path)
    const canonicalPath = request.canonical_path ? normalizePath(request.canonical_path) : undefined
    if (actualPath !== expected.path && canonicalPath !== expected.path) return false
    if (expected.origin) {
      const actualOrigin = request.origin ?? (
        request.scheme && request.host
          ? request.scheme + "://" + request.host + (request.port ? ":" + request.port : "")
          : undefined
      )
      if (!actualOrigin) return false
      try {
        if (new URL(actualOrigin).origin !== expected.origin) return false
      } catch {
        return false
      }
    }
    return true
  }

  // A caller-supplied Request ID is a useful priority hint, not an evidence
  // bypass. It must still match the finding's exact method, path, and origin.
  const preferred = preferredRequestIDs.filter((id) => {
    const request = known.get(id)
    return Boolean(request && matchesEndpoint(request))
  })
  const matching = requests
    .filter(matchesEndpoint)
    .sort((a, b) => b.time.updated - a.time.updated)
    .map((request) => request.id)

  return [...new Set([...preferred, ...matching])]
}

/**
 * Evaluate the exact same durable prerequisites whenever an agent or tool
 * launches Impact Hunter. proof_gap accepts any NEW, untriaged vulnerability
 * candidate regardless of weakness class; INFO observations are also eligible for
 * chain investigation even when their own PoC is complete. Both paths require target
 * attribution, an exact scoped endpoint, and a matching request or source file/line anchor.
 */
export function evaluateImpactHunterGate(input: {
  finding: Vulnerability.Info
  sessionID: string
  mode: ImpactHunterMode
  preferredRequestIDs?: readonly string[]
}): ImpactHunterGateResult {
  const { finding, mode } = input
  const sessionID = Session.root(input.sessionID)
  const requestIDs = supportingRequestIDs(finding, sessionID, input.preferredRequestIDs)

  if (!finding.id) {
    return { allowed: false, mode, reason: "finding has no persisted ID", requestIDs }
  }

  if (mode === "proof_gap") {
    if (finding.status !== "new") {
      return { allowed: false, mode, reason: "proof-gap investigation accepts only a NEW, untriaged candidate", requestIDs }
    }
    // The candidate marker is class-agnostic: it records that the reporter has
    // not supplied a complete, reviewable PoC. Never infer completeness from
    // baseline/request/response notes alone.
    const informationalLead = (finding.candidate ?? finding.severity) === "info"
    if (!informationalLead && finding.candidate == null && finding.poc?.trim() && finding.steps_to_reproduce?.trim()) {
      return { allowed: false, mode, reason: "finding already contains a complete-looking PoC and is not marked execution-unconfirmed", requestIDs }
    }
    if (!finding.target_id || !TargetMemory.list().some((workspace) => workspace.id === finding.target_id)) {
      return { allowed: false, mode, reason: "candidate is not linked to an existing target workspace", requestIDs }
    }
    if (!finding.endpoint?.trim()) {
      return { allowed: false, mode, reason: "candidate has no exact affected endpoint", requestIDs }
    }
    const sourceAnchor = Boolean(finding.file?.trim() && Number.isInteger(finding.line_start) && finding.line_start! > 0)
    if (!requestIDs.length && !sourceAnchor) {
      return { allowed: false, mode, reason: "candidate has no matching captured request or source file/line evidence anchor", requestIDs }
    }
    return { allowed: true, mode, requestIDs }
  }

  if (finding.status !== "approved") {
    return { allowed: false, mode, reason: "impact escalation accepts only an explicitly approved finding", requestIDs }
  }
  const latestValidation = FindingValidation.history({
    sessionID,
    vulnerabilityID: finding.id,
    limit: 1,
  })[0]
  if (!hasCompleteConfirmedValidation(latestValidation)) {
    return { allowed: false, mode, reason: "latest validation does not contain ten complete evidence-backed checks", requestIDs }
  }
  const durableConfirmed = VerificationLedger.list({
    sessionID,
    hypothesisKey: "finding:" + finding.id,
  }).some((attempt) =>
    attempt.outcome === "confirmed" &&
    attempt.validConditions &&
    Boolean(attempt.evidenceRef?.trim()) &&
    attempt.timeCreated <= latestValidation!.time_created,
  )
  if (!durableConfirmed) {
    return { allowed: false, mode, reason: "durable verification ledger has no evidence-backed CONFIRMED result for finding:" + finding.id, requestIDs }
  }

  return {
    allowed: true,
    mode,
    requestIDs,
    baselineValidationID: latestValidation!.id,
  }
}

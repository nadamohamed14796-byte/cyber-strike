export type ResumableTaskSession = {
  id: string
  parentID?: string | null
}

export type TaskRequestContextCandidate = {
  id: string
  status: string
  time: { updated: number }
}

export type TaskRequestContextSelection<T> = {
  request?: T
  reason?: "request_not_found" | "ambiguous_processing_requests"
}

const PROXY_TESTER_METHODOLOGY_PHASE = {
  "proxy-tester-idor": "authorization_testing",
  "proxy-tester-authz": "authorization_testing",
  "proxy-tester-authn": "authentication_testing",
  "proxy-tester-injection": "input_validation",
  "proxy-tester-file-attacks": "input_validation",
  "proxy-tester-business-logic": "business_logic",
  "proxy-tester-mass-assignment": "api_security",
  "proxy-tester-ssrf": "api_security",
  "proxy-tester-llm": "api_security",
} as const

/**
 * Active proxy specialists must not be spawned while their persisted
 * methodology phase is blocked. The analyzer is deliberately not part of this
 * map: passive request/architecture analysis remains available while active
 * testing prerequisites are incomplete.
 */
export function proxyTesterMethodologyPhase(agentID: string): string | undefined {
  return PROXY_TESTER_METHODOLOGY_PHASE[agentID as keyof typeof PROXY_TESTER_METHODOLOGY_PHASE]
}

/**
 * The persistent Extension Proxy must be able to dispatch an evidence-selected
 * specialist for passive triage even while the Main Recon methodology has not
 * initialized that active-testing phase. Scope/authorization checks remain in
 * the specialist tools; this only disables the premature Task-spawn gate.
 */
export function shouldEnforceProxyTesterMethodology(callerAgentID?: string): boolean {
  return callerAgentID !== "proxy-agent"
}

export function proxyTesterMethodologyBlock(
  agentID: string,
  phases: readonly { id: string; status: string; blockReason?: string }[],
): { phase: string; reason: string } | undefined {
  const phaseID = proxyTesterMethodologyPhase(agentID)
  if (!phaseID) return undefined
  const phase = phases.find((item) => item.id === phaseID)
  if (!phase) {
    return {
      phase: phaseID,
      reason: "This testing phase is not applicable to the current target scope or has not been initialized.",
    }
  }
  if (phase.status !== "blocked") return undefined
  return {
    phase: phaseID,
    reason: phase.blockReason || "Upstream methodology prerequisites are incomplete.",
  }
}

/**
 * Recover the exact captured request ID from a session's persisted user prompt.
 * Read only known identity sections so an unrelated mention of "Request ID"
 * elsewhere in free-form text cannot bind a nested task to the wrong capture.
 */
export function requestIDFromPromptText(text: string): string | undefined {
  for (const heading of ["## Request Task Identity", "## Current request"]) {
    const start = text.indexOf(heading)
    if (start < 0) continue
    const remainder = text.slice(start)
    const nextHeading = remainder.indexOf("\n## ", heading.length)
    const section = nextHeading < 0 ? remainder : remainder.slice(0, nextHeading)
    const match = section.match(/^\s*-\s*(?:Request ID|request_id):\s*([^\r\n]+)\s*$/im)
    if (match?.[1]) return match[1].trim()
  }
  return undefined
}

/**
 * Resolve the active request from a persistent broker transcript. Follow-up
 * messages may omit an identity block, so walk backward to the most recent
 * user turn that actually carries a trusted request identity section.
 */
export function requestIDFromRecentPromptTexts(texts: readonly string[]): string | undefined {
  for (let index = texts.length - 1; index >= 0; index--) {
    const requestID = requestIDFromPromptText(texts[index] ?? "")
    if (requestID) return requestID
  }
  return undefined
}


/**
 * Extract request identities explicitly attached to a task prompt. The primary
 * orchestrator often places the ID in a structured Request ID field in the
 * delegated prompt, while only Proxy Agent sessions previously inferred it from
 * their transcript. Keep this parser narrow: prose mentions do not bind a task.
 */
export function requestIDsFromTaskPrompt(text: string): string[] {
  const matches = text.matchAll(
    /^\s*(?:[-*]\s*)?(?:\*\*)?(?:Request ID|request_id)(?:\*\*)?\s*:\s*(req[-_][A-Za-z0-9_-]+)\s*$/gim,
  )
  return [...new Set(Array.from(matches, (match) => match[1]!).filter(Boolean))]
}

/**
 * Resolve request identity from the caller transcript when it is a request-aware
 * orchestrator. The Proxy Agent needs this in both standalone (mode=all) and
 * delegated (subagent) operation; ordinary primary agents must not scan their
 * unrelated chat history for captured-request markers.
 */
export function shouldInferSessionRequestID(caller?: {
  name?: string
  mode?: "subagent" | "primary" | "all"
}): boolean {
  return caller?.mode === "subagent" || caller?.name === "proxy-agent"
}

/**
 * Select request context without silently attaching a task to unrelated traffic.
 * An explicit ID is authoritative; otherwise only one in-flight request is safe
 * to infer. Multiple in-flight rows are ambiguous and must be resolved by ID.
 */
export function selectTaskRequestContext<T extends TaskRequestContextCandidate>(
  requests: readonly T[],
  requestedRequestID?: string,
): TaskRequestContextSelection<T> {
  if (requestedRequestID !== undefined) {
    const request = requests.find((item) => item.id === requestedRequestID)
    return request ? { request } : { reason: "request_not_found" }
  }

  const processing = requests.filter((item) => item.status === "processing")
  if (processing.length === 1) return { request: processing[0] }
  if (processing.length > 1) return { reason: "ambiguous_processing_requests" }

  // Request.get() is intake-ID ordered. Keep the fallback FIFO as well:
  // when the broker is between turns, the oldest queued request is next.
  // Falling back to the most recently updated row here selected the newest
  // capture (for example request 10) and skipped the earlier queued work.
  const oldestQueued = requests
    .filter((item) => item.status === "queued")
    .sort((a, b) => a.id.localeCompare(b.id))[0]
  if (oldestQueued) return { request: oldestQueued }

  // No pending work remains; an interactive follow-up may use the latest
  // completed request as its context.
  const latestCompleted = [...requests].sort((a, b) => b.time.updated - a.time.updated)[0]
  return latestCompleted ? { request: latestCompleted } : {}
}

/**
 * A subtask can only be resumed from the parent session that created it.
 * Prevents a caller-supplied task ID from attaching unrelated session history.
 */
export function assertTaskResumeScope(task: ResumableTaskSession, parentSessionID: string): void {
  if (task.parentID !== parentSessionID) {
    throw new Error("Cannot resume task " + task.id + ": it does not belong to the current parent session.")
  }
}

/** Narrow permission bypass for background Impact Hunter escalation only. */
export function isInternalImpactHandoff(input: {
  subagentType: string
  background?: boolean
  caller?: string
  callerMode?: "subagent" | "primary" | "all"
}) {
  return (
    input.subagentType === "impact-hunter" &&
    input.background === true &&
    input.caller !== undefined &&
    input.caller !== "impact-hunter" &&
    input.callerMode !== undefined
  )
}

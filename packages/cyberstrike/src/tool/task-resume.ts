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

  const latest = [...requests].sort((a, b) => b.time.updated - a.time.updated)[0]
  return latest ? { request: latest } : {}
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

/** Narrow permission bypass for in-scope, non-blocking Impact Hunter escalation only. */
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
    input.callerMode === "subagent"
  )
}

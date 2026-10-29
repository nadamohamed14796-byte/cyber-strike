export type ResumableTaskSession = {
  id: string
  parentID?: string | null
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

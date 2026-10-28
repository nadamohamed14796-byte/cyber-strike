import type { PromptInfo } from "./history"

/**
 * A failed submit must not overwrite a new draft or place an old draft in a
 * different session's editor. Restore only when the current editor is empty
 * and still points at the original submission's session.
 */
export function shouldRestoreFailedSubmission(
  current: PromptInfo,
  activeSessionID: string | undefined,
  submittedSessionID: string,
): boolean {
  return (
    current.input === "" &&
    current.parts.length === 0 &&
    (activeSessionID === undefined || activeSessionID === submittedSessionID)
  )
}

export function submissionFailureMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error)
  return message.trim().slice(0, 240) || "No error details were returned."
}

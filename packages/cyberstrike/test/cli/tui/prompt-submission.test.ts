import { describe, expect, test } from "bun:test"
import { shouldRestoreFailedSubmission, submissionFailureMessage } from "../../../../src/cli/cmd/tui/component/prompt/submission"
import type { PromptInfo } from "../../../../src/cli/cmd/tui/component/prompt/history"

const empty: PromptInfo = { input: "", parts: [] }
const submitted = "session-original"

describe("failed TUI prompt submission recovery", () => {
  test("restores a failed prompt when the editor is empty in the same session", () => {
    expect(shouldRestoreFailedSubmission(empty, submitted, submitted)).toBe(true)
  })

  test("restores a failed first prompt before the new session route is active", () => {
    expect(shouldRestoreFailedSubmission(empty, undefined, submitted)).toBe(true)
  })

  test("does not overwrite text typed while the request was in flight", () => {
    expect(shouldRestoreFailedSubmission({ input: "new draft", parts: [] }, submitted, submitted)).toBe(false)
    expect(shouldRestoreFailedSubmission({ input: " ", parts: [] }, submitted, submitted)).toBe(false)
  })

  test("does not overwrite attachments or pasted content in a newer draft", () => {
    expect(shouldRestoreFailedSubmission({ input: "", parts: [{ type: "agent", name: "reviewer" } as any] }, submitted, submitted)).toBe(false)
  })

  test("stashes instead of restoring into a different active session", () => {
    expect(shouldRestoreFailedSubmission(empty, "session-other", submitted)).toBe(false)
  })

  test("formats thrown errors without leaking unbounded text into a toast", () => {
    expect(submissionFailureMessage(new Error("request rejected"))).toBe("request rejected")
    expect(submissionFailureMessage("")).toBe("No error details were returned.")
    expect(submissionFailureMessage(new Error("x".repeat(300)))).toHaveLength(240)
  })
})

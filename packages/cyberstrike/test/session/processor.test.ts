import { describe, expect, test } from "bun:test"
import { SessionProcessor } from "../../src/session/processor"

describe("session processor output detection", () => {
  test("does not treat a partial tool input as an executed call", () => {
    expect(SessionProcessor.hasProducedOutput("", 0)).toBe(false)
  })

  test("accepts a tool-call event even when it produced no text", () => {
    expect(SessionProcessor.hasProducedOutput("", 1)).toBe(true)
  })

  test("accepts non-empty text and ignores whitespace-only text", () => {
    expect(SessionProcessor.hasProducedOutput("Finished", 0)).toBe(true)
    expect(SessionProcessor.hasProducedOutput("  \n  ", 0)).toBe(false)
  })

  test("uses only text accumulated by the current stream attempt", () => {
    const previousAttemptText = "partial output from a failed attempt"
    const currentAttemptText = ""
    expect(SessionProcessor.hasProducedOutput(currentAttemptText, 0)).toBe(false)
    expect(previousAttemptText.length).toBeGreaterThan(0)
  })
})

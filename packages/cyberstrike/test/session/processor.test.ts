import { describe, expect, test } from "bun:test"
import { SessionProcessor } from "../../src/session/processor"
import { MessageV2 } from "../../src/session/message-v2"

describe("session processor output detection", () => {
  test("does not treat an unfinished tool input as an executed tool call", () => {
    const pendingToolPart = { type: "tool" } as unknown as MessageV2.Part
    expect(SessionProcessor.hasProducedOutput([pendingToolPart], 0)).toBe(false)
  })

  test("accepts a completed tool-call event even when it produced no text", () => {
    expect(SessionProcessor.hasProducedOutput([], 1)).toBe(true)
  })

  test("accepts non-empty text and ignores whitespace-only text", () => {
    const textPart = (text: string) => ({ type: "text", text }) as unknown as MessageV2.Part
    expect(SessionProcessor.hasProducedOutput([textPart("Finished")], 0)).toBe(true)
    expect(SessionProcessor.hasProducedOutput([textPart("  \n  ")], 0)).toBe(false)
  })
})

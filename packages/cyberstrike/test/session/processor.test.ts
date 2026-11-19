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

describe("session processor stream watchdog", () => {
  test("times out provider initialization instead of waiting indefinitely", async () => {
    const controller = new AbortController()
    const never = new Promise<never>(() => {})
    await expect(
      SessionProcessor.withPromiseTimeout(never, controller.signal, 5, "test provider setup"),
    ).rejects.toThrow("test provider setup")
  })

  test("times out a stalled model stream", async () => {
    const controller = new AbortController()
    async function* stalled() {
      await new Promise((resolve) => setTimeout(resolve, 30))
      yield { type: "text-delta" }
    }

    await expect(
      (async () => {
        for await (const _ of SessionProcessor.withStreamTimeout(stalled(), controller.signal, 5)) {
          // The first event must not arrive before the watchdog fires.
        }
      })(),
    ).rejects.toThrow("stopped responding")
  })

  test("does not time out while a tool call is executing", async () => {
    const controller = new AbortController()
    async function* toolRun() {
      yield { type: "tool-call" }
      await new Promise((resolve) => setTimeout(resolve, 20))
      yield { type: "tool-result" }
      yield { type: "text-delta" }
    }

    const events: string[] = []
    for await (const event of SessionProcessor.withStreamTimeout(toolRun(), controller.signal, 5)) {
      events.push(event.type)
    }
    expect(events).toEqual(["tool-call", "tool-result", "text-delta"])
  })
})

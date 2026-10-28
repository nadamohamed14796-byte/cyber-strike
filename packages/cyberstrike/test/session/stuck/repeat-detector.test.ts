import { describe, expect, test } from "bun:test"
import { EmptyContinuationDetector, FailedToolStreakDetector, ReadOnlyRepeatDetector, RepeatDetector } from "../../../src/session/stuck/repeat-detector"

describe("RepeatDetector — cross-turn identical-call loop", () => {
  test("same signature reaching the limit across steps → nudge, then abort", () => {
    const d = new RepeatDetector(3)
    expect(d.observe(["a"])).toBe("ok") // count 1
    expect(d.observe(["a"])).toBe("ok") // count 2
    expect(d.observe(["a"])).toBe("nudge") // count 3 → first strike
    expect(d.observe(["a"])).toBe("abort") // count 4 → second strike
  })

  test("different args never collide (legitimate probing unaffected)", () => {
    const d = new RepeatDetector(3)
    expect(d.observe(["read::1"])).toBe("ok")
    expect(d.observe(["read::2"])).toBe("ok")
    expect(d.observe(["read::3"])).toBe("ok")
    expect(d.observe(["read::4"])).toBe("ok")
  })

  test("a within-step burst of identical sigs counts ONCE (cross-turn, not within-turn)", () => {
    const d = new RepeatDetector(3)
    expect(d.observe(["x", "x", "x"])).toBe("ok") // deduped → count 1 this step
    expect(d.observe(["x"])).toBe("ok") // count 2
    expect(d.observe(["x", "x"])).toBe("nudge") // count 3 across three STEPS → nudge
  })

  test("interleaved distinct signatures still count per-signature", () => {
    const d = new RepeatDetector(3)
    d.observe(["a", "b"]) // a=1 b=1
    d.observe(["a", "b"]) // a=2 b=2
    expect(d.observe(["a"])).toBe("nudge") // a=3
  })

  test("empty step is ok", () => {
    const d = new RepeatDetector(3)
    expect(d.observe([])).toBe("ok")
  })

  test("reset clears counts and the nudged latch", () => {
    const d = new RepeatDetector(3)
    d.observe(["a"])
    d.observe(["a"])
    expect(d.observe(["a"])).toBe("nudge")
    d.reset()
    expect(d.observe(["a"])).toBe("ok") // fresh
    expect(d.observe(["a"])).toBe("ok")
    expect(d.observe(["a"])).toBe("nudge") // nudge again (latch cleared), not abort
  })

  test("custom limit of 2", () => {
    const d = new RepeatDetector(2)
    expect(d.observe(["a"])).toBe("ok")
    expect(d.observe(["a"])).toBe("nudge")
    expect(d.observe(["a"])).toBe("abort")
  })
})


describe("ReadOnlyRepeatDetector — polling without progress", () => {
  test("nudges only after repeated identical reads without intervening progress", () => {
    const detector = new ReadOnlyRepeatDetector(3)
    const poll = [{ tool: "methodology_status", input: {} }]
    expect(detector.observe(poll)).toBe("ok")
    expect(detector.observe(poll)).toBe("ok")
    expect(detector.observe(poll)).toBe("nudge")
  })

  test("a meaningful work step resets repeated-poll detection", () => {
    const detector = new ReadOnlyRepeatDetector(3)
    const poll = [{ tool: "methodology_status", input: {} }]
    detector.observe(poll)
    detector.observe(poll)
    expect(detector.observe([{ tool: "bash", input: { command: "verify-results" }, succeeded: true }])).toBe("ok")
    expect(detector.observe(poll)).toBe("ok")
    expect(detector.observe(poll)).toBe("ok")
    expect(detector.observe(poll)).toBe("nudge")
  })



  test("failed tool calls do not reset read-only polling detection", () => {
    const detector = new ReadOnlyRepeatDetector(3)
    const poll = [{ tool: "methodology_status", input: {} }]
    detector.observe(poll)
    detector.observe(poll)
    expect(detector.observe([{ tool: "bash", input: { command: "blocked" }, succeeded: false }])).toBe("ok")
    expect(detector.observe(poll)).toBe("nudge")
  })

  test("different read-only arguments do not collide", () => {
    const detector = new ReadOnlyRepeatDetector(3)
    expect(detector.observe([{ tool: "read", input: { filePath: "a.ts" } }])).toBe("ok")
    expect(detector.observe([{ tool: "read", input: { filePath: "b.ts" } }])).toBe("ok")
    expect(detector.observe([{ tool: "read", input: { filePath: "c.ts" } }])).toBe("ok")
  })
})


describe("EmptyContinuationDetector — continuing turns without tool calls", () => {
  test("nudges after repeated empty continuations and aborts if the pattern continues", () => {
    const detector = new EmptyContinuationDetector(3)
    expect(detector.observe(0)).toBe("ok")
    expect(detector.observe(0)).toBe("ok")
    expect(detector.observe(0)).toBe("nudge")
    expect(detector.observe(0)).toBe("abort")
  })

  test("a tool-call turn resets the empty-continuation streak and latch", () => {
    const detector = new EmptyContinuationDetector(2)
    expect(detector.observe(0)).toBe("ok")
    expect(detector.observe(1)).toBe("ok")
    expect(detector.observe(0)).toBe("ok")
    expect(detector.observe(0)).toBe("nudge")
    detector.reset()
    expect(detector.observe(0)).toBe("ok")
  })
})


describe("FailedToolStreakDetector — distinct failed calls without progress", () => {
  test("nudges after a bounded streak of failed work calls even when arguments differ", () => {
    const detector = new FailedToolStreakDetector(3)
    expect(detector.observe([{ tool: "bash", input: { command: "bad-a" }, succeeded: false }])).toBe("ok")
    expect(detector.observe([{ tool: "bash", input: { command: "bad-b" }, succeeded: false }])).toBe("ok")
    expect(detector.observe([{ tool: "bash", input: { command: "bad-c" }, succeeded: false }])).toBe("nudge")
  })

  test("successful work resets the failed-call streak", () => {
    const detector = new FailedToolStreakDetector(3)
    detector.observe([{ tool: "bash", succeeded: false }])
    detector.observe([{ tool: "bash", succeeded: false }])
    expect(detector.observe([{ tool: "bash", succeeded: true }])).toBe("ok")
    expect(detector.observe([{ tool: "bash", succeeded: false }])).toBe("ok")
    expect(detector.observe([{ tool: "bash", succeeded: false }])).toBe("ok")
  })

  test("read-only and context calls do not count as failed target-work attempts", () => {
    const detector = new FailedToolStreakDetector(2)
    expect(detector.observe([{ tool: "methodology_status", succeeded: false }])).toBe("ok")
    expect(detector.observe([{ tool: "memory_read", succeeded: false }])).toBe("ok")
  })
})

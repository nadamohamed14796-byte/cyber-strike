import { describe, expect, test } from "bun:test"
import { EmptyContinuationDetector, FailedToolStreakDetector, ReadOnlyRepeatDetector, RepeatDetector, toolCallSucceeded } from "../../../src/session/stuck/repeat-detector"

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

  test("a different repeated signature gets its own recovery before terminal wrap-up", () => {
    const d = new RepeatDetector(3)
    d.observe(["a"])
    d.observe(["a"])
    expect(d.observe(["a"])).toBe("nudge")

    expect(d.observe(["b"])).toBe("ok")
    expect(d.observe(["b"])).toBe("ok")
    expect(d.observe(["b"])).toBe("nudge")
    expect(d.observe(["b"])).toBe("abort")
  })

  test("a mixed recovery step with a new action is not aborted immediately", () => {
    const d = new RepeatDetector(3)
    d.observe(["a"])
    d.observe(["a"])
    expect(d.observe(["a"])).toBe("nudge")
    expect(d.observe(["a", "b"])).toBe("nudge")
    expect(d.observe(["a"])).toBe("abort")
  })

  test("empty step is ok", () => {
    const d = new RepeatDetector(3)
    expect(d.observe([])).toBe("ok")
  })

  test("reset clears counts and per-signature recovery state", () => {
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

  test("a new method after the recovery nudge gets another chance", () => {
    const detector = new FailedToolStreakDetector(2)
    expect(detector.observe([{ tool: "bash", input: { command: "bad-a" }, succeeded: false }])).toBe("ok")
    expect(detector.observe([{ tool: "bash", input: { command: "bad-b" }, succeeded: false }])).toBe("nudge")
    expect(detector.observe([{ tool: "curl", input: { url: "new-method" }, succeeded: false }])).toBe("ok")
  })

  test("the same failed call after recovery is terminal", () => {
    const detector = new FailedToolStreakDetector(2)
    expect(detector.observe([{ tool: "bash", input: { command: "bad-a" }, succeeded: false }])).toBe("ok")
    expect(detector.observe([{ tool: "bash", input: { command: "bad-b" }, succeeded: false }])).toBe("nudge")
    expect(detector.observe([{ tool: "bash", input: { command: "bad-b" }, succeeded: false }])).toBe("abort")
  })

  test("read-only and context calls do not count as failed target-work attempts", () => {
    const detector = new FailedToolStreakDetector(2)
    expect(detector.observe([{ tool: "methodology_status", succeeded: false }])).toBe("ok")
    expect(detector.observe([{ tool: "memory_read", succeeded: false }])).toBe("ok")
  })
})


describe("toolCallSucceeded — normalized tool outcomes", () => {
  test("requires a completed tool part", () => {
    expect(toolCallSucceeded({ status: "running", tool: "bash", metadata: { exit: 0 } })).toBe(false)
    expect(toolCallSucceeded({ status: "error", tool: "bash", metadata: { exit: 0 } })).toBe(false)
  })

  test("honors bash exit and common explicit failure flags", () => {
    expect(toolCallSucceeded({ status: "completed", tool: "bash", metadata: { exit: 0 } })).toBe(true)
    expect(toolCallSucceeded({ status: "completed", tool: "bash", metadata: { exit: 2 } })).toBe(false)
    expect(toolCallSucceeded({ status: "completed", tool: "target_note", metadata: { saved: false } })).toBe(false)
    expect(toolCallSucceeded({ status: "completed", tool: "tool", metadata: { error: true } })).toBe(false)
    expect(toolCallSucceeded({ status: "completed", tool: "tool", metadata: { error: "workspace missing" } })).toBe(false)
  })

  test("recognizes tool-specific boolean error markers", () => {
    expect(toolCallSucceeded({ status: "completed", tool: "correlate_javascript", metadata: { correlation_error: true } })).toBe(false)
    expect(toolCallSucceeded({ status: "completed", tool: "validate_finding", metadata: { validation_error: true } })).toBe(false)
    expect(toolCallSucceeded({ status: "completed", tool: "recon_checkpoint", metadata: { request_blocked: true } })).toBe(false)
  })

  test("handles negative process exit sentinels but preserves grep no-match semantics", () => {
    expect(toolCallSucceeded({ status: "completed", tool: "attack_script", metadata: { exitCode: -1 } })).toBe(false)
    expect(toolCallSucceeded({ status: "completed", tool: "ebpf", metadata: { exitCode: 1 } })).toBe(false)
    expect(toolCallSucceeded({ status: "completed", tool: "attack_script", metadata: { exitCode: 0 } })).toBe(true)
    // grep documents exit code 1 as "no matches", not an execution failure.
    expect(toolCallSucceeded({ status: "completed", tool: "grep", metadata: { exitCode: 1 } })).toBe(true)
  })

  test("does not mistake diagnostic metadata for failure", () => {
    expect(toolCallSucceeded({ status: "completed", tool: "correlate_javascript", metadata: { sourceFiles: 0, notes: ["no assets captured"] } })).toBe(true)
    expect(toolCallSucceeded({ status: "completed", tool: "tool", metadata: { reason: "no_matches" } })).toBe(true)
  })
})

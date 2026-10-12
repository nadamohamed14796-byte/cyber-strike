import { describe, expect, test } from "bun:test"
import { RepeatDetector } from "./repeat-detector"

describe("RepeatDetector", () => {
  test("nudges when distinct signatures first reach the limit in the same step", () => {
    const detector = new RepeatDetector(2)

    expect(detector.observe(["tool-a", "tool-b"])).toBe("ok")
    expect(detector.observe(["tool-a", "tool-b"])).toBe("nudge")
  })

  test("aborts only when a signature reaches the limit after the nudge step", () => {
    const detector = new RepeatDetector(2)

    expect(detector.observe(["tool-a", "tool-b"])).toBe("ok")
    expect(detector.observe(["tool-a", "tool-b"])).toBe("nudge")
    expect(detector.observe(["tool-a"])).toBe("abort")
  })
})

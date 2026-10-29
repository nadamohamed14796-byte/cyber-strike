// Cross-turn identical-call and read-only polling detectors (loop-termination Layer 2b).
import { isProgressTool, READ_ONLY_TOOLS, toolSig } from "./signals"
//
// The within-turn duplicate suppressor (prompt.ts resolveTools) and the doom_loop
// check (processor.ts) both operate on a SINGLE generation, so they miss a loop
// that re-emits the same (tool, args) exactly ONCE per turn across many turns —
// the classic failure-to-terminate (observed: qwen re-emitting an identical
// record_coverage_note ~26×). This detector accumulates tool-call signatures over
// the whole prompt run and reacts once any signature repeats past a limit.
//
// Pure + deterministic (no IO), so it is unit-testable without mocks. One instance
// per prompt run, including primary and subagent agents. Signatures are
// `toolSig(tool, input)` values (see signals.ts):
// byte-identical (tool, args) collide; different args do not, so legitimate probing
// (e.g. id=1, id=2, id=3) never trips it.

export type RepeatVerdict = "ok" | "nudge" | "abort"

/**
 * Normalize tool-result metadata before feeding no-progress detectors.
 * Some tools report failures through metadata.exit, others use exitCode or
 * purpose-specific flags. Do not treat exitCode=1 as universally fatal:
 * tools such as grep use it to mean "no matches", which is a valid result.
 */
export function toolCallSucceeded(input: {
  status: string
  tool: string
  metadata?: Record<string, unknown> | null
}): boolean {
  if (input.status !== "completed") return false

  const metadata = input.metadata ?? {}
  if (typeof metadata.exit === "number" && metadata.exit !== 0) return false
  if (typeof metadata.exitCode === "number") {
    // -1 is used by several tools as a pre-execution/missing-script failure.
    if (metadata.exitCode < 0) return false
    // These tools surface the subprocess status directly, so any non-zero code
    // means the requested operation did not complete successfully.
    if ((input.tool === "attack_script" || input.tool === "ebpf") && metadata.exitCode !== 0) return false
  }
  if (metadata.saved === false || metadata.error === true) return false
  if (typeof metadata.error === "string" && metadata.error.trim().length > 0) return false
  if (metadata.success === false || metadata.ok === false || metadata.failed === true) return false

  // Handle standardized boolean error markers such as validation_error,
  // correlation_error, operation_failed, and request_blocked without hardcoding
  // every tool's metadata schema.
  for (const [key, value] of Object.entries(metadata)) {
    if (value === true && /(?:error|failed|blocked)$/i.test(key)) return false
  }
  return true
}

export class RepeatDetector {
  private readonly counts = new Map<string, number>()
  private nudged = false

  /** @param limit occurrences of one signature before the detector reacts (default 3). */
  constructor(private readonly limit: number = 3) {}

  /**
   * Feed the signatures of one completed step's tool calls. Returns the strongest
   * verdict triggered this step: "nudge" once a signature reaches the limit so the
   * caller can run a recovery turn with tools available; "abort" if it repeats after
   * that recovery, so the caller can schedule a terminal wrap-up. "ok" otherwise.
   */
  observe(signatures: string[]): RepeatVerdict {
    // A nudge triggered by this step must not turn another signature in the same
    // step into an abort. Only a nudge from a prior step permits aborting now.
    const wasNudgedBefore = this.nudged
    let verdict: RepeatVerdict = "ok"
    // Count each distinct signature at most ONCE per step: this detector measures
    // CROSS-turn repetition, so a within-turn burst of k identical calls (already
    // handled by the resolveTools suppressor) must advance the counter by 1, not k.
    for (const sig of new Set(signatures)) {
      const n = (this.counts.get(sig) ?? 0) + 1
      this.counts.set(sig, n)
      if (n >= this.limit) {
        if (wasNudgedBefore) {
          verdict = "abort"
        } else {
          this.nudged = true
          if (verdict !== "abort") verdict = "nudge"
        }
      }
    }
    return verdict
  }

  /** Clear all state — call at the start of each subagent run. */
  reset(): void {
    this.counts.clear()
    this.nudged = false
  }
}


/**
 * Count exact read/status calls separately from ordinary work. A brief poll is normal;
 * repeated identical polling without a meaningful recon/testing step is not progress.
 * Any real progress resets the streak, so normal workflows can revisit status tools.
 */
export class ReadOnlyRepeatDetector {
  private readonly detector: RepeatDetector

  constructor(limit: number = 8) {
    this.detector = new RepeatDetector(limit)
  }

  observe(toolCalls: { tool: string; input?: unknown; succeeded?: boolean }[]): RepeatVerdict {
    if (toolCalls.some((call) => call.succeeded === true && isProgressTool(call.tool))) {
      this.detector.reset()
      return "ok"
    }
    const signatures = toolCalls
      .filter((call) => call.input !== undefined && READ_ONLY_TOOLS.has(call.tool))
      .map((call) => toolSig(call.tool, call.input))
    return this.detector.observe(signatures)
  }

  reset(): void {
    this.detector.reset()
  }
}


/**
 * Detect a provider/agent loop that keeps yielding a continuing turn without any
 * tool calls. There are no (tool,args) signatures to count in this case, so it needs
 * a separate bounded guard. Any actual tool-call turn resets the streak.
 */
export class EmptyContinuationDetector {
  private streak = 0
  private nudged = false

  constructor(private readonly limit: number = 3) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError("limit must be a positive safe integer")
  }

  observe(toolCallCount: number): RepeatVerdict {
    if (toolCallCount > 0) {
      this.reset()
      return "ok"
    }
    this.streak++
    if (this.streak < this.limit) return "ok"
    if (this.nudged) return "abort"
    this.nudged = true
    return "nudge"
  }

  reset(): void {
    this.streak = 0
    this.nudged = false
  }
}


/**
 * A sequence of different failing tool calls can evade exact-signature repetition
 * checks. Count only turns containing failed target/work operations and no successful
 * target/work progress; reads and context-management calls do not trip this guard.
 */
export class FailedToolStreakDetector {
  private streak = 0
  private nudged = false

  constructor(private readonly limit: number = 4) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError("limit must be a positive safe integer")
  }

  observe(toolCalls: { tool: string; input?: unknown; succeeded?: boolean }[]): RepeatVerdict {
    if (toolCalls.some((call) => call.succeeded === true && isProgressTool(call.tool))) {
      this.reset()
      return "ok"
    }
    if (!toolCalls.some((call) => call.succeeded === false && isProgressTool(call.tool))) return "ok"
    this.streak++
    if (this.streak < this.limit) return "ok"
    if (this.nudged) return "abort"
    this.nudged = true
    return "nudge"
  }

  reset(): void {
    this.streak = 0
    this.nudged = false
  }
}

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

export class RepeatDetector {
  private readonly counts = new Map<string, number>()
  private nudged = false

  /** @param limit occurrences of one signature before the detector reacts (default 3). */
  constructor(private readonly limit: number = 3) {}

  /**
   * Feed the signatures of one completed step's tool calls. Returns the strongest
   * verdict triggered this step: "nudge" the first time any signature reaches the
   * limit (caller forces a tool-free wrap-up next turn), then "abort" if a signature
   * reaches the limit again after a nudge (backstop). "ok" otherwise.
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

  observe(toolCalls: { tool: string; input?: unknown }[]): RepeatVerdict {
    if (toolCalls.some((call) => isProgressTool(call.tool))) {
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

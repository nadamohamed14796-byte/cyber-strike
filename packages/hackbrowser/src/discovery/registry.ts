import { Log } from "../log.ts"
import { EMPTY_RESULT, type Detector, type DiscoveryContext, type DiscoveryResult, type Endpoint } from "./detector.ts"

const log = Log.create({ service: "hackbrowser:discovery" })

// Per-detector wall-clock cap. Detectors probe the network serially inside
// themselves; without a bound one slow/hung host would stretch discovery
// arbitrarily. A detector that overruns is abandoned (its result discarded) —
// results are best-effort and additive, so partial discovery is fine.
const DETECTOR_TIMEOUT_MS = 20000

const registry: Detector[] = []

/** Register a detector. Each detector module calls this at import time. */
export function register(detector: Detector): void {
  registry.push(detector)
}

/** Registered detectors (read-only) — for introspection and tests. */
export function detectors(): readonly Detector[] {
  return registry
}

/** Run one detector's applies+detect, isolated: never throws, bounded by a timeout. */
async function runOne(detector: Detector, ctx: DiscoveryContext): Promise<DiscoveryResult> {
  const work = async (): Promise<DiscoveryResult> => {
    try {
      if (!(await detector.applies(ctx))) return EMPTY_RESULT
      const result = await detector.detect(ctx)
      log.debug("detector ran", {
        detector: detector.name,
        pages: result.pages.length,
        endpoints: result.endpoints.length,
      })
      return result
    } catch (err) {
      log.warn("detector failed (skipped)", { detector: detector.name, err: String(err) })
      return EMPTY_RESULT
    }
  }

  // Complete-worklist detectors cannot be abandoned after a global timeout:
  // doing so would silently discard every script result after the time limit.
  const timeoutMs = detector.timeoutMs === undefined ? DETECTOR_TIMEOUT_MS : detector.timeoutMs
  if (timeoutMs === null) return work()

  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<DiscoveryResult>((resolve) => {
    timer = setTimeout(() => {
      log.warn("detector timed out (skipped)", { detector: detector.name, ms: timeoutMs })
      resolve(EMPTY_RESULT)
    }, timeoutMs)
  })
  try {
    return await Promise.race([work(), timeout])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

/**
 * Run every detector CONCURRENTLY and aggregate results. Each detector is
 * isolated (a throw or timeout yields an empty result) — one bad detector must
 * never abort discovery, and a slow one can't serialize the rest onto its own
 * latency. Pages and endpoints are de-duplicated across detectors; confidence is
 * the max reported.
 */
export async function runDetectors(ctx: DiscoveryContext): Promise<DiscoveryResult> {
  const pages = new Set<string>()
  const endpoints = new Map<string, Endpoint>() // key: "METHOD url"
  let confidence = 0

  const results = await Promise.all(registry.map((detector) => runOne(detector, ctx)))
  for (const result of results) {
    for (const page of result.pages) pages.add(page)
    for (const endpoint of result.endpoints) endpoints.set(`${endpoint.method} ${endpoint.url}`, endpoint)
    confidence = Math.max(confidence, result.confidence)
  }

  return { pages: [...pages], endpoints: [...endpoints.values()], confidence }
}

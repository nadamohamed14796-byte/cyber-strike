import { Log } from "./log.ts"
import { IngestDeliveryError } from "./ingest.ts"
import type { CapturedRequest } from "./types.ts"

const log = Log.create({ service: "hackbrowser:capture-queue" })

export type CaptureDrainResult = {
  /** Requests still waiting for delivery after this drain pass. */
  pending: number
  /** Requests rejected permanently by the server during this pass. */
  rejected: number
}

export type RejectedCaptureDetail = {
  /** Method and query-free path only; never retain raw headers or bodies in the diagnostic ledger. */
  request: string
  status: number | null
  reason: string
}

const activeDrains = new WeakMap<CapturedRequest[], Promise<CaptureDrainResult>>()
const rejectedTotals = new WeakMap<CapturedRequest[], number>()
const rejectedDetails = new WeakMap<CapturedRequest[], RejectedCaptureDetail[]>()

function safeRequestLabel(captured: CapturedRequest): string {
  const firstLine = captured.raw.split(/\r?\n/, 1)[0]?.trim() ?? ""
  const match = /^([A-Z]+)\s+(\S+)/i.exec(firstLine)
  if (!match) return "[unparsed captured request]"
  const method = match[1]!.toUpperCase()
  const requestTarget = match[2]!
  try {
    const url = /^https?:\/\//i.test(requestTarget) ? new URL(requestTarget) : undefined
    const safeTarget = url ? url.origin + url.pathname : requestTarget.split(/[?#]/, 1)[0]!
    return (method + " " + (safeTarget || "[empty path]")).slice(0, 240)
  } catch {
    return (method + " " + requestTarget.split(/[?#]/, 1)[0]!).slice(0, 240)
  }
}

function safeErrorReason(error: Error): string {
  return error.message
    .replace(/https?:\/\/[^\s"'<>]+/gi, "[URL]")
    .replace(/(authorization|cookie|token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .slice(0, 240)
}

/** Number of permanent backend rejections observed for this queue over its lifetime. */
export function permanentlyRejectedCaptureCount(queue: CapturedRequest[]): number {
  return rejectedTotals.get(queue) ?? 0
}

/** Recent, redacted diagnostics for permanently rejected captures in this live queue. */
export function permanentlyRejectedCaptureDetails(queue: CapturedRequest[]): RejectedCaptureDetail[] {
  return (rejectedDetails.get(queue) ?? []).map((item) => ({ ...item }))
}

/**
 * Deliver captured requests in FIFO order without losing the queue head before
 * the backend acknowledges it. A transient network/server failure leaves the
 * request at the head for the next drain. Permanent 4xx rejections are reported
 * and skipped so one malformed capture cannot block every later request.
 *
 * Overlapping timer/final drains for the same queue share one in-flight pass.
 */
export async function drainCaptureQueue(
  queue: CapturedRequest[],
  handler: (captured: CapturedRequest) => Promise<void>,
  label: string,
  options: { finalDrain?: boolean } = {},
): Promise<CaptureDrainResult> {
  const existing = activeDrains.get(queue)
  if (existing) {
    const result = await existing
    if (options.finalDrain && queue.length > 0) {
      const followUp = await drainCaptureQueue(queue, handler, label, options)
      return { pending: followUp.pending, rejected: result.rejected + followUp.rejected }
    }
    return { pending: queue.length, rejected: result.rejected }
  }

  // Defer the first iteration until after activeDrains is populated.
  const task = Promise.resolve().then(async () => {
    let rejected = 0
    let transientFailures = 0

    while (queue.length > 0) {
      const captured = queue[0]!
      try {
        await handler(captured)
        // Do not remove the item until the handler confirms delivery.
        if (queue[0] === captured) queue.shift()
        transientFailures = 0
      } catch (error) {
        if (error instanceof IngestDeliveryError && !error.retryable) {
          queue.shift()
          rejected++
          rejectedTotals.set(queue, (rejectedTotals.get(queue) ?? 0) + 1)
          const detail: RejectedCaptureDetail = {
            request: safeRequestLabel(captured),
            status: error.status ?? null,
            reason: safeErrorReason(error),
          }
          const recent = rejectedDetails.get(queue) ?? []
          recent.push(detail)
          if (recent.length > 20) recent.splice(0, recent.length - 20)
          rejectedDetails.set(queue, recent)
          log.error("captured request was permanently rejected; continuing with later requests", {
            queue: label,
            request: detail.request,
            status: detail.status,
            pending: queue.length,
            error: detail.reason,
          })
          continue
        }

        transientFailures++
        log.warn("captured request delivery failed; retaining it for retry", {
          queue: label,
          pending: queue.length,
          attempt: transientFailures,
          error: error instanceof Error ? error.message : String(error),
        })

        // Background drains return promptly; the next timer tick retries.
        // Final drains make a few bounded retries before reporting undelivered
        // work to the caller, rather than hanging shutdown indefinitely.
        if (!options.finalDrain || transientFailures >= 3) break
        await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** (transientFailures - 1)))
      }
    }

    return { pending: queue.length, rejected }
  })

  activeDrains.set(queue, task)
  try {
    return await task
  } finally {
    if (activeDrains.get(queue) === task) activeDrains.delete(queue)
  }
}

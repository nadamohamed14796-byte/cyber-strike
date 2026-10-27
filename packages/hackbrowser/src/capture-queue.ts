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

const activeDrains = new WeakMap<CapturedRequest[], Promise<CaptureDrainResult>>()

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
          log.error("captured request was permanently rejected; continuing with later requests", {
            queue: label,
            status: error.status ?? null,
            pending: queue.length,
            error: error.message,
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

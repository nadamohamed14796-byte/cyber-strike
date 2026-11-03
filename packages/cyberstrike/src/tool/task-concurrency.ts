export type TaskSchedulerOptions = {
  maxConcurrent: number
  maxPerLane: number
  /**
   * Lane names (or suffixes such as "impact") that retain dedicated global
   * capacity. Non-reserved work cannot consume these slots.
   */
  reservedLaneSuffixes?: string[]
}

type ScheduledEntry = {
  lane: string
  start: (release: () => void) => void
}

/**
 * Small FIFO scheduler for agent loops. It preserves work when saturated and
 * skips a lane temporarily at capacity so an independent lane can still run.
 */
export function createTaskScheduler(options: TaskSchedulerOptions) {
  const maxConcurrent = Math.max(1, Math.floor(options.maxConcurrent))
  const maxPerLane = Math.max(1, Math.floor(options.maxPerLane))
  const reservedLaneSuffixes = [...new Set((options.reservedLaneSuffixes ?? []).map((value) => value.trim()).filter(Boolean))]
  const isReservedLane = (lane: string) => reservedLaneSuffixes.some((suffix) =>
    lane === suffix || lane.endsWith(":" + suffix),
  )
  const reservedCapacity = Math.min(Math.max(0, maxConcurrent - 1), reservedLaneSuffixes.length)
  const pending: ScheduledEntry[] = []
  const activeByLane = new Map<string, number>()
  let active = 0

  function releaseFor(lane: string) {
    let released = false
    return () => {
      if (released) return
      released = true
      active = Math.max(0, active - 1)
      const next = (activeByLane.get(lane) ?? 1) - 1
      if (next <= 0) activeByLane.delete(lane)
      else activeByLane.set(lane, next)
      drain()
    }
  }

  function drain() {
    while (active < maxConcurrent) {
      const nonReservedActive = [...activeByLane.entries()]
        .filter(([lane]) => !isReservedLane(lane))
        .reduce((total, [, count]) => total + count, 0)
      const index = pending.findIndex((entry) =>
        (activeByLane.get(entry.lane) ?? 0) < maxPerLane &&
        (isReservedLane(entry.lane) || nonReservedActive < maxConcurrent - reservedCapacity),
      )
      if (index < 0) return
      const [entry] = pending.splice(index, 1)
      if (!entry) return
      active += 1
      activeByLane.set(entry.lane, (activeByLane.get(entry.lane) ?? 0) + 1)
      const release = releaseFor(entry.lane)
      try {
        entry.start(release)
      } catch (error) {
        release()
        throw error
      }
    }
  }

  function abortError(): Error {
    const error = new Error("Task was aborted before an execution slot became available.")
    error.name = "AbortError"
    return error
  }

  function acquire(lane: string, signal?: AbortSignal): Promise<() => void> {
    return new Promise<() => void>((resolve, reject) => {
      if (signal?.aborted) {
        reject(abortError())
        return
      }

      let settled = false
      let entry!: ScheduledEntry
      const cleanup = () => signal?.removeEventListener("abort", onAbort)
      const onAbort = () => {
        if (settled) return
        const index = pending.indexOf(entry)
        if (index < 0) return
        pending.splice(index, 1)
        settled = true
        cleanup()
        reject(abortError())
        drain()
      }

      entry = {
        lane,
        start: (release) => {
          if (settled) {
            release()
            return
          }
          settled = true
          cleanup()
          resolve(release)
        },
      }

      signal?.addEventListener("abort", onAbort, { once: true })
      if (signal?.aborted) {
        settled = true
        cleanup()
        reject(abortError())
        return
      }

      pending.push(entry)
      drain()
    })
  }

  async function run<T>(lane: string, task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    const release = await acquire(lane, signal)
    try {
      if (signal?.aborted) throw abortError()
      return await task()
    } finally {
      release()
    }
  }

  function enqueue(
    lane: string,
    task: () => Promise<unknown>,
    onError?: (error: unknown) => void,
    signal?: AbortSignal,
    onCancel?: () => void,
  ): "started" | "queued" | "cancelled" {
    const cancel = () => {
      try {
        onCancel?.()
      } catch {
        // Cancellation cleanup must never corrupt scheduler accounting.
      }
    }
    if (signal?.aborted) {
      cancel()
      return "cancelled"
    }

    let started = false
    let executionStarted = false
    let cancelled = false
    let entry!: ScheduledEntry
    const cleanup = () => signal?.removeEventListener("abort", onAbort)
    const onAbort = () => {
      if (executionStarted || cancelled) return
      if (!started) {
        const index = pending.indexOf(entry)
        if (index < 0) return
        pending.splice(index, 1)
      }
      // A slot may have been assigned while the task callback is still waiting
      // for its microtask. Cancellation wins until the callback actually starts.
      cancelled = true
      cleanup()
      cancel()
      if (!started) drain()
    }

    entry = {
      lane,
      start: (release) => {
        started = true
        void Promise.resolve()
          .then(() => {
            if (cancelled) return
            executionStarted = true
            cleanup()
            return task()
          })
          .catch((error) => {
            try {
              onError?.(error)
            } catch {
              // Error reporting must never leak a scheduler slot.
            }
          })
          .finally(release)
      },
    }

    signal?.addEventListener("abort", onAbort, { once: true })
    if (signal?.aborted) {
      cancelled = true
      cleanup()
      cancel()
      return "cancelled"
    }

    pending.push(entry)
    drain()
    return started ? "started" : cancelled ? "cancelled" : "queued"
  }

  return {
    acquire,
    run,
    enqueue,
    stats: () => ({
      active,
      pending: pending.length,
      activeByLane: Object.fromEntries(activeByLane),
    }),
  }
}

// Main Recon, Extension Proxy, and Impact Hunter use independent lanes. The
// process-wide cap still bounds total live model/tool loops.
export const AgentTaskConcurrency = createTaskScheduler({
  maxConcurrent: 4,
  maxPerLane: 2,
  reservedLaneSuffixes: ["impact"],
})

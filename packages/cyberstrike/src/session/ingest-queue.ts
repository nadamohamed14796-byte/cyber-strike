import { Instance } from "@/project/instance"
import { Log } from "@/util/log"
import { SessionQueueStatus } from "./queue-status"

const log = Log.create({ service: "ingest-queue" })

export namespace IngestQueue {
  type State = {
    paused: boolean
    pending: number
    resumeSignal: Promise<void> | null
    resumeResolve: (() => void) | null
  }

  const state = Instance.state(() => {
    const data: Record<string, State> = {}
    return data
  })

  function getOrInit(sessionID: string): State {
    let s = state()[sessionID]
    if (!s) {
      s = {
        paused: false,
        pending: 0,
        resumeSignal: null,
        resumeResolve: null,
      }
      state()[sessionID] = s
    }
    return s
  }

  function publish(sessionID: string) {
    const s = state()[sessionID]
    SessionQueueStatus.set(sessionID, {
      paused: s?.paused ?? false,
      pending: s?.pending ?? 0,
    })
  }

  function maybeCleanup(sessionID: string) {
    const s = state()[sessionID]
    if (!s) return
    if (s.pending === 0 && !s.paused) {
      delete state()[sessionID]
    }
  }

  function beginTracking(sessionID: string, parentSessionID?: string) {
    const trackedIDs = [...new Set([sessionID, ...(parentSessionID ? [parentSessionID] : [])])]
    for (const id of trackedIDs) {
      const tracked = getOrInit(id)
      tracked.pending++
      publish(id)
    }

    let settled = false
    return {
      trackedIDs,
      settle() {
        if (settled) return
        settled = true
        for (const id of trackedIDs) {
          const cur = state()[id]
          if (cur) cur.pending = Math.max(0, cur.pending - 1)
          publish(id)
          maybeCleanup(id)
        }
      },
    }
  }

  function waitIfAnyPaused(sessionIDs: string[]): Promise<void> {
    const paused = [...new Set(sessionIDs)]
      .map((id) => ({ id, state: state()[id] }))
      .filter((entry) => entry.state?.paused)
    if (paused.length === 0) return Promise.resolve()
    return Promise.race(
      paused.map(({ state: s }) => {
        if (!s!.resumeSignal) {
          s!.resumeSignal = new Promise<void>((resolve) => {
            s!.resumeResolve = resolve
          })
        }
        return s!.resumeSignal
      }),
    )
  }

  /**
   * Track request intake/normalization before a persisted Request row exists.
   * This makes the queue indicator react as soon as the extension sends traffic.
   * The callback runs immediately; queue pause only gates actual queued work.
   */
  export async function track<T>(
    sessionID: string,
    task: () => Promise<T>,
    parentSessionID?: string,
  ): Promise<T> {
    const ticket = beginTracking(sessionID, parentSessionID)
    try {
      return await task()
    } finally {
      ticket.settle()
    }
  }

  /**
   * Schedule independent request analyses without serializing siblings.
   * Each request runs in its own child session. Pending counts and pause/resume
   * are scoped to the parent session, but there is deliberately no fixed
   * concurrency ceiling here; callers should delegate only distinct useful work.
   */
  export function enqueue(sessionID: string, task: () => Promise<unknown>, parentSessionID?: string) {
    const ticket = beginTracking(sessionID, parentSessionID)
    log.info("ingest task enqueued", {
      sessionID,
      trackedSessionIDs: ticket.trackedIDs,
      pending: state()[sessionID]?.pending ?? 0,
      paused: state()[sessionID]?.paused ?? false,
    })

    void (async () => {
      while (ticket.trackedIDs.some((id) => state()[id]?.paused)) {
        log.info("ingest task waiting for queue resume", {
          sessionID,
          trackedSessionIDs: ticket.trackedIDs,
        })
        await waitIfAnyPaused(ticket.trackedIDs)
      }
      log.info("ingest task started", {
        sessionID,
        trackedSessionIDs: ticket.trackedIDs,
        pending: state()[sessionID]?.pending ?? 0,
      })
      await task()
    })()
      .catch((err) => {
        log.error("ingest prompt failed", { sessionID, error: err })
      })
      .finally(() => {
        ticket.settle()
        log.info("ingest task settled", {
          sessionID,
          trackedSessionIDs: ticket.trackedIDs,
          pending: state()[sessionID]?.pending ?? 0,
          paused: state()[sessionID]?.paused ?? false,
        })
      })
  }

  export function pause(sessionID: string) {
    const s = getOrInit(sessionID)
    if (s.paused) return
    s.paused = true
    publish(sessionID)
  }

  export function resume(sessionID: string) {
    const s = state()[sessionID]
    if (!s || !s.paused) return
    s.paused = false
    const resolve = s.resumeResolve
    s.resumeResolve = null
    s.resumeSignal = null
    if (resolve) resolve()
    publish(sessionID)
    maybeCleanup(sessionID)
  }

  export function pendingCount(sessionID: string): number {
    return state()[sessionID]?.pending ?? 0
  }

  export function isPaused(sessionID: string): boolean {
    return state()[sessionID]?.paused ?? false
  }
}

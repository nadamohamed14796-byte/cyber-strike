import { Instance } from "@/project/instance"
import { Log } from "@/util/log"
import { SessionQueueStatus } from "./queue-status"

const log = Log.create({ service: "ingest-queue" })

export namespace IngestQueue {
  type State = {
    chain: Promise<void>
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
        chain: Promise.resolve(),
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

  function waitIfAnyPaused(sessionIDs: string[]): Promise<void> {
    const paused = [...new Set(sessionIDs)]
      .map((id) => ({ id, state: state()[id] }))
      .filter((entry) => entry.state?.paused)
    if (paused.length === 0) return Promise.resolve()
    return Promise.race(
      paused.map(({ id, state: s }) => {
        if (!s!.resumeSignal) {
          s!.resumeSignal = new Promise<void>((resolve) => {
            s!.resumeResolve = resolve
          })
        }
        return s!.resumeSignal
      }),
    )
  }

  export function enqueue(sessionID: string, task: () => Promise<unknown>, parentSessionID?: string) {
    const s = getOrInit(sessionID)
    const trackedIDs = [...new Set([sessionID, ...(parentSessionID ? [parentSessionID] : [])])]
    for (const id of trackedIDs) {
      const tracked = getOrInit(id)
      tracked.pending++
      publish(id)
    }

    const next = s.chain
      // A child ingest inherits pause/resume from its owning parent session.
      // Re-check after every wake-up because a pause can race with resume.
      .then(async () => {
        while (trackedIDs.some((id) => state()[id]?.paused)) {
          await waitIfAnyPaused(trackedIDs)
        }
        return task()
      })
      .then(
        () => {},
        (err) => log.error("ingest prompt failed", { sessionID, error: err }),
      )
      .then(() => {
        for (const id of trackedIDs) {
          const cur = state()[id]
          if (cur) cur.pending = Math.max(0, cur.pending - 1)
          publish(id)
          maybeCleanup(id)
        }
      })

    s.chain = next
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

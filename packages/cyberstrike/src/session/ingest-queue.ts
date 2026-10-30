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

  // Reserve ordering synchronously at intake, before awaited request setup.
  // The actual queue reservation is created only when this ticket reaches the head.
  const intakeOrder = Instance.state(() => ({} as Record<string, Promise<void>>))

  export interface IntakeOrderReservation {
    previous: Promise<void>
    release(): void
  }

  export function reserveOrder(key: string): IntakeOrderReservation {
    const chains = intakeOrder()
    const previous = chains[key] ?? Promise.resolve()
    let resolveSlot!: () => void
    let released = false
    const slot = new Promise<void>((resolve) => {
      resolveSlot = resolve
    })
    const chain = previous.then(() => slot)
    chains[key] = chain

    return {
      previous,
      release() {
        if (released) return
        released = true
        resolveSlot()
        void chain.then(() => {
          if (chains[key] === chain) delete chains[key]
        })
      },
    }
  }

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
   * Reserve a FIFO position as soon as a capture reaches the server. Request
   * normalization may complete out of order, but a later reservation cannot
   * pass this slot until it is enqueued or explicitly skipped.
   */
  export interface Reservation {
    sessionID: string
    trackedIDs: string[]
    previous: Promise<void>
    release(): void
  }

  export function reserve(sessionID: string, parentSessionID?: string): Reservation {
    const ticket = beginTracking(sessionID, parentSessionID)
    const s = getOrInit(sessionID)
    const previous = s.chain
    let releaseSlot!: () => void
    let released = false
    const slot = new Promise<void>((resolve) => {
      releaseSlot = resolve
    })
    // Insert the placeholder immediately. Subsequent reservations and ordinary
    // serial tasks will wait behind it, even if this capture normalizes slowly.
    s.chain = previous.then(() => slot)
    return {
      sessionID,
      trackedIDs: ticket.trackedIDs,
      previous,
      release() {
        if (released) return
        released = true
        releaseSlot()
        ticket.settle()
      },
    }
  }

  async function waitForReservation(reservation: Reservation) {
    while (reservation.trackedIDs.some((id) => state()[id]?.paused)) {
      log.info("ingest task waiting for queue resume", {
        sessionID: reservation.sessionID,
        trackedSessionIDs: reservation.trackedIDs,
      })
      await waitIfAnyPaused(reservation.trackedIDs)
    }
  }

  /** Fill a previously reserved FIFO slot with the captured request's analysis. */
  export function enqueueReserved(reservation: Reservation, task: () => Promise<unknown>) {
    void reservation.previous.then(async () => {
      try {
        await waitForReservation(reservation)
        log.info("reserved ingest task started", {
          sessionID: reservation.sessionID,
          trackedSessionIDs: reservation.trackedIDs,
          pending: state()[reservation.sessionID]?.pending ?? 0,
        })
        await task()
      } catch (err) {
        log.error("reserved ingest task failed", { sessionID: reservation.sessionID, error: err })
      } finally {
        reservation.release()
        log.info("reserved ingest task settled", {
          sessionID: reservation.sessionID,
          trackedSessionIDs: reservation.trackedIDs,
          pending: state()[reservation.sessionID]?.pending ?? 0,
        })
      }
    })
  }

  /** Release a reservation when normalization, deduplication, or validation
   * determines that no Proxy Agent turn should be created for this capture. */
  export function skipReserved(reservation: Reservation) {
    void reservation.previous.then(() => reservation.release())
  }

  /**
   * Track request intake/normalization before a persisted Request row exists.
   * Kept for non-queued intake callers; Extension captures should use reserve()
   * so their arrival order is preserved through normalization.
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
   * Schedule work for a session. Ordinary serial tasks append to the session
   * chain; explicitly independent tasks may bypass it when they have isolated
   * sessions and no shared conversational context. Captured requests use
   * reserve()/enqueueReserved() because they share one persistent Proxy Agent.
   * There is no fixed concurrency ceiling for explicitly independent work.
   */
  export function enqueue(
    sessionID: string,
    task: () => Promise<unknown>,
    parentSessionID?: string,
    concurrent = false,
  ) {
    const ticket = beginTracking(sessionID, parentSessionID)
    const run = async () => {
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
        concurrent,
      })
      await task()
    }

    const settle = () => {
      ticket.settle()
      log.info("ingest task settled", {
        sessionID,
        trackedSessionIDs: ticket.trackedIDs,
        pending: state()[sessionID]?.pending ?? 0,
        paused: state()[sessionID]?.paused ?? false,
      })
    }

    const execute = async () => {
      try {
        await run()
      } catch (err) {
        log.error("ingest prompt failed", { sessionID, error: err })
      } finally {
        settle()
      }
    }

    log.info("ingest task enqueued", {
      sessionID,
      trackedSessionIDs: ticket.trackedIDs,
      pending: state()[sessionID]?.pending ?? 0,
      paused: state()[sessionID]?.paused ?? false,
      concurrent,
    })

    if (concurrent) {
      // No queue-chain dependency for independent child-session analyses.
      void execute()
      return
    }

    const s = getOrInit(sessionID)
    const next = s.chain.then(execute, execute)
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

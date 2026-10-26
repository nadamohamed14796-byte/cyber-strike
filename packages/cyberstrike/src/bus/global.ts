import { EventEmitter } from "events"
import { Log } from "../util/log"

const log = Log.create({ service: "global.bus" })

export const GlobalBus = new EventEmitter<{
  event: [
    {
      directory?: string
      payload: any
    },
  ]
}>()

/**
 * Broadcast a global event without allowing one broken listener to starve the rest.
 * Handles both synchronous throws and rejected promises while preserving listener order.
 */
export function emitSafe(event: { directory?: string; payload: any }) {
  const listeners = GlobalBus.rawListeners("event")
  for (const listener of listeners) {
    try {
      void Promise.resolve(Reflect.apply(listener, GlobalBus, [event])).catch((error) => {
        log.error("global event listener failed", { type: event.payload?.type, error })
      })
    } catch (error) {
      log.error("global event listener failed", { type: event.payload?.type, error })
    }
  }
  return listeners.length > 0
}

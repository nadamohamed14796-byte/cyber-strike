export type ModeAwareFlight<M extends string, R> = {
  mode: M
  promise: Promise<R>
}

/**
 * Deduplicate concurrent work for the same key and serialize mode transitions.
 * Repeated requests for the current mode share one promise; a different mode is
 * queued after the current run. Each queued operation retains its own execution
 * closure, so it cannot accidentally reuse another finding's caller context.
 */
export function createModeAwareFlightRegistry<K, M extends string, R>() {
  const flights = new Map<K, ModeAwareFlight<M, R>>()

  return function start(key: K, mode: M, run: () => Promise<R>): Promise<R> {
    const active = flights.get(key)
    if (active?.mode === mode) return active.promise

    const pending = active
      ? active.promise.then(run, run)
      : run()
    const flight = { mode, promise: pending }
    flights.set(key, flight)

    const cleanup = () => {
      if (flights.get(key) === flight) flights.delete(key)
    }
    void pending.then(cleanup, cleanup)
    return pending
  }
}

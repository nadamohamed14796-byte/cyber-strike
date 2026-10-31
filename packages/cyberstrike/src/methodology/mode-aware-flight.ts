export type ModeAwareFlight<M extends string, R> = {
  mode: M
  promise: Promise<R>
}

/**
 * Deduplicate concurrent work for the same key and serialize mode transitions.
 * Repeated requests for the current mode share one promise; a different mode is
 * queued after the current run so the caller can resume the same underlying task.
 */
export function createModeAwareFlightRegistry<K, M extends string, R>(
  run: (key: K, mode: M) => Promise<R>,
) {
  const flights = new Map<K, ModeAwareFlight<M, R>>()

  return function start(key: K, mode: M): Promise<R> {
    const active = flights.get(key)
    if (active?.mode === mode) return active.promise

    const pending = active
      ? active.promise.then(
          () => run(key, mode),
          () => run(key, mode),
        )
      : run(key, mode)
    const flight = { mode, promise: pending }
    flights.set(key, flight)

    const cleanup = () => {
      if (flights.get(key) === flight) flights.delete(key)
    }
    void pending.then(cleanup, cleanup)
    return pending
  }
}

/**
 * FIFO executor for tool calls produced in a single assistant step.
 *
 * A failed operation is returned to its caller unchanged, while the internal
 * tail absorbs the rejection so later queued operations still get a turn.
 */
export function createToolExecutionQueue() {
  let tail: Promise<void> = Promise.resolve()

  return function run<T>(operation: () => T | PromiseLike<T>): Promise<T> {
    const result = tail.then(operation, operation)
    tail = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }
}

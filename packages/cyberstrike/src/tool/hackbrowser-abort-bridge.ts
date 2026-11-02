/**
 * Bridges a caller AbortSignal to a worker IPC abort message.
 *
 * A worker must receive its start message before an abort message. The signal
 * may already be aborted while asynchronous preparation is running, so aborts
 * are buffered until markStarted(). dispose() removes the listener on every
 * worker exit path.
 */
export function createWorkerAbortBridge(signal: AbortSignal | undefined, sendAbort: () => void) {
  let started = false
  let pendingAbort = signal?.aborted ?? false
  let disposed = false

  const onAbort = () => {
    if (disposed) return
    if (!started) {
      pendingAbort = true
      return
    }
    sendAbort()
  }

  if (signal && !signal.aborted) {
    signal.addEventListener("abort", onAbort, { once: true })
  }

  return {
    markStarted() {
      if (disposed || started) return
      started = true
      if (!pendingAbort) return
      pendingAbort = false
      sendAbort()
    },
    dispose() {
      if (disposed) return
      disposed = true
      pendingAbort = false
      signal?.removeEventListener("abort", onAbort)
    },
  }
}

/**
 * Close a newly connected browser if setting up its context/page fails.
 * The main agent crawl owns a separate finally block after setup succeeds;
 * this guard covers the gap before that lifecycle begins.
 */
export async function closeBrowserOnSetupFailure<T>(
  browser: { close(): Promise<void> },
  setup: () => Promise<T>,
): Promise<T> {
  try {
    return await setup()
  } catch (error) {
    await browser.close().catch(() => {})
    throw error
  }
}


/** Browser event surface required by waitForBrowserClose. */
export interface BrowserCloseSource {
  on(event: "disconnected", listener: () => void): unknown
  removeListener(event: "disconnected", listener: () => void): unknown
  isConnected(): boolean
}

export const BROWSER_WAIT_TIMEOUT = 30 * 60 * 1000

/**
 * Resolve when the browser disconnects, the caller aborts, or the wait times out.
 * Every completion path removes both event listeners and clears the timer.
 */
export function waitForBrowserClose(
  browser: BrowserCloseSource,
  signal?: AbortSignal,
  timeoutMs = BROWSER_WAIT_TIMEOUT,
): Promise<void> {
  return new Promise<void>((resolve) => {
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer)
      browser.removeListener("disconnected", done)
      signal?.removeEventListener("abort", done)
    }

    const done = () => {
      if (settled) return
      settled = true
      cleanup()
      resolve()
    }

    // Avoid registering listeners for sources that have already completed.
    if (signal?.aborted || !browser.isConnected()) {
      done()
      return
    }

    browser.on("disconnected", done)
    signal?.addEventListener("abort", done, { once: true })

    // Recheck after registration to close the check/register race.
    if (signal?.aborted || !browser.isConnected()) {
      done()
      return
    }

    timer = setTimeout(done, timeoutMs)
  })
}

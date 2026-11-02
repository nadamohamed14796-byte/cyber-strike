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

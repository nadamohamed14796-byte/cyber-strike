import { expect, test } from "bun:test"
import { closeBrowserOnSetupFailure, waitForBrowserClose } from "../src/browser-lifecycle.ts"

test("closes the browser when context/page setup fails and preserves the setup error", async () => {
  const setupError = new Error("newPage failed")
  let closeCount = 0
  const browser = {
    close: async () => {
      closeCount++
    },
  }

  await expect(closeBrowserOnSetupFailure(browser, async () => {
    throw setupError
  })).rejects.toBe(setupError)

  expect(closeCount).toBe(1)
})

test("does not close the browser when setup succeeds", async () => {
  let closeCount = 0
  const browser = {
    close: async () => {
      closeCount++
    },
  }

  const result = await closeBrowserOnSetupFailure(browser, async () => "ready")

  expect(result).toBe("ready")
  expect(closeCount).toBe(0)
})

test("does not replace the setup error when browser cleanup also fails", async () => {
  const setupError = new Error("addInitScript failed")
  let closeCount = 0
  const browser = {
    close: async () => {
      closeCount++
      throw new Error("browser close failed")
    },
  }

  await expect(closeBrowserOnSetupFailure(browser, async () => {
    throw setupError
  })).rejects.toBe(setupError)

  expect(closeCount).toBe(1)
})


class FakeBrowser {
  connected = true
  private listeners = new Set<() => void>()

  on(_event: "disconnected", listener: () => void): this {
    this.listeners.add(listener)
    return this
  }

  removeListener(_event: "disconnected", listener: () => void): this {
    this.listeners.delete(listener)
    return this
  }

  isConnected(): boolean {
    return this.connected
  }

  disconnect(): void {
    this.connected = false
    for (const listener of [...this.listeners]) listener()
  }

  listenerCount(): number {
    return this.listeners.size
  }
}

function trackedSignal() {
  let aborted = false
  let listener: (() => void) | undefined
  const signal = {
    get aborted() { return aborted },
    addEventListener(_type: string, callback: () => void) {
      listener = callback
    },
    removeEventListener(_type: string, callback: () => void) {
      if (listener === callback) listener = undefined
    },
  } as unknown as AbortSignal
  return {
    signal,
    abort() {
      aborted = true
      listener?.()
    },
    listenerCount: () => listener ? 1 : 0,
  }
}

test("waitForBrowserClose removes both listeners after browser disconnect", async () => {
  const browser = new FakeBrowser()
  const tracked = trackedSignal()
  const waiting = waitForBrowserClose(browser, tracked.signal, 1000)

  expect(browser.listenerCount()).toBe(1)
  expect(tracked.listenerCount()).toBe(1)
  browser.disconnect()
  await waiting

  expect(browser.listenerCount()).toBe(0)
  expect(tracked.listenerCount()).toBe(0)
})

test("waitForBrowserClose removes both listeners after abort", async () => {
  const browser = new FakeBrowser()
  const tracked = trackedSignal()
  const waiting = waitForBrowserClose(browser, tracked.signal, 1000)

  tracked.abort()
  await waiting

  expect(browser.listenerCount()).toBe(0)
  expect(tracked.listenerCount()).toBe(0)
})

test("waitForBrowserClose removes listeners after timeout", async () => {
  const browser = new FakeBrowser()
  const tracked = trackedSignal()

  await waitForBrowserClose(browser, tracked.signal, 1)

  expect(browser.listenerCount()).toBe(0)
  expect(tracked.listenerCount()).toBe(0)
})

test("waitForBrowserClose immediately resolves for an already disconnected browser", async () => {
  const browser = new FakeBrowser()
  browser.connected = false
  const tracked = trackedSignal()

  await waitForBrowserClose(browser, tracked.signal, 1000)

  expect(browser.listenerCount()).toBe(0)
  expect(tracked.listenerCount()).toBe(0)
})

test("waitForBrowserClose immediately resolves for an already aborted signal", async () => {
  const browser = new FakeBrowser()
  const tracked = trackedSignal()
  tracked.abort()

  await waitForBrowserClose(browser, tracked.signal, 1000)

  expect(browser.listenerCount()).toBe(0)
  expect(tracked.listenerCount()).toBe(0)
})

test("waitForBrowserClose does not leak listeners across 20 consecutive abort cycles", async () => {
  const browser = new FakeBrowser()

  for (let i = 0; i < 20; i++) {
    const tracked = trackedSignal()
    const waiting = waitForBrowserClose(browser, tracked.signal, 1000)
    expect(browser.listenerCount()).toBe(1)
    expect(tracked.listenerCount()).toBe(1)

    tracked.abort()
    await waiting

    expect(browser.listenerCount()).toBe(0)
    expect(tracked.listenerCount()).toBe(0)
  }
})

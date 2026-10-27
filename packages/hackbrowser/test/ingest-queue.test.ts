import { describe, expect, test } from "bun:test"
import { drainCaptureQueue, permanentlyRejectedCaptureCount } from "../src/capture-queue.ts"
import { IngestDeliveryError } from "../src/ingest.ts"
import type { CapturedRequest } from "../src/types.ts"

function capture(path: string): CapturedRequest {
  return {
    raw: `GET ${path} HTTP/1.1\r\nHost: example.test\r\n\r\n`,
    scheme: "https",
    response: null,
    uiContext: null,
    triggerElement: null,
    elementRoles: null,
    pageUrl: null,
    pageVisitedBy: null,
    timestamp: Date.now(),
  }
}

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe("drainCaptureQueue", () => {
  test("serializes overlapping drains and preserves FIFO order", async () => {
    const queue = [capture("/first"), capture("/second")]
    const firstStarted = deferred()
    const releaseFirst = deferred()
    const delivered: string[] = []

    const handler = async (item: CapturedRequest) => {
      const path = item.raw.split(" ")[1]!
      if (path === "/first") {
        firstStarted.resolve()
        await releaseFirst.promise
      }
      delivered.push(path)
    }

    const firstDrain = drainCaptureQueue(queue, handler, "test")
    await firstStarted.promise
    const overlappingDrain = drainCaptureQueue(queue, handler, "test")
    expect(delivered).toEqual([])

    releaseFirst.resolve()
    await Promise.all([firstDrain, overlappingDrain])

    expect(delivered).toEqual(["/first", "/second"])
    expect(queue).toHaveLength(0)
  })

  test("retains a transiently failed request and retries it before later captures", async () => {
    const first = capture("/first")
    const second = capture("/second")
    const queue = [first, second]
    const attempts: string[] = []
    const delivered: string[] = []
    let shouldFail = true

    const handler = async (item: CapturedRequest) => {
      const path = item.raw.split(" ")[1]!
      attempts.push(path)
      if (item === first && shouldFail) {
        shouldFail = false
        throw new IngestDeliveryError("temporary backend outage", true)
      }
      delivered.push(path)
    }

    const failed = await drainCaptureQueue(queue, handler, "test")
    expect(failed.pending).toBe(2)
    expect(queue[0]).toBe(first)
    expect(delivered).toEqual([])

    const retried = await drainCaptureQueue(queue, handler, "test")
    expect(retried.pending).toBe(0)
    expect(attempts).toEqual(["/first", "/first", "/second"])
    expect(delivered).toEqual(["/first", "/second"])
  })

  test("drops and reports a permanent HTTP rejection without blocking later captures", async () => {
    const queue = [capture("/bad"), capture("/good")]
    const delivered: string[] = []

    const result = await drainCaptureQueue(
      queue,
      async (item) => {
        const path = item.raw.split(" ")[1]!
        if (path === "/bad") throw new IngestDeliveryError("HTTP 400", false, 400)
        delivered.push(path)
      },
      "test",
    )

    expect(result.pending).toBe(0)
    expect(result.rejected).toBe(1)
    expect(permanentlyRejectedCaptureCount(queue)).toBe(1)
    expect(delivered).toEqual(["/good"])
    expect(queue).toHaveLength(0)
  })

  test("bounds final-drain retries and leaves transient failures queued", async () => {
    const queue = [capture("/offline")]
    let attempts = 0

    const result = await drainCaptureQueue(
      queue,
      async () => {
        attempts++
        throw new IngestDeliveryError("offline", true)
      },
      "test",
      { finalDrain: true },
    )

    expect(attempts).toBe(3)
    expect(result.pending).toBe(1)
    expect(queue).toHaveLength(1)
  })
})

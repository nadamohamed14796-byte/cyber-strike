import { expect, test } from "bun:test"
import { createTaskScheduler } from "../../src/tool/task-concurrency"

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

test("bounds sibling fan-out and still admits an independent lane", async () => {
  const scheduler = createTaskScheduler({ maxConcurrent: 2, maxPerLane: 1 })
  const releaseMain = deferred()
  const releaseExtension = deferred()
  const started: string[] = []

  const first = scheduler.enqueue("main", async () => {
    started.push("main-1")
    await releaseMain.promise
  })
  const second = scheduler.enqueue("main", async () => {
    started.push("main-2")
  })
  const independent = scheduler.enqueue("extension", async () => {
    started.push("extension-1")
    await releaseExtension.promise
  })

  expect(first).toBe("started")
  expect(second).toBe("queued")
  expect(independent).toBe("started")
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(started).toEqual(["main-1", "extension-1"])
  expect(scheduler.stats()).toMatchObject({ active: 2, pending: 1 })

  releaseMain.resolve()
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(started).toEqual(["main-1", "extension-1", "main-2"])

  releaseExtension.resolve()
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})

test("releases a scheduler slot after a failed task and preserves FIFO within a lane", async () => {
  const scheduler = createTaskScheduler({ maxConcurrent: 1, maxPerLane: 1 })
  const order: string[] = []
  scheduler.enqueue("proxy", async () => {
    order.push("first")
    throw new Error("expected failure")
  })
  scheduler.enqueue("proxy", async () => {
    order.push("second")
  })
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(order).toEqual(["first", "second"])
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})

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

test("completes every queued sibling in batches of two without a total-dispatch cap", async () => {
  const scheduler = createTaskScheduler({
    maxConcurrent: 4,
    maxPerLane: 2,
    reservedLaneSuffixes: ["impact"],
  })
  const releases: Array<() => void> = []
  const started: number[] = []
  const finished: number[] = []
  const work = Array.from({ length: 9 }, (_, index) =>
    scheduler.enqueue("root:extension", async () => {
      started.push(index)
      await new Promise<void>((resolve) => releases.push(resolve))
      finished.push(index)
    }),
  )

  expect(work).toEqual(["started", "started", ...Array(7).fill("queued")])
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(started).toHaveLength(2)
  expect(scheduler.stats()).toMatchObject({ active: 2, pending: 7 })

  while (finished.length < 9) {
    const release = releases.shift()
    expect(release).toBeDefined()
    release?.()
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(scheduler.stats().active).toBeLessThanOrEqual(2)
  }

  expect(started.sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8])
  expect(finished.sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8])
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})


test("run removes an aborted queued task before it can consume a slot", async () => {
  const scheduler = createTaskScheduler({ maxConcurrent: 1, maxPerLane: 1 })
  const releaseActive = deferred()
  const active = scheduler.run("active", () => releaseActive.promise)
  const controller = new AbortController()
  let queuedTaskStarted = false
  const queued = scheduler.run("queued", async () => {
    queuedTaskStarted = true
  }, controller.signal)

  expect(scheduler.stats()).toMatchObject({ active: 1, pending: 1 })
  controller.abort()
  await expect(queued).rejects.toMatchObject({ name: "AbortError" })
  expect(scheduler.stats()).toMatchObject({ active: 1, pending: 0 })

  releaseActive.resolve()
  await active
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(queuedTaskStarted).toBe(false)
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})

test("enqueue removes an aborted background task and runs its cancellation cleanup once", async () => {
  const scheduler = createTaskScheduler({ maxConcurrent: 1, maxPerLane: 1 })
  const releaseActive = deferred()
  const active = scheduler.run("active", () => releaseActive.promise)
  const controller = new AbortController()
  let queuedTaskStarted = false
  let cancellations = 0

  const result = scheduler.enqueue(
    "queued",
    async () => {
      queuedTaskStarted = true
    },
    undefined,
    controller.signal,
    () => { cancellations++ },
  )
  expect(result).toBe("queued")
  expect(scheduler.stats()).toMatchObject({ active: 1, pending: 1 })

  controller.abort()
  controller.abort()
  expect(cancellations).toBe(1)
  expect(scheduler.stats()).toMatchObject({ active: 1, pending: 0 })

  releaseActive.resolve()
  await active
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(queuedTaskStarted).toBe(false)
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})

test("enqueue immediately cancels when the signal is already aborted", () => {
  const scheduler = createTaskScheduler({ maxConcurrent: 1, maxPerLane: 1 })
  const controller = new AbortController()
  controller.abort()
  let taskStarted = false
  let cancellations = 0

  const result = scheduler.enqueue(
    "queued",
    async () => { taskStarted = true },
    undefined,
    controller.signal,
    () => { cancellations++ },
  )

  expect(result).toBe("cancelled")
  expect(cancellations).toBe(1)
  expect(taskStarted).toBe(false)
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})

test("an already aborted run never enters the scheduler", async () => {
  const scheduler = createTaskScheduler({ maxConcurrent: 1, maxPerLane: 1 })
  const controller = new AbortController()
  controller.abort()
  let taskStarted = false

  await expect(scheduler.run("lane", async () => {
    taskStarted = true
  }, controller.signal)).rejects.toMatchObject({ name: "AbortError" })

  expect(taskStarted).toBe(false)
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})


test("cancellation wins after slot assignment but before the task callback starts", async () => {
  const scheduler = createTaskScheduler({ maxConcurrent: 1, maxPerLane: 1 })
  const controller = new AbortController()
  let taskStarted = false
  let cancellations = 0

  const result = scheduler.enqueue(
    "lane",
    async () => { taskStarted = true },
    undefined,
    controller.signal,
    () => { cancellations++ },
  )
  expect(result).toBe("started")

  // enqueue() grants the slot synchronously, while its task callback is queued
  // in a microtask. Abort in that gap; the callback must never run.
  controller.abort()
  await new Promise((resolve) => setTimeout(resolve, 0))

  expect(taskStarted).toBe(false)
  expect(cancellations).toBe(1)
  expect(scheduler.stats()).toMatchObject({ active: 0, pending: 0 })
})

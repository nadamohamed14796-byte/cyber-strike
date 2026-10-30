import { expect, test } from "bun:test"
import { createToolExecutionQueue } from "../../src/tool/execution-queue"

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

test("serializes tool execution in invocation order", async () => {
  const run = createToolExecutionQueue()
  const firstGate = deferred()
  const started: string[] = []

  const first = run(async () => {
    started.push("first:start")
    await firstGate.promise
    started.push("first:end")
    return "one"
  })
  const second = run(async () => {
    started.push("second")
    return "two"
  })

  await Promise.resolve()
  await Promise.resolve()
  expect(started).toEqual(["first:start"])

  firstGate.resolve()
  await expect(Promise.all([first, second])).resolves.toEqual(["one", "two"])
  expect(started).toEqual(["first:start", "first:end", "second"])
})

test("a failed tool does not block later queued calls", async () => {
  const run = createToolExecutionQueue()
  const order: string[] = []

  const failed = run(async () => {
    order.push("failed")
    throw new Error("expected failure")
  })
  const succeeded = run(async () => {
    order.push("succeeded")
    return "ok"
  })

  await expect(failed).rejects.toThrow("expected failure")
  await expect(succeeded).resolves.toBe("ok")
  expect(order).toEqual(["failed", "succeeded"])
})

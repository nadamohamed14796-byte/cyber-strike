import { expect, test } from "bun:test"
import { createWorkerAbortBridge } from "../../src/tool/hackbrowser-abort-bridge"

test("forwards an abort that happened during preparation only after worker start", () => {
  const controller = new AbortController()
  const events: string[] = []
  const bridge = createWorkerAbortBridge(controller.signal, () => events.push("abort"))

  controller.abort()
  expect(events).toEqual([])

  events.push("start")
  bridge.markStarted()
  expect(events).toEqual(["start", "abort"])
  bridge.dispose()
})

test("forwards an already-aborted signal after the start message", () => {
  const controller = new AbortController()
  controller.abort()
  const events: string[] = []
  const bridge = createWorkerAbortBridge(controller.signal, () => events.push("abort"))

  expect(events).toEqual([])
  events.push("start")
  bridge.markStarted()
  bridge.markStarted()

  expect(events).toEqual(["start", "abort"])
  bridge.dispose()
})

test("forwards a post-start abort once and removes the listener on dispose", () => {
  const controller = new AbortController()
  const events: string[] = []
  const bridge = createWorkerAbortBridge(controller.signal, () => events.push("abort"))

  events.push("start")
  bridge.markStarted()
  controller.abort()
  controller.abort()
  expect(events).toEqual(["start", "abort"])

  bridge.dispose()
  controller.abort()
  expect(events).toEqual(["start", "abort"])
})

test("dispose cancels a buffered abort before the worker starts", () => {
  const controller = new AbortController()
  const events: string[] = []
  const bridge = createWorkerAbortBridge(controller.signal, () => events.push("abort"))

  controller.abort()
  bridge.dispose()
  events.push("start")
  bridge.markStarted()

  expect(events).toEqual(["start"])
})

test("works without an AbortSignal", () => {
  const events: string[] = []
  const bridge = createWorkerAbortBridge(undefined, () => events.push("abort"))

  bridge.markStarted()
  bridge.dispose()

  expect(events).toEqual([])
})

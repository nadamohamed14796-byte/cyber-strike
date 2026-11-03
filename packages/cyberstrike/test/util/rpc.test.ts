import { afterEach, describe, expect, test } from "bun:test"
import { Rpc } from "../../src/util/rpc"

const scope = globalThis as typeof globalThis & {
  onmessage?: ((event: MessageEvent<string>) => unknown) | null
  postMessage?: (message: string) => void
}

const originalOnMessage = Object.getOwnPropertyDescriptor(scope, "onmessage")
const originalPostMessage = Object.getOwnPropertyDescriptor(scope, "postMessage")

type RpcMessageTarget = {
  onmessage: ((this: Worker, event: MessageEvent<any>) => unknown) | null
}

async function dispatch(target: RpcMessageTarget, payload: unknown) {
  const handler = target.onmessage
  if (!handler) throw new Error("RPC message handler is not registered")
  await Reflect.apply(handler, target as unknown as Worker, [
    new MessageEvent("message", { data: JSON.stringify(payload) }),
  ])
}

afterEach(() => {
  if (originalOnMessage) Object.defineProperty(scope, "onmessage", originalOnMessage)
  else Reflect.deleteProperty(scope, "onmessage")

  if (originalPostMessage) Object.defineProperty(scope, "postMessage", originalPostMessage)
  else Reflect.deleteProperty(scope, "postMessage")
})

describe("util.rpc", () => {
  test("returns handler exceptions to the caller instead of leaving requests pending", async () => {
    const responses: string[] = []
    Object.defineProperty(scope, "onmessage", {
      configurable: true,
      writable: true,
      value: null,
    })
    Object.defineProperty(scope, "postMessage", {
      configurable: true,
      writable: true,
      value: (message: string) => responses.push(message),
    })

    Rpc.listen({
      fail: async () => {
        throw new TypeError("worker request failed")
      },
    })

    const handler = scope.onmessage
    expect(handler).toBeFunction()
    await handler!(new MessageEvent("message", {
      data: JSON.stringify({ type: "rpc.request", method: "fail", input: undefined, id: 7 }),
    }))

    expect(responses).toHaveLength(1)
    expect(JSON.parse(responses[0]!)).toMatchObject({
      type: "rpc.error",
      id: 7,
      error: {
        name: "TypeError",
        message: "worker request failed",
      },
    })
  })

  test("rejects a pending client call when the worker returns rpc.error", async () => {
    const sent: string[] = []
    const target = {
      postMessage(message: string) {
        sent.push(message)
      },
      onmessage: null as ((this: Worker, event: MessageEvent<any>) => unknown) | null,
    }
    const client = Rpc.client<{ read: (input: string) => Promise<string> }>(target)

    const pending = client.call("read", "value")
    expect(JSON.parse(sent[0]!)).toMatchObject({
      type: "rpc.request",
      method: "read",
      input: "value",
      id: 0,
    })

    await dispatch(target, {
      type: "rpc.error",
      id: 0,
      error: { name: "TypeError", message: "worker request failed" },
    })

    await expect(pending).rejects.toMatchObject({
      name: "TypeError",
      message: "worker request failed",
    })
  })

  test("rejects in-flight and future calls after the worker fails", async () => {
    const sent: string[] = []
    const target = {
      postMessage(message: string) {
        sent.push(message)
      },
      onmessage: null as ((this: Worker, event: MessageEvent<any>) => unknown) | null,
    }
    const client = Rpc.client<{ read: (input: string) => Promise<string> }>(target)
    const failure = new Error("worker exited during startup")

    const pending = client.call("read", "first")
    client.fail(failure)

    await expect(pending).rejects.toBe(failure)
    await expect(client.call("read", "second")).rejects.toBe(failure)
    expect(sent).toHaveLength(1)
  })

  test("resolves successful calls and continues delivering events", async () => {
    const sent: string[] = []
    const target = {
      postMessage(message: string) {
        sent.push(message)
      },
      onmessage: null as ((this: Worker, event: MessageEvent<any>) => unknown) | null,
    }
    const client = Rpc.client<{ read: (input: string) => Promise<string> }>(target)

    const pending = client.call("read", "value")
    await dispatch(target, { type: "rpc.result", id: 0, result: "ok" })
    await expect(pending).resolves.toBe("ok")

    const received: unknown[] = []
    client.on("ready", (value) => received.push(value))
    await dispatch(target, { type: "rpc.event", event: "ready", data: { state: "up" } })
    expect(received).toEqual([{ state: "up" }])
  })
})

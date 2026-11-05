import { describe, expect, test } from "bun:test"
import { Rpc } from "../../src/util/rpc"

type RpcMessageTarget = {
  addEventListener?: (type: "message", listener: (event: MessageEvent<string>) => void | Promise<void>) => void
  onmessage?: ((event: MessageEvent<string>) => unknown) | null
  postMessage: (message: string) => void
}

async function dispatch(target: { onmessage: ((this: Worker, event: MessageEvent<any>) => unknown) | null }, payload: unknown) {
  const handler = target.onmessage
  if (!handler) throw new Error("RPC message handler is not registered")
  await Reflect.apply(handler, target as unknown as Worker, [
    new MessageEvent("message", { data: JSON.stringify(payload) }),
  ])
}

describe("util.rpc", () => {
  test("returns handler exceptions to the caller instead of leaving requests pending", async () => {
    const responses: string[] = []
    let receive: ((event: MessageEvent<string>) => void | Promise<void>) | undefined
    const target: RpcMessageTarget = {
      addEventListener(_type, listener) {
        receive = listener
      },
      postMessage(message) {
        responses.push(message)
      },
    }

    Rpc.listen(
      {
        fail: async () => {
          throw new TypeError("worker request failed")
        },
      },
      target,
    )

    expect(receive).toBeFunction()
    await receive!(new MessageEvent("message", {
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

  test("uses onmessage when EventTarget listeners are unavailable", async () => {
    const responses: string[] = []
    const target: RpcMessageTarget = {
      onmessage: null,
      postMessage(message) {
        responses.push(message)
      },
    }

    Rpc.listen({ echo: async (input) => input }, target)
    expect(target.onmessage).toBeFunction()
    await target.onmessage!(new MessageEvent("message", {
      data: JSON.stringify({ type: "rpc.request", method: "echo", input: "ok", id: 8 }),
    }))

    expect(JSON.parse(responses[0]!)).toEqual({ type: "rpc.result", result: "ok", id: 8 })
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

  test("receives requests immediately while the worker continues asynchronous startup", async () => {
    const worker = new Worker(new URL("../fixtures/rpc-worker.ts", import.meta.url))
    const client = Rpc.client<{ echo: (input: string) => Promise<string> }>(worker)

    let timeout: ReturnType<typeof setTimeout> | undefined
    let unsubscribe = () => {}
    try {
      await new Promise<void>((resolve, reject) => {
        unsubscribe = client.on("worker.ready", () => resolve())
        timeout = setTimeout(() => reject(new Error("worker RPC transport did not become ready")), 5000)
      })
      if (timeout) clearTimeout(timeout)
      timeout = undefined
      const response = await Promise.race([
        client.call("echo", "sent-during-startup"),
        new Promise<never>((_, reject) => {
          timeout = setTimeout(() => reject(new Error("worker RPC did not answer during startup")), 5000)
        }),
      ])
      expect(response).toBe("sent-during-startup")
    } finally {
      if (timeout) clearTimeout(timeout)
      unsubscribe()
      worker.terminate()
    }
  })
})

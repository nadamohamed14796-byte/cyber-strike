export namespace Rpc {
  type Definition = {
    [method: string]: (input: any) => any
  }

  type SerializedError = {
    name: string
    message: string
    stack?: string
  }

  function serializeError(error: unknown): SerializedError {
    if (error instanceof Error) {
      return {
        name: error.name,
        message: error.message,
        stack: error.stack,
      }
    }

    return {
      name: "Error",
      message: String(error),
    }
  }

  export function listen(rpc: Definition) {
    // Bun's WorkerGlobalScope reliably dispatches incoming messages through
    // EventTarget. Assigning the bare `onmessage` global can leave the handler
    // detached in some Bun worker/module combinations while postMessage still
    // works, which makes every RPC call wait until its client-side timeout.
    const scope = globalThis as typeof globalThis & {
      addEventListener: (type: "message", listener: (event: MessageEvent<string>) => void) => void
      postMessage: (message: string) => void
    }

    scope.addEventListener("message", (evt) => {
      let parsed: { type?: string; method?: string; input?: unknown; id?: number }
      try {
        parsed = JSON.parse(evt.data)
      } catch (error) {
        LogRpcError("Invalid RPC message", error)
        return
      }
      if (parsed.type !== "rpc.request" || typeof parsed.id !== "number") return

      void (async () => {
        try {
          const handler = typeof parsed.method === "string" ? rpc[parsed.method] : undefined
          if (typeof handler !== "function") {
            throw new Error(`Unknown RPC method: ${String(parsed.method)}`)
          }
          const result = await handler(parsed.input)
          scope.postMessage(JSON.stringify({ type: "rpc.result", result, id: parsed.id }))
        } catch (error) {
          scope.postMessage(
            JSON.stringify({
              type: "rpc.error",
              error: serializeError(error),
              id: parsed.id,
            }),
          )
        }
      })()
    })
  }

  function LogRpcError(message: string, error: unknown) {
    // Keep malformed external messages from crashing the worker. The RPC
    // request path itself always returns a correlated error response.
    console.error(message, error)
  }

  export function emit(event: string, data: unknown) {
    postMessage(JSON.stringify({ type: "rpc.event", event, data }))
  }

  export function client<T extends Definition>(target: {
    postMessage: (data: string) => void | null
    onmessage: ((this: Worker, ev: MessageEvent<any>) => any) | null
  }) {
    const pending = new Map<
      number,
      {
        resolve: (result: any) => void
        reject: (error: Error) => void
      }
    >()
    const listeners = new Map<string, Set<(data: any) => void>>()
    let id = 0
    let failure: Error | undefined
    const failPending = (error: unknown) => {
      if (failure) return
      failure = error instanceof Error ? error : new Error(String(error))
      for (const [requestId, request] of pending) {
        pending.delete(requestId)
        request.reject(failure)
      }
    }
    target.onmessage = async (evt) => {
      const parsed = JSON.parse(evt.data)
      if (parsed.type === "rpc.result" || parsed.type === "rpc.error") {
        const request = pending.get(parsed.id)
        if (request) {
          pending.delete(parsed.id)
          if (parsed.type === "rpc.result") {
            request.resolve(parsed.result)
          } else {
            const detail = parsed.error
            const error = new Error(
              typeof detail?.message === "string" ? detail.message : "RPC request failed",
            )
            if (typeof detail?.name === "string") error.name = detail.name
            if (typeof detail?.stack === "string") error.stack = detail.stack
            request.reject(error)
          }
        }
      }
      if (parsed.type === "rpc.event") {
        const handlers = listeners.get(parsed.event)
        if (handlers) {
          for (const handler of handlers) {
            handler(parsed.data)
          }
        }
      }
    }
    return {
      call<Method extends keyof T>(method: Method, input: Parameters<T[Method]>[0]): Promise<ReturnType<T[Method]>> {
        if (failure) return Promise.reject(failure)
        const requestId = id++
        return new Promise((resolve, reject) => {
          pending.set(requestId, { resolve, reject })
          try {
            target.postMessage(JSON.stringify({ type: "rpc.request", method, input, id: requestId }))
          } catch (error) {
            pending.delete(requestId)
            reject(error instanceof Error ? error : new Error(String(error)))
          }
        })
      },
      fail: failPending,
      on<Data>(event: string, handler: (data: Data) => void) {
        let handlers = listeners.get(event)
        if (!handlers) {
          handlers = new Set()
          listeners.set(event, handlers)
        }
        handlers.add(handler)
        return () => {
          handlers!.delete(handler)
          if (handlers!.size === 0) listeners.delete(event)
        }
      },
    }
  }
}

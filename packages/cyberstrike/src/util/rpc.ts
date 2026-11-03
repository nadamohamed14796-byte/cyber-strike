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
    onmessage = async (evt) => {
      const parsed = JSON.parse(evt.data)
      if (parsed.type !== "rpc.request") return

      try {
        const handler = rpc[parsed.method]
        if (typeof handler !== "function") {
          throw new Error(`Unknown RPC method: ${String(parsed.method)}`)
        }
        const result = await handler(parsed.input)
        postMessage(JSON.stringify({ type: "rpc.result", result, id: parsed.id }))
      } catch (error) {
        // Always answer a request, including failures. Otherwise the caller's
        // promise remains pending forever and can block TUI startup.
        postMessage(
          JSON.stringify({
            type: "rpc.error",
            error: serializeError(error),
            id: parsed.id,
          }),
        )
      }
    }
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

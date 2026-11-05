// Keep this worker entrypoint free of top-level awaits and heavyweight static imports.
// Bun can dispatch messages while a worker's module graph is still evaluating; messages
// sent before a handler is installed are dropped. Rpc has no asynchronous dependencies,
// so install the listener first and load the application runtime asynchronously below.
import { Rpc } from "@/util/rpc"

type Event = import("@cyberstrike-io/sdk/v2").Event
type BunWebSocketData = import("hono/bun").BunWebSocketData

type WorkerModules = {
  Installation: typeof import("@/installation").Installation
  Server: typeof import("@/server/server").Server
  Log: typeof import("@/util/log").Log
  Instance: typeof import("@/project/instance").Instance
  InstanceBootstrap: typeof import("@/project/bootstrap").InstanceBootstrap
  upgrade: typeof import("@/cli/upgrade").upgrade
  Config: typeof import("@/config/config").Config
  GlobalBus: typeof import("@/bus/global").GlobalBus
  createCyberstrikeClient: typeof import("@cyberstrike-io/sdk/v2").createCyberstrikeClient
  Flag: typeof import("@/flag/flag").Flag
}

let server: Bun.Server<BunWebSocketData> | undefined
let startup: Promise<WorkerModules> | undefined

const eventStream = {
  abort: undefined as AbortController | undefined,
}

async function initialize(): Promise<WorkerModules> {
  const [
    installationModule,
    serverModule,
    logModule,
    instanceModule,
    bootstrapModule,
    upgradeModule,
    configModule,
    globalBusModule,
    sdkModule,
    flagModule,
  ] = await Promise.all([
    import("@/installation"),
    import("@/server/server"),
    import("@/util/log"),
    import("@/project/instance"),
    import("@/project/bootstrap"),
    import("@/cli/upgrade"),
    import("@/config/config"),
    import("@/bus/global"),
    import("@cyberstrike-io/sdk/v2"),
    import("@/flag/flag"),
  ])

  const modules: WorkerModules = {
    Installation: installationModule.Installation,
    Server: serverModule.Server,
    Log: logModule.Log,
    Instance: instanceModule.Instance,
    InstanceBootstrap: bootstrapModule.InstanceBootstrap,
    upgrade: upgradeModule.upgrade,
    Config: configModule.Config,
    GlobalBus: globalBusModule.GlobalBus,
    createCyberstrikeClient: sdkModule.createCyberstrikeClient,
    Flag: flagModule.Flag,
  }

  await modules.Log.init({
    print: process.argv.includes("--print-logs"),
    dev: modules.Installation.isLocal(),
    level: modules.Installation.isLocal() ? "DEBUG" : "INFO",
  })

  modules.Log.Default.info("TUI worker startup stage", { stage: "worker-module-started" })

  process.on("unhandledRejection", (e) => {
    modules.Log.Default.error("rejection", {
      e: e instanceof Error ? e.message : e,
      name: e instanceof Error ? e.name : undefined,
      stack: e instanceof Error ? e.stack : undefined,
      cause:
        e instanceof Error && e.cause instanceof Error
          ? { name: e.cause.name, message: e.cause.message, stack: e.cause.stack }
          : e instanceof Error
            ? e.cause
            : undefined,
    })
  })

  process.on("uncaughtException", (e) => {
    modules.Log.Default.error("exception", {
      e: e instanceof Error ? e.message : e,
    })
  })

  modules.GlobalBus.on("event", (event) => {
    Rpc.emit("global.event", event)
  })

  startEventStream(process.cwd(), modules)
  modules.Log.Default.info("TUI worker startup stage", { stage: "worker-runtime-ready" })
  return modules
}

function start(): Promise<WorkerModules> {
  if (!startup) {
    let pending: Promise<WorkerModules>
    pending = initialize().catch((error) => {
      if (startup === pending) startup = undefined
      throw error
    })
    startup = pending
  }
  return startup
}

function getAuthorizationHeader(Flag: WorkerModules["Flag"]): string | undefined {
  const password = Flag.CYBERSTRIKE_SERVER_PASSWORD
  if (!password) return undefined
  const username = Flag.CYBERSTRIKE_SERVER_USERNAME ?? "cyberstrike"
  return "Basic " + btoa(username + ":" + password)
}

function startEventStream(directory: string, modules: WorkerModules) {
  if (eventStream.abort) eventStream.abort.abort()
  const abort = new AbortController()
  eventStream.abort = abort
  const signal = abort.signal

  void (async () => {
    const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const auth = getAuthorizationHeader(modules.Flag)
      if (auth) request.headers.set("Authorization", auth)
      return modules.Server.App().fetch(request)
    }) as typeof globalThis.fetch

    const sdk = modules.createCyberstrikeClient({
      baseUrl: "http://cyberstrike.internal",
      directory,
      fetch: fetchFn,
      signal,
    })

    while (!signal.aborted) {
      const events = await Promise.resolve(
        sdk.event.subscribe(
          {},
          {
            signal,
          },
        ),
      ).catch(() => undefined)

      if (!events) {
        await Bun.sleep(250)
        continue
      }

      for await (const event of events.stream) {
        Rpc.emit("event", event as Event)
      }

      if (!signal.aborted) await Bun.sleep(250)
    }
  })().catch((error) => {
    modules.Log.Default.error("event stream error", {
      error: error instanceof Error ? error.message : error,
    })
  })
}

export const rpc = {
  async fetch(input: { url: string; method: string; headers: Record<string, string>; body?: string }) {
    const modules = await start()
    const headers = { ...input.headers }
    const auth = getAuthorizationHeader(modules.Flag)
    if (auth && !headers["authorization"] && !headers["Authorization"]) {
      headers["Authorization"] = auth
    }
    const startedAt = Date.now()
    const request = new Request(input.url, {
      method: input.method,
      headers,
      body: input.body,
    })
    const path = new URL(request.url).pathname
    modules.Log.Default.debug("TUI worker fetch", {
      stage: "request-start",
      method: request.method,
      path,
    })
    const app = modules.Server.App()
    modules.Log.Default.debug("TUI worker fetch", {
      stage: "server-app-ready",
      method: request.method,
      path,
      duration: Date.now() - startedAt,
    })
    const response = await app.fetch(request)
    modules.Log.Default.debug("TUI worker fetch", {
      stage: "response-headers",
      method: request.method,
      path,
      status: response.status,
      duration: Date.now() - startedAt,
    })
    const body = await response.text()
    modules.Log.Default.debug("TUI worker fetch", {
      stage: "response-complete",
      method: request.method,
      path,
      status: response.status,
      bytes: body.length,
      duration: Date.now() - startedAt,
    })
    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body,
    }
  },
  async server(input: { port: number; hostname: string; mdns?: boolean; cors?: string[] }) {
    const modules = await start()
    if (server) await server.stop(true)
    server = modules.Server.listen(input)
    return { url: server.url.toString() }
  },
  async checkUpgrade(input: { directory: string }) {
    const modules = await start()
    await modules.Instance.provide({
      directory: input.directory,
      init: modules.InstanceBootstrap,
      fn: async () => {
        await modules.upgrade().catch(() => {})
      },
    })
  },
  async reload() {
    const modules = await start()
    modules.Config.global.reset()
    await modules.Instance.disposeAll()
  },
  async shutdown() {
    const modules = await start()
    modules.Log.Default.info("worker shutting down")
    if (eventStream.abort) eventStream.abort.abort()
    await modules.Instance.disposeAll()
    if (server) await server.stop(true)
  },
}

// Register the worker message handler before starting imports, initialization, or any
// other asynchronous work. Incoming TUI calls can now wait on start() instead of being lost.
Rpc.listen(rpc)
void start().catch((error) => {
  console.error("TUI worker initialization failed", error)
})

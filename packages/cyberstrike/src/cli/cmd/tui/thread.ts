import { cmd } from "@/cli/cmd/cmd"
import { tui } from "./app"
import { Rpc } from "@/util/rpc"
import { type rpc } from "./worker"
import path from "path"
import { UI } from "@/cli/ui"
import { iife } from "@/util/iife"
import { Log } from "@/util/log"
import { Config } from "@/config/config"
import { withNetworkOptions, resolveNetworkOptions } from "@/cli/network"
import type { Event } from "@cyberstrike-io/sdk/v2"
import type { EventSource } from "./context/sdk"
import { win32DisableProcessedInput, win32InstallCtrlCGuard } from "./win32"

declare global {
  const CYBERSTRIKE_WORKER_PATH: string
}

type RpcClient = ReturnType<typeof Rpc.client<typeof rpc>>

function createWorkerFetch(client: RpcClient): typeof fetch {
  const fn = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init)
    const body = request.body ? await request.text() : undefined
    const result = await new Promise<{ status: number; headers: Record<string, string>; body: string }>(
      (resolve, reject) => {
        const cleanup = () => request.signal.removeEventListener("abort", onAbort)
        const onAbort = () => {
          cleanup()
          reject(request.signal.reason ?? new DOMException("Request aborted", "AbortError"))
        }
        if (request.signal.aborted) {
          onAbort()
          return
        }
        request.signal.addEventListener("abort", onAbort, { once: true })
        client
          .call("fetch", {
            url: request.url,
            method: request.method,
            headers: Object.fromEntries(request.headers.entries()),
            body,
          })
          .then(
            (value) => {
              cleanup()
              resolve(value)
            },
            (error) => {
              cleanup()
              reject(error)
            },
          )
      },
    )
    return new Response(result.body, {
      status: result.status,
      headers: result.headers,
    })
  }
  return fn as typeof fetch
}

function createEventSource(client: RpcClient): EventSource {
  return {
    on: (handler) => client.on<Event>("event", handler),
  }
}

export const TuiThreadCommand = cmd({
  command: "$0 [project]",
  describe: "start cyberstrike tui",
  builder: (yargs) =>
    withNetworkOptions(yargs)
      .positional("project", {
        type: "string",
        describe: "path to start cyberstrike in",
      })
      .option("model", {
        type: "string",
        alias: ["m"],
        describe: "model to use in the format of provider/model",
      })
      .option("continue", {
        alias: ["c"],
        describe: "continue the last session",
        type: "boolean",
      })
      .option("session", {
        alias: ["s"],
        type: "string",
        describe: "session id to continue",
      })
      .option("fork", {
        type: "boolean",
        describe: "fork the session when continuing (use with --continue or --session)",
      })
      .option("prompt", {
        type: "string",
        describe: "prompt to use",
      })
      .option("agent", {
        type: "string",
        describe: "agent to use",
      }),
  handler: async (args) => {
    // Keep ENABLE_PROCESSED_INPUT cleared even if other code flips it.
    // (Important when running under `bun run` wrappers on Windows.)
    const unguard = win32InstallCtrlCGuard()
    try {
      // Must be the very first thing — disables CTRL_C_EVENT before any Worker
      // spawn or async work so the OS cannot kill the process group.
      win32DisableProcessedInput()

      if (args.fork && !args.continue && !args.session) {
        UI.error("--fork requires --continue or --session")
        process.exitCode = 1
        return
      }

      // Resolve relative paths against PWD to preserve behavior when using --cwd flag
      const baseCwd = process.env.PWD ?? process.cwd()
      const cwd = args.project ? path.resolve(baseCwd, args.project) : process.cwd()
      const localWorker = new URL("./worker.ts", import.meta.url)
      const distWorker = new URL("./cli/cmd/tui/worker.js", import.meta.url)
      const workerPath = await iife(async () => {
        if (typeof CYBERSTRIKE_WORKER_PATH !== "undefined") return CYBERSTRIKE_WORKER_PATH
        if (await Bun.file(distWorker).exists()) return distWorker
        return localWorker
      })
      Log.Default.info("TUI startup stage", {
        stage: "worker-path-resolved",
        workerPath: String(workerPath),
        stdinTTY: process.stdin.isTTY,
        stdoutTTY: process.stdout.isTTY,
        cwd,
      })
      try {
        process.chdir(cwd)
      } catch (e) {
        UI.error("Failed to change directory to " + cwd)
        return
      }

      const worker = new Worker(workerPath, {
        env: Object.fromEntries(
          Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
        ),
      })
      Log.Default.info("TUI startup stage", { stage: "worker-created" })
      const client = Rpc.client<typeof rpc>(worker)
      worker.onerror = (e) => {
        const error = e.error instanceof Error ? e.error : new Error(e.message || "CyberStrike worker failed")
        Log.Default.error("TUI worker failed", { error })
        client.fail(error)
      }
      worker.onmessageerror = () => {
        const error = new Error("CyberStrike worker sent an unreadable message")
        Log.Default.error("TUI worker message could not be deserialized", { error })
        client.fail(error)
      }
      process.on("uncaughtException", (e) => {
        Log.Default.error(e)
      })
      process.on("unhandledRejection", (e) => {
        Log.Default.error("rejection", {
          e: e instanceof Error ? e.message : e,
          name: e instanceof Error ? e.name : undefined,
          stack: e instanceof Error ? e.stack : undefined,
          cause: e instanceof Error ? e.cause : undefined,
        })
      })
      process.on("SIGUSR2", async () => {
        await client.call("reload", undefined)
      })

      Log.Default.info("TUI startup stage", {
        stage: "prompt-input-start",
        stdinTTY: process.stdin.isTTY,
        hasPromptArgument: Boolean(args.prompt),
      })
      const prompt = await iife(async () => {
        const piped = !process.stdin.isTTY ? await Bun.stdin.text() : undefined
        if (!args.prompt) return piped
        return piped ? piped + "\n" + args.prompt : args.prompt
      })
      Log.Default.info("TUI startup stage", { stage: "prompt-input-complete", hasPrompt: Boolean(prompt) })

      // Check if server should be started (port or hostname explicitly set in CLI or config)
      Log.Default.info("TUI startup stage", { stage: "network-options-start" })
      const networkOpts = await resolveNetworkOptions(args)
      Log.Default.info("TUI startup stage", { stage: "network-options-complete", networkOpts })
      // Network options have defaults (notably port=4096), so their resolved
      // values cannot tell us whether the user requested an HTTP server.
      // Keep ordinary TUI startup on the lower-overhead worker RPC transport.
      const globalConfig = await Config.global()
      const serverConfigured =
        globalConfig?.server?.port !== undefined ||
        globalConfig?.server?.hostname !== undefined ||
        globalConfig?.server?.mdns === true
      const readyStartedAt = Date.now()
      Log.Default.info("TUI startup stage", { stage: "worker-readiness-start" })
      let readyTimeout: ReturnType<typeof setTimeout> | undefined
      try {
        await Promise.race([
          client.call("ready", undefined),
          new Promise<never>((_, reject) => {
            readyTimeout = setTimeout(
              () => reject(new Error("Local engine did not become ready within 90 seconds")),
              90_000,
            )
          }),
        ])
        Log.Default.info("TUI startup stage", {
          stage: "worker-readiness-complete",
          duration: Date.now() - readyStartedAt,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        Log.Default.error("TUI worker readiness failed", { error: message })
        client.fail(error)
        worker.terminate()
        UI.error("Failed to initialize the local engine: " + message)
        process.exitCode = 1
        return
      } finally {
        if (readyTimeout) clearTimeout(readyTimeout)
      }
      const explicitlySet = (name: string) =>
        process.argv.some((value) => value === `--${name}` || value.startsWith(`--${name}=`))
      const shouldStartServer =
        explicitlySet("port") ||
        explicitlySet("hostname") ||
        explicitlySet("mdns") ||
        explicitlySet("mdns-domain") ||
        explicitlySet("cors") ||
        serverConfigured ||
        networkOpts.mdns ||
        networkOpts.hostname !== "127.0.0.1"
      Log.Default.info("TUI startup stage", {
        stage: shouldStartServer ? "server-start-selected" : "direct-rpc-selected",
        serverConfigured,
        networkOpts,
      })

      let url: string
      let customFetch: typeof fetch | undefined
      let events: EventSource | undefined

      if (shouldStartServer) {
        // Start HTTP server for external access
        try {
          const server = await client.call("server", networkOpts)
          url = server.url
        } catch (e) {
          UI.error(`Failed to start server on port ${networkOpts.port}. The port may already be in use.`)
          process.exitCode = 1
          return
        }
      } else {
        // Use direct RPC communication (no HTTP)
        url = "http://cyberstrike.internal"
        customFetch = createWorkerFetch(client)
        events = createEventSource(client)
      }

      Log.Default.info("TUI startup stage", {
        stage: "tui-call",
        url,
        directRPC: !shouldStartServer,
      })
      const tuiPromise = tui({
        url,
        fetch: customFetch,
        events,
        args: {
          continue: args.continue,
          sessionID: args.session,
          agent: args.agent,
          model: args.model,
          prompt,
          fork: args.fork,
        },
        onExit: async () => {
          await client.call("shutdown", undefined)
        },
      })

      setTimeout(() => {
        client.call("checkUpgrade", { directory: cwd }).catch(() => {})
      }, 1000)

      Log.Default.info("TUI startup stage", { stage: "tui-promise-await" })
      await tuiPromise
      Log.Default.info("TUI startup stage", { stage: "tui-exited" })
    } finally {
      unguard?.()
    }
  },
})

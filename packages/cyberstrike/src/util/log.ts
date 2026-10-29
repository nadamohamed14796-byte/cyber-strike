import path from "path"
import fs from "fs/promises"
import { Global } from "../global"
import z from "zod"

export namespace Log {
  export const Level = z.enum(["DEBUG", "INFO", "WARN", "ERROR"]).meta({ ref: "LogLevel", description: "Log level" })
  export type Level = z.infer<typeof Level>

  const levelPriority: Record<Level, number> = {
    DEBUG: 0,
    INFO: 1,
    WARN: 2,
    ERROR: 3,
  }

  let level: Level = "INFO"

  function shouldLog(input: Level): boolean {
    return levelPriority[input] >= levelPriority[level]
  }

  export type Logger = {
    debug(message?: any, extra?: Record<string, any>): void
    info(message?: any, extra?: Record<string, any>): void
    error(message?: any, extra?: Record<string, any>): void
    warn(message?: any, extra?: Record<string, any>): void
    tag(key: string, value: string): Logger
    clone(): Logger
    time(
      message: string,
      extra?: Record<string, any>,
    ): {
      stop(): void
      [Symbol.dispose](): void
    }
  }

  const loggers = new Map<string, Logger>()

  export const Default = create({ service: "default" })

  export interface Options {
    print: boolean
    dev?: boolean
    level?: Level
  }

  let logpath = ""
  export const MAX_LOG_FILE_BYTES = 16 * 1024 * 1024
  export const MAX_LOG_FILES = 10
  export const MAX_TOTAL_LOG_BYTES = 128 * 1024 * 1024
  const LOG_FILE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}[.]log$/
  let logBytesWritten = 0
  let logLimitReached = false
  export function file() {
    return logpath
  }
  let write = (msg: any) => {
    process.stderr.write(msg)
    return msg.length
  }

  export async function init(options: Options) {
    if (options.level) level = options.level
    await cleanup(Global.Path.log)
    if (options.print) return
    logpath = path.join(
      Global.Path.log,
      options.dev ? "dev.log" : new Date().toISOString().split(".")[0].replace(/:/g, "") + ".log",
    )
    const logfile = Bun.file(logpath)
    await fs.truncate(logpath).catch(() => {})
    const writer = logfile.writer()
    logBytesWritten = 0
    logLimitReached = false
    write = (msg: any) => {
      if (logLimitReached) return 0
      const value = typeof msg === "string" ? msg : String(msg)
      const incomingBytes = Buffer.byteLength(value, "utf-8")
      if (logBytesWritten + incomingBytes > MAX_LOG_FILE_BYTES) {
        const marker = String.fromCharCode(10) + "[CyberStrike log limit reached; later log entries omitted to protect disk space.]" + String.fromCharCode(10)
        const markerBytes = Buffer.byteLength(marker, "utf-8")
        if (logBytesWritten + markerBytes <= MAX_LOG_FILE_BYTES) {
          writer.write(marker)
          writer.flush()
          logBytesWritten += markerBytes
        }
        logLimitReached = true
        return value.length
      }
      const num = writer.write(value)
      writer.flush()
      logBytesWritten += incomingBytes
      return num
    }
  }

  async function cleanup(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => [])
    const files: Array<{ path: string; mtimeMs: number; size: number }> = []
    for (const entry of entries) {
      if (!entry.isFile() || !LOG_FILE_PATTERN.test(entry.name)) continue
      const filepath = path.join(dir, entry.name)
      const info = await fs.stat(filepath).catch(() => undefined)
      if (!info?.isFile()) continue
      files.push({ path: filepath, mtimeMs: info.mtimeMs, size: info.size })
    }
    files.sort((a, b) => a.mtimeMs - b.mtimeMs || a.path.localeCompare(b.path))
    let totalBytes = files.reduce((sum, file) => sum + file.size, 0)
    let retainedCount = files.length
    for (const file of files) {
      if (retainedCount <= MAX_LOG_FILES && totalBytes <= MAX_TOTAL_LOG_BYTES) break
      await fs.unlink(file.path).catch(() => {})
      totalBytes -= file.size
      retainedCount--
    }
  }

  function formatError(error: Error, depth = 0): string {
    const result = error.message
    return error.cause instanceof Error && depth < 10
      ? result + " Caused by: " + formatError(error.cause, depth + 1)
      : result
  }

  let last = Date.now()
  export function create(tags?: Record<string, any>) {
    tags = tags || {}

    const service = tags["service"]
    if (service && typeof service === "string") {
      const cached = loggers.get(service)
      if (cached) {
        return cached
      }
    }

    function build(message: any, extra?: Record<string, any>) {
      const prefix = Object.entries({
        ...tags,
        ...extra,
      })
        .filter(([_, value]) => value !== undefined && value !== null)
        .map(([key, value]) => {
          const prefix = `${key}=`
          if (value instanceof Error) return prefix + formatError(value)
          if (typeof value === "object") return prefix + JSON.stringify(value)
          return prefix + value
        })
        .join(" ")
      const next = new Date()
      const diff = next.getTime() - last
      last = next.getTime()
      return [next.toISOString().split(".")[0], "+" + diff + "ms", prefix, message].filter(Boolean).join(" ") + "\n"
    }
    const result: Logger = {
      debug(message?: any, extra?: Record<string, any>) {
        if (shouldLog("DEBUG")) {
          write("DEBUG " + build(message, extra))
        }
      },
      info(message?: any, extra?: Record<string, any>) {
        if (shouldLog("INFO")) {
          write("INFO  " + build(message, extra))
        }
      },
      error(message?: any, extra?: Record<string, any>) {
        if (shouldLog("ERROR")) {
          write("ERROR " + build(message, extra))
        }
      },
      warn(message?: any, extra?: Record<string, any>) {
        if (shouldLog("WARN")) {
          write("WARN  " + build(message, extra))
        }
      },
      tag(key: string, value: string) {
        if (tags) tags[key] = value
        return result
      },
      clone() {
        return Log.create({ ...tags })
      },
      time(message: string, extra?: Record<string, any>) {
        const now = Date.now()
        result.info(message, { status: "started", ...extra })
        function stop() {
          result.info(message, {
            status: "completed",
            duration: Date.now() - now,
            ...extra,
          })
        }
        return {
          stop,
          [Symbol.dispose]() {
            stop()
          },
        }
      },
    }

    if (service && typeof service === "string") {
      loggers.set(service, result)
    }

    return result
  }
}

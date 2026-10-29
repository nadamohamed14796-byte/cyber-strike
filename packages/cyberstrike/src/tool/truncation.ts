import fs from "fs/promises"
import path from "path"
import { Global } from "../global"
import { Identifier } from "../id/id"
import { PermissionNext } from "../permission/next"
import type { Agent } from "../agent/agent"
import { Scheduler } from "../scheduler"

export namespace Truncate {
  export const MAX_LINES = 2000
  export const MAX_BYTES = 50 * 1024
  export const DIR = path.join(Global.Path.data, "tool-output")
  export const GLOB = path.join(DIR, "*")
  const RETENTION_MS = 7 * 24 * 60 * 60 * 1000 // 7 days
  const HOUR_MS = 60 * 60 * 1000
  // Generated tool-output artifacts are temporary; bound individual and total disk usage.
  export const MAX_OUTPUT_FILE_BYTES = 8 * 1024 * 1024
  export const MAX_TOTAL_OUTPUT_BYTES = 128 * 1024 * 1024
  const TOOL_OUTPUT_PREFIX = "tool_"
  type OutputFile = { name: string; filepath: string; size: number; createdAt: number }
  let storageQueue: Promise<void> = Promise.resolve()

  export type Result = { content: string; truncated: false } | { content: string; truncated: true; outputPath: string }

  // Synchronous hard byte cap for a single string, keeping the head (where the
  // useful content usually is) and appending a caller-supplied note. Unlike
  // output() it persists nothing — for cases where the full text is available
  // elsewhere (a tool the agent can re-call) or simply isn't worth keeping.
  export function cap(text: string, maxBytes: number, note: (shown: number, total: number) => string): string {
    const total = Buffer.byteLength(text, "utf-8")
    if (total <= maxBytes) return text
    const head = Buffer.from(text, "utf-8").subarray(0, maxBytes).toString("utf-8")
    return `${head}\n\n${note(maxBytes, total)}`
  }

  // Hard byte cap for tool ERROR strings. Guards against a single huge error
  // (e.g. a DeniedError or a multi-MB stack/dump) blowing the model context.
  export const MAX_ERROR_BYTES = 50 * 1024
  export function error(text: string, maxBytes: number = MAX_ERROR_BYTES): string {
    return cap(text, maxBytes, (shown, total) => `...[error truncated: showing ${shown} of ${total} bytes]`)
  }

  export interface Options {
    maxLines?: number
    maxBytes?: number
    direction?: "head" | "tail"
  }

  export function init() {
    Scheduler.register({
      id: "tool.truncation.cleanup",
      interval: HOUR_MS,
      run: cleanup,
      scope: "global",
    })
  }

  function serializeStorage<T>(action: () => Promise<T>): Promise<T> {
    const result = storageQueue.then(action, action)
    storageQueue = result.then(() => undefined, () => undefined)
    return result
  }

  async function listOutputFiles(): Promise<OutputFile[]> {
    const entries = await fs.readdir(DIR, { withFileTypes: true }).catch(() => [])
    const files: OutputFile[] = []
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.startsWith(TOOL_OUTPUT_PREFIX)) continue
      const filepath = path.join(DIR, entry.name)
      const info = await fs.stat(filepath).catch(() => undefined)
      if (!info?.isFile()) continue
      let idTimestamp = 0
      try {
        idTimestamp = Identifier.timestamp(entry.name)
      } catch {
        // Malformed temporary-file names use filesystem time for pruning.
      }
      files.push({
        name: entry.name,
        filepath,
        size: info.size,
        createdAt: Number.isFinite(idTimestamp) && idTimestamp > 0 ? idTimestamp : info.mtimeMs,
      })
    }
    return files
  }

  async function cleanupUnlocked(): Promise<void> {
    const cutoff = Date.now() - RETENTION_MS
    const files = await listOutputFiles()
    let retained = files.filter((file) => file.createdAt >= cutoff)
    for (const file of files) {
      if (file.createdAt >= cutoff) continue
      await fs.unlink(file.filepath).catch(() => {})
    }
    let totalBytes = retained.reduce((sum, file) => sum + file.size, 0)
    retained.sort((a, b) => a.createdAt - b.createdAt || a.name.localeCompare(b.name))
    while (totalBytes > MAX_TOTAL_OUTPUT_BYTES && retained.length > 0) {
      const oldest = retained.shift()!
      await fs.unlink(oldest.filepath).catch(() => {})
      totalBytes -= oldest.size
    }
  }

  export async function cleanup() {
    await serializeStorage(cleanupUnlocked)
  }

  function boundedStoredOutput(text: string): { content: string; truncated: boolean; originalBytes: number } {
    const original = Buffer.from(text, "utf-8")
    if (original.byteLength <= MAX_OUTPUT_FILE_BYTES) {
      return { content: text, truncated: false, originalBytes: original.byteLength }
    }
    const notice = "\n\n[CyberStrike disk safeguard: saved output capped at " + MAX_OUTPUT_FILE_BYTES + " bytes; original was " + original.byteLength + " bytes. Beginning and end retained.]\n\n"
    const available = MAX_OUTPUT_FILE_BYTES - Buffer.byteLength(notice, "utf-8")
    const headBytes = Math.floor(available * 0.7)
    const tailBytes = available - headBytes
    const head = original.subarray(0, headBytes).toString("utf-8")
    const tail = original.subarray(original.byteLength - tailBytes).toString("utf-8")
    return { content: head + notice + tail, truncated: true, originalBytes: original.byteLength }
  }

  function hasTaskTool(agent?: Agent.Info): boolean {
    if (!agent?.permission) return false
    const rule = PermissionNext.evaluate("task", "*", agent.permission)
    return rule.action !== "deny"
  }

  export async function output(text: string, options: Options = {}, agent?: Agent.Info): Promise<Result> {
    const maxLines = options.maxLines ?? MAX_LINES
    const maxBytes = options.maxBytes ?? MAX_BYTES
    const direction = options.direction ?? "head"
    const totalBytes = Buffer.byteLength(text)

    // Count lines without split("\n"): splitting a multi-megabyte tool result
    // allocates an array and a string entry for every line before truncation.
    let totalLines = 1
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) totalLines++
    }

    if (totalLines <= maxLines && totalBytes <= maxBytes) {
      return { content: text, truncated: false }
    }

    const out: string[] = []
    let bytes = 0
    let hitBytes = false

    if (direction === "head") {
      let lineStart = 0
      while (lineStart <= text.length && out.length < maxLines) {
        const newline = text.indexOf("\n", lineStart)
        const lineEnd = newline === -1 ? text.length : newline
        const line = text.slice(lineStart, lineEnd)
        const size = Buffer.byteLength(line, "utf-8") + (out.length > 0 ? 1 : 0)
        if (bytes + size > maxBytes) {
          hitBytes = true
          break
        }
        out.push(line)
        bytes += size
        if (newline === -1) break
        lineStart = newline + 1
      }
    } else {
      let lineEnd = text.length
      while (lineEnd >= 0 && out.length < maxLines) {
        const newline = text.lastIndexOf("\n", lineEnd - 1)
        const lineStart = newline + 1
        const line = text.slice(lineStart, lineEnd)
        const size = Buffer.byteLength(line, "utf-8") + (out.length > 0 ? 1 : 0)
        if (bytes + size > maxBytes) {
          hitBytes = true
          break
        }
        out.unshift(line)
        bytes += size
        if (newline === -1) break
        lineEnd = newline
      }
    }

    const removed = hitBytes ? totalBytes - bytes : totalLines - out.length
    const unit = hitBytes ? "bytes" : "lines"
    const preview = out.join("\n")

    const id = Identifier.ascending("tool")
    const filepath = path.join(DIR, id)
    const saved = boundedStoredOutput(text)
    await serializeStorage(async () => {
      await fs.mkdir(DIR, { recursive: true })
      await cleanupUnlocked()
      const existing = (await listOutputFiles()).sort((a, b) => a.createdAt - b.createdAt || a.name.localeCompare(b.name))
      let totalBytes = existing.reduce((sum, file) => sum + file.size, 0)
      while (totalBytes + Buffer.byteLength(saved.content, "utf-8") > MAX_TOTAL_OUTPUT_BYTES && existing.length > 0) {
        const oldest = existing.shift()!
        await fs.unlink(oldest.filepath).catch(() => {})
        totalBytes -= oldest.size
      }
      await Bun.write(Bun.file(filepath), saved.content)
    })

    const savedNote = saved.truncated
      ? ` The saved artifact was capped at ${MAX_OUTPUT_FILE_BYTES} bytes (original: ${saved.originalBytes} bytes); its beginning and end were retained.`
      : ""
    const hint = hasTaskTool(agent)
      ? `The tool call succeeded but the output was truncated.${savedNote} Saved output: ${filepath}\nUse the Task tool to have explore agent process this file with Grep and Read (with offset/limit). Do NOT read the full file yourself - delegate to save context.`
      : `The tool call succeeded but the output was truncated.${savedNote} Saved output: ${filepath}\nUse Grep to search the saved content or Read with offset/limit to view specific sections.`
    const message =
      direction === "head"
        ? `${preview}\n\n...${removed} ${unit} truncated...\n\n${hint}`
        : `...${removed} ${unit} truncated...\n\n${hint}\n\n${preview}`

    return { content: message, truncated: true, outputPath: filepath }
  }
}

import { Identifier } from "../id/id"
import { Database, and, count, eq, notInArray } from "../storage/db"
import {
  WebFunctionTable,
  WebObjectTable,
  WebRoleTable,
  WebCredentialTable,
  VulnerabilityTable,
} from "./session.sql"
import { Session } from "."

export namespace IngestSummary {
  export const KIND = "ingest-summary"

  export interface Snapshot {
    functions: number
    objects: number
    roles: number
    credentials: number
    vulnerabilities: number
  }

  export function snapshot(sessionID: string): Snapshot {
    // Snapshot is called before and after every captured request. Use SQL COUNTs
    // rather than materializing every evidence row just to read array lengths;
    // large proxy histories otherwise allocate the full evidence inventory twice
    // per request even though only five integers are needed.
    return Database.use((db) => ({
      functions: db.select({ value: count() }).from(WebFunctionTable)
        .where(eq(WebFunctionTable.session_id, sessionID)).get()?.value ?? 0,
      objects: db.select({ value: count() }).from(WebObjectTable)
        .where(eq(WebObjectTable.session_id, sessionID)).get()?.value ?? 0,
      roles: db.select({ value: count() }).from(WebRoleTable)
        .where(eq(WebRoleTable.session_id, sessionID)).get()?.value ?? 0,
      credentials: db.select({ value: count() }).from(WebCredentialTable)
        .where(eq(WebCredentialTable.session_id, sessionID)).get()?.value ?? 0,
      vulnerabilities: db.select({ value: count() }).from(VulnerabilityTable)
        .where(and(
          eq(VulnerabilityTable.session_id, sessionID),
          notInArray(VulnerabilityTable.status, ["duplicate"]),
        )).get()?.value ?? 0,
    }))
  }

  const LABELS: Record<keyof Snapshot, string> = {
    functions: "function",
    objects: "object",
    roles: "role",
    credentials: "credential",
    vulnerabilities: "vulnerability",
  }

  export function formatDelta(before: Snapshot, after: Snapshot): string | null {
    const parts: string[] = []
    for (const key of Object.keys(LABELS) as (keyof Snapshot)[]) {
      const delta = after[key] - before[key]
      if (delta === 0) continue
      const sign = delta > 0 ? "+" : ""
      parts.push(`${sign}${delta} ${LABELS[key]}`)
    }
    return parts.length > 0 ? parts.join(", ") : null
  }

  export interface WriteInput {
    sessionID: string
    agent: string
    model: { providerID: string; modelID: string }
    source: string
    before: Snapshot
    after: Snapshot
    /** Return the summary without appending a synthetic user turn to a persistent agent conversation. */
    transcript?: boolean
  }

  /** Add a non-agent notification to the parent transcript. This makes extension
   * intake and completion visible in the active window without starting or
   * interrupting the parent agent. */
  export async function notice(sessionID: string, text: string): Promise<void> {
    // Routine intake/queue/dedup/completion status belongs in logs and the
    // live analysis panel, not the conversation transcript. Keep only actionable
    // parse failures visible because no analysis panel will be created for them.
    if (!text.startsWith("Extension request rejected before analysis:")) return
    const { SessionPrompt } = await import("./prompt")
    const model = await SessionPrompt.lastModel(sessionID)
    const messageID = Identifier.ascending("message")
    await Session.updateMessage({
      id: messageID,
      role: "user",
      sessionID,
      time: { created: Date.now() },
      agent: "proxy-agent",
      model,
      // Parent-visible Extension notices are UI status, never Main Agent input.
      excludeHistory: true,
    })
    await Session.updatePart({
      id: Identifier.ascending("part"),
      messageID,
      sessionID,
      type: "text",
      text,
      time: { start: Date.now(), end: Date.now() },
      metadata: { kind: KIND, notice: true },
    })
  }

  export type RequestAnalysisStatus = "analyzing" | "processed" | "failed"

  export interface RequestAnalysis {
    requestID: string
    analysisSessionID?: string
    method: string
    url: string
    status: RequestAnalysisStatus
  }

  export interface LiveNotice {
    messageID: string
    partID: string
    startedAt: number
    requestAnalysis: Omit<RequestAnalysis, "status">
  }

  // Keep each captured request's parent-side entry independently addressable.
  // The Proxy Agent session is shared across requests, but request status and
  // streaming output must never overwrite another request's panel entry.
  const activeLiveNotices = new Map<string, LiveNotice>()
  const liveNoticeLocks = new Map<string, Promise<void>>()

  function liveNoticeKey(sessionID: string, requestID: string) {
    return sessionID + "\\0" + requestID
  }

  async function withLiveNoticeLock<T>(sessionID: string, run: () => Promise<T>): Promise<T> {
    const previous = liveNoticeLocks.get(sessionID) ?? Promise.resolve()
    let release!: () => void
    const current = new Promise<void>((resolve) => {
      release = resolve
    })
    liveNoticeLocks.set(sessionID, current)
    await previous
    try {
      return await run()
    } finally {
      release()
      if (liveNoticeLocks.get(sessionID) === current) liveNoticeLocks.delete(sessionID)
    }
  }

  /** Create one durable parent-transcript entry per captured request. */
  export async function createLiveNotice(input: {
    sessionID: string
    agent: string
    model: { providerID: string; modelID: string }
    text: string
    requestAnalysis: Omit<RequestAnalysis, "status">
  }): Promise<LiveNotice> {
    return withLiveNoticeLock(input.sessionID, async () => {
      const startedAt = Date.now()
      const messageID = Identifier.ascending("message")
      const partID = Identifier.ascending("part")
      await Session.updateMessage({
        id: messageID,
        role: "user",
        sessionID: input.sessionID,
        time: { created: startedAt },
        agent: input.agent,
        model: input.model,
        // The panel reads this metadata, but it must not enter Main Agent history.
        excludeHistory: true,
      })
      await Session.updatePart({
        id: partID,
        messageID,
        sessionID: input.sessionID,
        type: "text",
        text: input.text,
        time: { start: startedAt },
        metadata: {
          kind: KIND,
          notice: true,
          live: true,
          requestAnalysis: { ...input.requestAnalysis, status: "analyzing" satisfies RequestAnalysisStatus },
        },
      })
      const live = { messageID, partID, startedAt, requestAnalysis: input.requestAnalysis }
      activeLiveNotices.set(liveNoticeKey(input.sessionID, input.requestAnalysis.requestID), live)
      return live
    })
  }

  /** Update only the matching request entry; stale writes cannot affect another capture. */
  export async function updateLiveNotice(input: {
    sessionID: string
    live: LiveNotice
    text: string
    completed?: boolean
    status?: RequestAnalysisStatus
  }): Promise<void> {
    await withLiveNoticeLock(input.sessionID, async () => {
      const key = liveNoticeKey(input.sessionID, input.live.requestAnalysis.requestID)
      const active = activeLiveNotices.get(key)
      if (!active || active.partID !== input.live.partID) return
      await Session.updatePart({
        id: input.live.partID,
        messageID: input.live.messageID,
        sessionID: input.sessionID,
        type: "text",
        text: input.text,
        time: {
          start: input.live.startedAt,
          ...(input.completed ? { end: Date.now() } : {}),
        },
        metadata: {
          kind: KIND,
          notice: true,
          live: !input.completed,
          requestAnalysis: {
            ...input.live.requestAnalysis,
            status: input.status ?? "analyzing",
          },
        },
      })
      if (input.completed) activeLiveNotices.delete(key)
    })
  }

  export async function write(input: WriteInput): Promise<string | null> {
    const delta = formatDelta(input.before, input.after)
    if (!delta) return null
    const summary = `Ingest processed: ${input.source} — ${delta}`
    if (input.transcript === false) return summary

    const messageID = Identifier.ascending("message")
    await Session.updateMessage({
      id: messageID,
      role: "user",
      sessionID: input.sessionID,
      time: { created: Date.now() },
      agent: input.agent,
      model: input.model,
    })
    await Session.updatePart({
      id: Identifier.ascending("part"),
      messageID,
      sessionID: input.sessionID,
      type: "text",
      text: summary,
      time: { start: Date.now(), end: Date.now() },
      metadata: { kind: KIND },
    })
    return summary
  }
}

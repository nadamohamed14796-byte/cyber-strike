import { Identifier } from "../id/id"
import { Session } from "."
import { WebFunction } from "./web/web-function"
import { WebObject } from "./web/web-object"
import { WebRole } from "./web/web-role"
import { WebCredential } from "./web/web-credential"
import { Vulnerability } from "./vulnerability"

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
    return {
      functions: WebFunction.get(sessionID).length,
      objects: WebObject.get(sessionID).length,
      roles: WebRole.get(sessionID).length,
      credentials: WebCredential.get(sessionID).length,
      vulnerabilities: Vulnerability.confirmed(sessionID).length,
    }
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
  }

  /** Add a non-agent notification to the parent transcript. This makes extension
   * intake and completion visible in the active window without starting or
   * interrupting the parent agent. */
  export async function notice(sessionID: string, text: string): Promise<void> {
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

  /** Create one parent-transcript entry that can be updated as the subagent streams.
   * Keeping one stable part per captured request makes the live analysis visible
   * without flooding the transcript with a new message for every token. */
  export async function createLiveNotice(input: {
    sessionID: string
    agent: string
    model: { providerID: string; modelID: string }
    text: string
    requestAnalysis: Omit<RequestAnalysis, "status">
  }): Promise<LiveNotice> {
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
    return { messageID, partID, startedAt, requestAnalysis: input.requestAnalysis }
  }

  /** Update the same visible transcript entry while the captured request is analyzed. */
  export async function updateLiveNotice(input: {
    sessionID: string
    live: LiveNotice
    text: string
    completed?: boolean
    status?: RequestAnalysisStatus
  }): Promise<void> {
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
  }

  export async function write(input: WriteInput): Promise<void> {
    const delta = formatDelta(input.before, input.after)
    if (!delta) return

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
      text: `Ingest processed: ${input.source} — ${delta}`,
      time: { start: Date.now(), end: Date.now() },
      metadata: { kind: KIND },
    })
  }
}

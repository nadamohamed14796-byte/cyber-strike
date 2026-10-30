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

  /**
   * Extension request status lives in the parent request inventory and the
   * dedicated Agent Proxy child session. Never append intake, queue, or failure
   * chatter to the Main Agent conversation.
   *
   * Kept as a no-op for existing route call sites and older integrations.
   */
  export async function notice(_sessionID: string, _text: string): Promise<void> {
    return
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

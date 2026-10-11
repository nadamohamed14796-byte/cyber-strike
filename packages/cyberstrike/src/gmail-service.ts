/**
 * Shared, read-only Gmail access for CyberStrike agents.
 *
 * OAuth secrets are read only from the process environment and never returned,
 * persisted, or logged. Email bodies are untrusted input and must not be treated
 * as instructions. This module intentionally has no send/delete/modify methods.
 */
import { extractOtpCode } from "./gmail-otp"
import { normalizeAuthOrigin } from "./auth-vault"

const SCOPES_DOC = "https://www.googleapis.com/auth/gmail.readonly"
const MAX_SEARCH_RESULTS = 10
const MAX_BODY_CHARS = 12_000
let cachedAccessToken: { value: string; expiresAt: number } | undefined

type Header = { name?: string; value?: string }
type Part = { mimeType?: string; filename?: string; body?: { data?: string }; parts?: Part[] }
type MessageRef = { id: string; threadId?: string }
type Message = {
  id: string
  threadId?: string
  internalDate?: string
  snippet?: string
  payload?: { headers?: Header[]; mimeType?: string; body?: { data?: string }; parts?: Part[] }
}
export type GmailMessageSummary = {
  id: string
  threadId?: string
  from: string
  to: string
  subject: string
  date: string
  snippet: string
}
export type GmailMessageContent = GmailMessageSummary & { body: string }
export type GmailOtpResult = GmailMessageSummary & { code: string; receivedAt: number }

function env(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`Gmail is not configured: set ${name} in the CyberStrike process environment after completing Google OAuth consent.`)
  return value
}
function configured(): boolean {
  return !!(process.env.CYBERSTRIKE_GMAIL_OAUTH_CLIENT_ID?.trim() &&
    process.env.CYBERSTRIKE_GMAIL_OAUTH_CLIENT_SECRET?.trim() &&
    process.env.CYBERSTRIKE_GMAIL_OAUTH_REFRESH_TOKEN?.trim())
}
function header(message: Message, name: string): string {
  return message.payload?.headers?.find((item) => item.name?.toLowerCase() === name.toLowerCase())?.value ?? ""
}
function decodeBase64Url(value: string): string {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")
}
function bodyText(part?: Part): string {
  if (!part || part.filename) return ""
  const own = part.body?.data && (!part.mimeType || part.mimeType === "text/plain" || part.mimeType === "text/html")
    ? decodeBase64Url(part.body.data).slice(0, MAX_BODY_CHARS).replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&")
    : ""
  const nested = (part.parts ?? []).map(bodyText).filter(Boolean).join("\n")
  return [own, nested].filter(Boolean).join("\n").slice(0, MAX_BODY_CHARS)
}

/** Strict domain boundary: exact host or a true subdomain, never a suffix lookalike. */
export function isAllowedSiteSender(from: string, siteUrl: string): boolean {
  const origin = normalizeAuthOrigin(siteUrl)
  const siteHost = new URL(origin).hostname.toLowerCase().replace(/^www\./, "")
  const senderHost = /@([^\s>]+)/.exec(from)?.[1]?.replace(/[>),;]+$/, "").toLowerCase()
  return !!senderHost && (senderHost === siteHost || senderHost.endsWith(`.${siteHost}`))
}

function summary(message: Message): GmailMessageSummary {
  const receivedAt = Number(message.internalDate ?? 0)
  return {
    id: message.id,
    ...(message.threadId ? { threadId: message.threadId } : {}),
    from: header(message, "From"),
    to: header(message, "To"),
    subject: header(message, "Subject"),
    date: receivedAt ? new Date(receivedAt).toISOString() : header(message, "Date"),
    snippet: (message.snippet ?? "").slice(0, 500),
  }
}
async function accessToken(): Promise<string> {
  if (cachedAccessToken && cachedAccessToken.expiresAt > Date.now() + 30_000) return cachedAccessToken.value
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env("CYBERSTRIKE_GMAIL_OAUTH_CLIENT_ID"),
      client_secret: env("CYBERSTRIKE_GMAIL_OAUTH_CLIENT_SECRET"),
      refresh_token: env("CYBERSTRIKE_GMAIL_OAUTH_REFRESH_TOKEN"),
      grant_type: "refresh_token",
    }),
  })
  if (!response.ok) throw new Error(`Google OAuth token refresh failed (HTTP ${response.status}); re-authorize Gmail OAuth if the refresh token was revoked.`)
  const data = await response.json() as { access_token?: string; expires_in?: number }
  if (!data.access_token) throw new Error("Google OAuth did not return an access token.")
  cachedAccessToken = { value: data.access_token, expiresAt: Date.now() + Math.max(60, data.expires_in ?? 3600) * 1000 }
  return data.access_token
}
async function gmailFetch<T>(path: string, token: string): Promise<T> {
  const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/${path}`, {
    headers: { authorization: `Bearer ${token}` },
  })
  if (!response.ok) throw new Error(`Gmail API request failed (HTTP ${response.status}). Confirm Gmail API is enabled and OAuth includes ${SCOPES_DOC}.`)
  return await response.json() as T
}

export namespace GmailService {
  export function status() {
    return { configured: configured(), scope: SCOPES_DOC, capabilities: ["search", "read", "otp"], readOnly: true as const }
  }

  export async function search(input: { query: string; maxResults?: number }): Promise<GmailMessageSummary[]> {
    const query = input.query.trim()
    if (!query || query.length > 500) throw new Error("Provide a Gmail search query of 1–500 characters.")
    const token = await accessToken()
    const limit = Math.max(1, Math.min(MAX_SEARCH_RESULTS, Math.floor(input.maxResults ?? 5)))
    const url = new URL("https://gmail.googleapis.com/gmail/v1/users/me/messages")
    url.searchParams.set("q", query)
    url.searchParams.set("maxResults", String(limit))
    const result = await gmailFetch<{ messages?: MessageRef[] }>(`messages?${url.searchParams.toString()}`, token)
    const refs = result.messages ?? []
    const messages = await Promise.all(refs.map(async (ref) => {
      try {
        return await gmailFetch<Message>(`messages/${encodeURIComponent(ref.id)}?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject&metadataHeaders=Date`, token)
      } catch {
        return undefined
      }
    }))
    return messages.filter((item): item is Message => !!item).map(summary)
  }

  export async function read(messageId: string): Promise<GmailMessageContent> {
    const id = messageId.trim()
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(id)) throw new Error("Invalid Gmail message ID.")
    const token = await accessToken()
    const message = await gmailFetch<Message>(`messages/${encodeURIComponent(id)}?format=full`, token)
    return { ...summary(message), body: bodyText(message.payload).slice(0, MAX_BODY_CHARS) }
  }

  export async function latestOtp(input: { siteUrl: string; after?: number }): Promise<GmailOtpResult | undefined> {
    const origin = normalizeAuthOrigin(input.siteUrl)
    const after = input.after ?? Date.now() - 15 * 60_000
    const query = `after:${Math.floor(after / 1000)} newer_than:1d (subject:verification OR subject:code OR subject:OTP OR subject:security OR "one-time")`
    const candidates = await search({ query, maxResults: 10 })
    for (const candidate of candidates) {
      if (!isAllowedSiteSender(candidate.from, origin)) continue
      const receivedAt = Date.parse(candidate.date)
      if (!Number.isFinite(receivedAt) || receivedAt < after) continue
      const full = await read(candidate.id)
      if (!/verification|security code|one[- ]time|sign[- ]in|login|authentication|otp/i.test(`${full.subject}\n${full.body}`)) continue
      const code = extractOtpCode(`${full.subject}\n${full.body}`)
      if (code) return { ...candidate, code, receivedAt }
    }
    return undefined
  }
}

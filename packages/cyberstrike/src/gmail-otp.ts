/**
 * Read a recent one-time verification code from Gmail using a user-configured
 * Google OAuth refresh token. This module never accepts or stores a Google
 * account password. Configure OAuth credentials outside the repository.
 *
 * Required env:
 *   CYBERSTRIKE_GMAIL_OAUTH_CLIENT_ID
 *   CYBERSTRIKE_GMAIL_OAUTH_CLIENT_SECRET
 *   CYBERSTRIKE_GMAIL_OAUTH_REFRESH_TOKEN
 *
 * The refresh token must be issued for the Gmail readonly scope:
 * https://www.googleapis.com/auth/gmail.readonly
 */
import { normalizeAuthOrigin } from "./auth-vault"

type GmailMessageRef = { id: string; threadId?: string }
type GmailHeader = { name?: string; value?: string }
type GmailPart = {
  mimeType?: string
  body?: { data?: string }
  parts?: GmailPart[]
}
type GmailMessage = {
  id: string
  internalDate?: string
  snippet?: string
  payload?: { headers?: GmailHeader[]; body?: { data?: string }; parts?: GmailPart[] }
}
export type GmailOtpResult = {
  code: string
  messageId: string
  from: string
  subject: string
  receivedAt: number
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`Gmail OTP is not configured: set ${name} after completing Google OAuth consent.`)
  return value
}

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/")
  return Buffer.from(normalized, "base64").toString("utf8")
}

function collectText(part?: GmailPart): string {
  if (!part) return ""
  const own = part.body?.data ? decodeBase64Url(part.body.data) : ""
  return [own, ...(part.parts ?? []).map(collectText)].join("\n")
}

function header(message: GmailMessage, name: string): string {
  return message.payload?.headers?.find((item) => item.name?.toLowerCase() === name.toLowerCase())?.value ?? ""
}

function extractCode(text: string): string | undefined {
  const normalized = text.replace(/<[^>]*>/g, " ").replace(/&nbsp;/gi, " ")
  const patterns = [
    /(?:verification|security|confirmation|one[- ]time|login|sign[- ]in|authentication|otp)[^\d]{0,70}(\d{6,8})/i,
    /\b(\d{6})\b/,
    /\b(\d{8})\b/,
  ]
  for (const pattern of patterns) {
    const match = pattern.exec(normalized)
    if (match?.[1]) return match[1]
  }
  return undefined
}

export namespace GmailOtp {
  export async function latest(input: { siteUrl: string; after?: number }): Promise<GmailOtpResult | undefined> {
    const origin = normalizeAuthOrigin(input.siteUrl)
    const siteHost = new URL(origin).hostname.toLowerCase().replace(/^www\./, "")
    const clientId = requiredEnv("CYBERSTRIKE_GMAIL_OAUTH_CLIENT_ID")
    const clientSecret = requiredEnv("CYBERSTRIKE_GMAIL_OAUTH_CLIENT_SECRET")
    const refreshToken = requiredEnv("CYBERSTRIKE_GMAIL_OAUTH_REFRESH_TOKEN")

    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: refreshToken,
        grant_type: "refresh_token",
      }),
    })
    if (!tokenResponse.ok) throw new Error(`Google OAuth token refresh failed (HTTP ${tokenResponse.status}); re-authorize Gmail OAuth if the refresh token was revoked.`)
    const tokenData = await tokenResponse.json() as { access_token?: string }
    if (!tokenData.access_token) throw new Error("Google OAuth did not return an access token.")

    const afterSeconds = Math.floor((input.after ?? Date.now() - 15 * 60_000) / 1000)
    const query = `after:${afterSeconds} newer_than:1d (subject:verification OR subject:code OR subject:OTP OR subject:security OR "one-time")`
    const listURL = new URL("https://gmail.googleapis.com/gmail/v1/users/me/messages")
    listURL.searchParams.set("q", query)
    listURL.searchParams.set("maxResults", "15")
    const listResponse = await fetch(listURL, { headers: { authorization: `Bearer ${tokenData.access_token}` } })
    if (!listResponse.ok) throw new Error(`Gmail message search failed (HTTP ${listResponse.status}). Check that OAuth includes gmail.readonly.`)
    const listData = await listResponse.json() as { messages?: GmailMessageRef[] }
    const refs = listData.messages ?? []

    for (const ref of refs) {
      const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(ref.id)}?format=full`, {
        headers: { authorization: `Bearer ${tokenData.access_token}` },
      })
      if (!response.ok) continue
      const message = await response.json() as GmailMessage
      const from = header(message, "From")
      const subject = header(message, "Subject")
      const receivedAt = Number(message.internalDate ?? 0)
      if (!receivedAt || receivedAt < (input.after ?? Date.now() - 15 * 60_000)) continue

      // Only consider messages whose sender belongs to the exact target host
      // or a subdomain of it. Third-party mail senders require a future,
      // explicit per-site allowlist rather than broad inbox-wide OTP scraping.
      const senderHost = /@([^\s>]+)/.exec(from)?.[1]?.replace(/[>),;]+$/, "").toLowerCase()
      if (!senderHost || !(senderHost === siteHost || senderHost.endsWith(`.${siteHost}`))) continue

      const text = [message.snippet ?? "", collectText(message.payload)].join("\n")
      if (!/verification|security code|one[- ]time|sign[- ]in|login|authentication|otp/i.test(`${subject}\n${text}`)) continue
      const code = extractCode(`${subject}\n${text}`)
      if (code) return { code, messageId: message.id, from, subject, receivedAt }
    }
    return undefined
  }
}

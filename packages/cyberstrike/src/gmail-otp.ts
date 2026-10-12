/**
 * Pure helpers for extracting a likely one-time code from a candidate email.
 * Mailbox access lives in gmail-service.ts so all agents share one OAuth client.
 */
export function extractOtpCode(text: string): string | undefined {
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

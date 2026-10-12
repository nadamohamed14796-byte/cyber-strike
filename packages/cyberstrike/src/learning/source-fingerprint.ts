/**
 * Produce stable URL fingerprints without lowercasing case-sensitive path or
 * query data. The second key preserves lookup compatibility with records saved
 * by the earlier implementation, which lowercased the entire URL.
 */
export function sourceFingerprints(value: string) {
  const legacy = "url:" + value.trim().toLowerCase().replace(/\s+/g, " ")
  try {
    const url = new URL(value.trim())
    url.hash = ""
    return Array.from(new Set(["url:v2:" + url.toString(), legacy]))
  } catch {
    return [legacy]
  }
}

/**
 * Legacy fingerprint matches are safe only when the stored original URL has
 * the same case-preserving canonical identity as the incoming URL.
 */
export function matchesSourceURLFingerprint(storedURL: string | null | undefined, requestedFingerprint: string) {
  if (!storedURL) return false
  return sourceFingerprints(storedURL)[0] === requestedFingerprint
}

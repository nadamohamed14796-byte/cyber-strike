/** Shared deterministic scope matcher used by the CLI helper and active target tools. */

type ScopeMatch = { matches: boolean; reason: string }

/** Check one target against a single scope expression; exported for deterministic contract tests. */
export function checkMatch(target: string, scope: string): ScopeMatch {
  const value = target.trim().toLowerCase()
  const allowed = scope.trim().toLowerCase()

  // Treat any IPv4-looking CIDR as a CIDR candidate, including malformed prefixes,
  // so invalid ranges fail closed rather than falling through to hostname matching.
  if (/^\d+(?:\.\d+){3}\/.+$/.test(allowed) || /^\d+(?:\.\d+){3}\/$/.test(allowed)) {
    const cidrParts = allowed.split("/")
    if (cidrParts.length !== 2) {
      return { matches: false, reason: "invalid IPv4 CIDR" }
    }
    const [range, prefixText] = cidrParts
    const rangeNumber = ipv4ToNumber(range)
    if (!/^(?:0|[1-9]\d?)$/.test(prefixText)) {
      return { matches: false, reason: "invalid IPv4 CIDR" }
    }
    const prefix = Number(prefixText)
    if (rangeNumber === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      return { matches: false, reason: "invalid IPv4 CIDR" }
    }

    const hostname = parseHostname(value)
    const targetNumber = hostname ? ipv4ToNumber(hostname) : null
    if (targetNumber === null) {
      return { matches: false, reason: "target host is not a valid IPv4 address" }
    }

    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
    const inRange = ((targetNumber & mask) >>> 0) === ((rangeNumber & mask) >>> 0)
    return inRange
      ? { matches: true, reason: `IPv4 address ${hostname} is within CIDR ${allowed}` }
      : { matches: false, reason: `IPv4 address ${hostname} is outside CIDR ${allowed}` }
  }

  // Explicit URL scope entries can constrain scheme, port, and path. They must
  // never be reduced to a hostname because that would silently broaden permission.
  if (/^https?:\/\//i.test(allowed)) {
    let candidateURL: URL
    let scopeURL: URL
    try {
      candidateURL = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? new URL(value) : new URL(`https://${value}`)
      scopeURL = new URL(allowed)
    } catch {
      return { matches: false, reason: "invalid HTTP(S) URL scope or target" }
    }
    if ((candidateURL.protocol !== "http:" && candidateURL.protocol !== "https:") ||
      (scopeURL.protocol !== "http:" && scopeURL.protocol !== "https:") ||
      candidateURL.username || candidateURL.password || scopeURL.username || scopeURL.password) {
      return { matches: false, reason: "invalid HTTP(S) URL scope or target" }
    }
    const scopeHost = scopeURL.hostname.toLowerCase().replace(/\.$/, "")
    const targetHost = candidateURL.hostname.toLowerCase().replace(/\.$/, "")
    const hostMatches = scopeHost.startsWith("*.")
      ? targetHost === scopeHost.slice(2) || targetHost.endsWith("." + scopeHost.slice(2))
      : targetHost === scopeHost
    if (!hostMatches) return { matches: false, reason: "hostname does not match explicit URL scope" }
    if (candidateURL.protocol !== scopeURL.protocol) return { matches: false, reason: "protocol does not match explicit URL scope" }
    if (candidateURL.port !== scopeURL.port) return { matches: false, reason: "port does not match explicit URL scope" }
    const scopePath = scopeURL.pathname.replace(/\/+$/, "") || "/"
    const targetPath = candidateURL.pathname.replace(/\/+$/, "") || "/"
    const pathWildcard = scopePath.endsWith("/*")
    const pathPrefix = pathWildcard ? scopePath.slice(0, -2).replace(/\/+$/, "") : scopePath
    const pathMatches = pathWildcard
      ? targetPath === pathPrefix || targetPath.startsWith(pathPrefix + "/")
      : targetPath === pathPrefix
    return pathMatches
      ? { matches: true, reason: "matches explicit URL scope including scheme, port, and path" }
      : { matches: false, reason: "path does not match explicit URL scope" }
  }

  // A host:port entry constrains the network service while accepting either scheme.
  const hostPort = allowed.match(/^([^:/]+):(\d{1,5})$/)
  if (hostPort) {
    const hostname = parseHostname(value)
    if (!hostname) return { matches: false, reason: "target is not a valid domain, IP address, or HTTP(S) URL" }
    let targetURL: URL
    try { targetURL = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? new URL(value) : new URL(`https://${value}`) }
    catch { return { matches: false, reason: "target URL is invalid" } }
    const expectedHost = hostPort[1].toLowerCase().replace(/\.$/, "")
    const expectedPort = Number(hostPort[2])
    if (!Number.isInteger(expectedPort) || expectedPort < 1 || expectedPort > 65535)
      return { matches: false, reason: "invalid port in scope entry" }
    return hostname === expectedHost && Number(targetURL.port || (targetURL.protocol === "https:" ? 443 : 80)) === expectedPort
      ? { matches: true, reason: "exact hostname and port match" }
      : { matches: false, reason: "hostname or port does not match scope entry" }
  }

  const hostname = parseHostname(value)
  if (!hostname) return { matches: false, reason: "target is not a valid domain, IP address, or HTTP(S) URL" }

  // Wildcards are checked against the parsed hostname, never against URL text.
  if (allowed.startsWith("*.")) {
    const domain = parseHostname(allowed.slice(2))
    if (!domain) return { matches: false, reason: `invalid wildcard scope ${allowed}` }
    // CyberStrike treats an explicit *.example.com entry as the program's
    // domain family, including the apex. Match label boundaries so this never
    // admits lookalikes such as notexample.com or example.com.attacker.test.
    if (hostname === domain || hostname.endsWith("." + domain)) {
      return { matches: true, reason: `host matches wildcard domain family ${allowed}` }
    }
    return { matches: false, reason: `does not match wildcard ${allowed}` }
  }

  const scopeHost = parseHostname(allowed)
  if (!scopeHost) return { matches: false, reason: "scope item is not a valid domain, IP address, or HTTP(S) URL" }
  // A bare domain is an exact entry, not an implicit wildcard. Programs that
  // include subdomains must express that permission with an explicit wildcard.
  if (hostname === scopeHost) return { matches: true, reason: "exact domain/IP match (ignoring protocol, port, and path)" }
  return { matches: false, reason: "no exact domain/IP match; add an explicit wildcard if subdomains are in scope" }
}

/** Parse the actual HTTP(S) hostname. Bare hostnames and IPv4 literals are allowed. */
function parseHostname(input: string): string | null {
  const value = input.trim()
  if (!value || /[\u0000-\u0020\u007f]/.test(value)) return null

  let url: URL
  try {
    url = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? new URL(value) : new URL(`http://${value}`)
  } catch {
    return null
  }

  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || !url.hostname) {
    return null
  }
  return url.hostname.toLowerCase().replace(/\.$/, "")
}

/** Convert only a syntactically valid dotted-decimal IPv4 address. */
function ipv4ToNumber(input: string): number | null {
  const parts = input.split(".")
  if (parts.length !== 4) return null

  const octets: number[] = []
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null
    const octet = Number(part)
    if (octet < 0 || octet > 255) return null
    octets.push(octet)
  }
  return octets.reduce((acc, octet) => ((acc << 8) | octet) >>> 0, 0)
}

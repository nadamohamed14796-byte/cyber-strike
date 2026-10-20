/** Shared deterministic scope matcher used by the CLI helper and active target tools. */

type ScopeMatch = { matches: boolean; reason: string }

/** Check one target against a single scope expression; exported for deterministic contract tests. */
export function checkMatch(target: string, scope: string): ScopeMatch {
  const rawTarget = target.trim()
  const value = rawTarget.toLowerCase()
  const rawScope = scope.trim()
  let rawAllowed = rawScope
  let allowed = rawScope.toLowerCase()

  // HackerOne scope exports may include an asset type alongside its identifier.
  // Only web-addressable types can authorize an HTTP target. Non-web assets are
  // retained as scope evidence, but never authorize an unrelated HTTP request.
  const typed = rawScope.match(/^(domain|wildcard|url|cidr|ip address|api|google play app id|ai model|smart contract|smart contracts|source code|executable|hardware(?:\/iot)?|ios(?:: app store|: testflight|: \.ipa)?|android(?: play store|: \.apk)?|windows: microsoft store|aws account|azure account|aws cloud config|azure cloud config|other(?: asset)?)[ \t]*:[ \t]*(.+)$/i)
  if (typed) {
    const assetType = typed[1].replace(/\s+/g, " ").trim().toLowerCase()
    const identifier = typed[2].trim()
    const webTypes = new Set(["domain", "wildcard", "url", "cidr", "ip address", "api"])
    if (!webTypes.has(assetType)) {
      return { matches: false, reason: `HackerOne asset type "${assetType}" is not an HTTP target scope; use its appropriate assessment workflow` }
    }
    if (!identifier) return { matches: false, reason: `empty identifier for HackerOne asset type "${assetType}"` }
    if (assetType === "wildcard") allowed = identifier.includes("*") || /\{[^{}]+\}/.test(identifier) ? identifier : "*." + identifier
    else if (assetType === "url") {
      return matchURLScope(rawTarget, identifier, !/^https?:\/\//i.test(identifier))
    } else {
      rawAllowed = rawScope.replace(/^[^:]+:\s*/, "").trim()
      allowed = identifier
    }
  }

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

  // IPv6 CIDR matching is separate from IPv4 CIDR parsing to avoid treating
  // malformed network entries as ordinary hostnames.
  const ipv6Cidr = allowed.match(/^\[?([0-9a-f:.]+)\]?\/(\d{1,3})$/i)
  if (ipv6Cidr && ipv6Cidr[1].includes(":")) {
    const prefix = Number(ipv6Cidr[2])
    const network = ipv6ToBigInt(ipv6Cidr[1])
    const hostname = parseHostname(value)
    const address = hostname ? ipv6ToBigInt(hostname) : null
    if (prefix < 0 || prefix > 128 || network === null || address === null) {
      return { matches: false, reason: "invalid IPv6 CIDR or target address" }
    }
    const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n)
    return (address & mask) === (network & mask)
      ? { matches: true, reason: `IPv6 address is within CIDR ${allowed}` }
      : { matches: false, reason: `IPv6 address is outside CIDR ${allowed}` }
  }

  // HackerOne IP Address assets can be IPv6 literals without URL brackets.
  // Normalize both sides to 128-bit values for exact equality, never hostname suffix matching.
  if (allowed.includes(":") && !allowed.includes("/") && !allowed.includes("://")) {
    const scopeAddress = ipv6ToBigInt(allowed)
    if (scopeAddress !== null) {
      const targetHost = parseHostname(value)
      const targetAddress = targetHost ? ipv6ToBigInt(targetHost) : null
      return targetAddress !== null && targetAddress === scopeAddress
        ? { matches: true, reason: "IPv6 address exactly matches scope item " + allowed }
        : { matches: false, reason: "target does not match IPv6 address scope item " + allowed }
    }
  }

  // Explicit URL scope entries can constrain scheme, port, and path. They must
  // never be reduced to a hostname because that would silently broaden permission.
  if (/^https?:\/\//i.test(allowed)) {
    let candidateURL: URL
    let scopeURL: URL
    try {
        candidateURL = /^[a-z][a-z\d+.-]*:\/\//i.test(rawTarget) ? new URL(rawTarget) : new URL("https://" + rawTarget)
        scopeURL = new URL(rawAllowed)
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

  // Bare host/path scope entries are URL constraints, not a hostname shorthand.
  // Do not silently drop the path and broaden authorization to the entire origin.
  if (!typed && !allowed.includes("://") && allowed.includes("/") &&
      !/^\\d+(?:\\.\\d+){3}\\/\\d{1,2}$/.test(allowed) &&
      !/^\\[?[0-9a-f:.]+\\]?\\/\\d{1,3}$/i.test(allowed)) {
    return matchURLScope(rawTarget, allowed, true)
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

  // HackerOne also documents wildcard labels outside the leading "*." form,
  // e.g. "www.example.*" and "{tenant}.example.com". These match one DNS label
  // per token; only the leading "*.domain" form intentionally includes the apex.
  if (allowed.includes("*") || /\{[^{}]+\}/.test(allowed)) {
    const labels = allowed.split(".")
    if (labels.some((label) => label.includes("*") || /^\{[^{}]+\}$/.test(label))) {
      const escaped = labels
        .map((label) => label === "*" || /^\{[^{}]+\}$/.test(label)
          ? "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
          : label.replace(/[.*+?^\x24()|[\]\\]/g, "\\$&"))
        .join("\\.")
      let pattern: RegExp
      try { pattern = new RegExp("^" + escaped + "$", "i") }
      catch { return { matches: false, reason: "invalid wildcard scope " + allowed } }
      return pattern.test(hostname)
        ? { matches: true, reason: "host matches wildcard pattern " + allowed }
        : { matches: false, reason: "does not match wildcard pattern " + allowed }
    }
  }

  const scopeHost = parseHostname(allowed)
  if (!scopeHost) return { matches: false, reason: "scope item is not a valid domain, IP address, or HTTP(S) URL" }
  // A bare domain is an exact entry, not an implicit wildcard. Programs that
  // include subdomains must express that permission with an explicit wildcard.
  if (hostname === scopeHost) return { matches: true, reason: "exact domain/IP match (ignoring protocol, port, and path)" }
  return { matches: false, reason: "no exact domain/IP match; add an explicit wildcard if subdomains are in scope" }
}

/** Match URL assets without discarding the path, port, or an explicit scheme. */
function matchURLScope(rawTarget: string, identifier: string, allowEitherScheme: boolean): ScopeMatch {
  let targetURL: URL
  let scopeURL: URL
  const explicitScheme = /^https?:\/\//i.test(identifier)
  try {
    targetURL = /^[a-z][a-z\d+.-]*:\/\//i.test(rawTarget) ? new URL(rawTarget) : new URL("https://" + rawTarget)
    scopeURL = explicitScheme ? new URL(identifier) : new URL("https://" + identifier)
  } catch {
    return { matches: false, reason: "invalid URL asset identifier or target" }
  }
  if (
    (targetURL.protocol !== "http:" && targetURL.protocol !== "https:") ||
    (scopeURL.protocol !== "http:" && scopeURL.protocol !== "https:") ||
    targetURL.username || targetURL.password || scopeURL.username || scopeURL.password ||
    scopeURL.search || scopeURL.hash
  ) {
    return { matches: false, reason: "URL asset and target must be credential-free HTTP(S) URLs; scope URL cannot contain a query or fragment" }
  }
  if (explicitScheme && !allowEitherScheme && targetURL.protocol !== scopeURL.protocol) {
    return { matches: false, reason: "protocol does not match explicit URL asset" }
  }
  const scopeHost = scopeURL.hostname.toLowerCase().replace(/\.$/, "")
  const targetHost = targetURL.hostname.toLowerCase().replace(/\.$/, "")
  const hostMatches = scopeHost.startsWith("*.")
    ? targetHost === scopeHost.slice(2) || targetHost.endsWith("." + scopeHost.slice(2))
    : targetHost === scopeHost
  if (!hostMatches) return { matches: false, reason: "target does not match URL asset host" }
  if (targetURL.port !== scopeURL.port) return { matches: false, reason: "target does not match URL asset port" }
  const scopePath = scopeURL.pathname.replace(/\/+$/, "") || "/"
  const targetPath = targetURL.pathname.replace(/\/+$/, "") || "/"
  const pathPrefix = scopePath.endsWith("/*") ? scopePath.slice(0, -2).replace(/\/+$/, "") : scopePath
  // A URL asset names an application/resource path and includes its descendants,
  // but must not match sibling prefixes such as /app10 for /app1.
  const pathMatches = pathPrefix === "/" || targetPath === pathPrefix || targetPath.startsWith(pathPrefix + "/")
  return pathMatches
    ? { matches: true, reason: "matches URL asset host, port, and path" }
    : { matches: false, reason: "target does not match URL asset path" }
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

/** Parse a valid IPv6 literal (including compressed and IPv4-mapped forms) as a 128-bit integer. */
function ipv6ToBigInt(input: string): bigint | null {
  let value = input.trim().toLowerCase().replace(/^\[|\]$/g, "")
  if (!value.includes(":")) return null
  if (value.includes(".")) {
    const splitAt = value.lastIndexOf(":")
    const ipv4 = ipv4ToNumber(value.slice(splitAt + 1))
    if (splitAt < 0 || ipv4 === null) return null
    const high = ((ipv4 >>> 16) & 0xffff).toString(16)
    const low = (ipv4 & 0xffff).toString(16)
    value = value.slice(0, splitAt + 1) + high + ":" + low
  }
  if ((value.match(/::/g) ?? []).length > 1) return null
  const compressed = value.includes("::")
  const [leftText, rightText = ""] = value.split("::")
  const left = leftText ? leftText.split(":") : []
  const right = rightText ? rightText.split(":") : []
  const missing = 8 - left.length - right.length
  if ((compressed && missing < 1) || (!compressed && missing !== 0)) return null
  const groups = compressed ? [...left, ...Array(missing).fill("0"), ...right] : left
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null
  try { return BigInt("0x" + groups.map((group) => group.padStart(4, "0")).join("")) }
  catch { return null }
}

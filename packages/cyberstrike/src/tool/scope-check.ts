import z from "zod"
import { Tool } from "./tool"

export const ScopeCheckTool = Tool.define("scope_check", {
  description:
    "Validate that a target is in scope before testing. Supports exact domain match, wildcard domains (*.example.com), and IPv4 CIDR ranges (10.0.0.0/24). Always check scope before actively testing a new target to avoid scope violations.",
  parameters: z.object({
    target: z.string().describe("The target to check (domain, IPv4 address, or HTTP(S) URL)"),
    scope_items: z
      .array(z.string())
      .describe("List of in-scope items (domains, wildcards like *.example.com, IPv4 CIDRs like 10.0.0.0/24)"),
  }),
  async execute(params) {
    const target = params.target.toLowerCase().trim()
    const results: Array<{ scope: string; matches: boolean; reason: string }> = []
    let inScope = false

    for (const scope of params.scope_items) {
      const s = scope.toLowerCase().trim()
      const match = checkMatch(target, s)
      results.push({ scope: s, ...match })
      if (match.matches) inScope = true
    }

    const output = [
      `Target: ${target}`,
      `In scope: ${inScope ? "YES" : "NO"}`,
      "",
      "Scope check details:",
      ...results.map((r) => `  ${r.matches ? "[MATCH]" : "[NO]"} ${r.scope} — ${r.reason}`),
    ]

    if (!inScope) {
      output.push("")
      output.push("WARNING: Target is NOT in scope. Do NOT perform active testing on this target.")
    }

    return {
      title: inScope ? `In scope: ${target}` : `OUT OF SCOPE: ${target}`,
      output: output.join("\n"),
      metadata: { target, inScope, results },
    }
  },
})

type ScopeMatch = { matches: boolean; reason: string }

/** Check one target against a single scope expression; exported for deterministic contract tests. */
export function checkMatch(target: string, scope: string): ScopeMatch {
  const value = target.trim().toLowerCase()
  const allowed = scope.trim().toLowerCase()

  // Treat any IPv4-looking CIDR as a CIDR candidate, including malformed prefixes,
  // so invalid ranges fail closed rather than falling through to hostname matching.
  if (/^\d+(?:\.\d+){3}\/.+$/.test(allowed) || /^\d+(?:\.\d+){3}\/$/.test(allowed)) {
    const [range, prefixText] = allowed.split("/", 2)
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

  const hostname = parseHostname(value)
  if (!hostname) return { matches: false, reason: "target is not a valid domain, IP address, or HTTP(S) URL" }

  // Wildcards are checked against the parsed hostname, never against URL text.
  if (allowed.startsWith("*.")) {
    const domain = parseHostname(allowed.slice(2))
    if (!domain) return { matches: false, reason: `invalid wildcard scope ${allowed}` }
    // A wildcard grants only subdomains. The apex must be listed explicitly
    // when it is in scope; otherwise this broadens scope beyond the operator's entry.
    if (hostname.endsWith("." + domain)) return { matches: true, reason: `subdomain matches wildcard ${allowed}` }
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

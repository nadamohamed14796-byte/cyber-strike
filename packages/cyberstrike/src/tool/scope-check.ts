import z from "zod"
import { Tool } from "./tool"
import { TargetMemory } from "../target"

export const ScopeCheckTool = Tool.define("scope_check", {
  description:
    "Validate that a target is in scope before testing. Supports exact domain match, wildcard domains (*.example.com), and IPv4 CIDR ranges (10.0.0.0/24). During target hunting, pass target_url to load the authoritative scope manifest from the existing CyberStrike target workspace; an unconfigured or missing manifest fails closed. Without target_url, supplied scope_items are informational caller-provided entries, not persisted authorization.",
  parameters: z.object({
    target: z.string().describe("The target to check (domain, IPv4 address, or HTTP(S) URL)"),
    target_url: z.string().optional().describe("Existing CyberStrike target workspace URL; when supplied, its persisted scope manifest is authoritative and scope_items are ignored"),
    scope_items: z
      .array(z.string())
      .optional()
      .describe("Caller-provided scope entries for standalone checks only; use target_url for the persisted target scope"),
  }),
  async execute(params) {
    const target = params.target.toLowerCase().trim()
    let scopeItems = params.scope_items ?? []
    let excludedItems: string[] = []
    let scopeSource = "caller-provided (not persisted authorization)"
    let scopeConfigured = false

    if (params.target_url) {
      let persisted
      try {
        persisted = await TargetMemory.getScope(params.target_url)
      } catch (error) {
        return {
          title: "Target scope could not be loaded",
          output: error instanceof Error ? error.message : String(error),
          metadata: { target, inScope: false, scopeConfigured: false, scopeError: true },
        }
      }
      if (!persisted || persisted.status !== "configured" || persisted.scopeItems.length === 0) {
        return {
          title: "Target scope is not configured",
          output: [
            "Target under test: " + target,
            "Workspace target: " + params.target_url,
            "In scope: NO",
            "No explicitly configured scope manifest was found.",
            "Configure it with: cyberstrike target scope <url> --include <domain> --source <program> --reference <official-https-url>",
            "Do NOT perform active testing until the official program scope has been reviewed and configured.",
          ].join("\n"),
          metadata: { target, inScope: false, scopeConfigured: false, scopeSource: "missing-or-unconfigured", results: [] },
        }
      }
      scopeItems = persisted.scopeItems
      excludedItems = persisted.excludedItems
      scopeConfigured = true
      scopeSource = persisted.authorizationSource ?? "persisted manifest (source missing)"
    }

    const results: Array<{ scope: string; matches: boolean; reason: string; excluded?: boolean }> = []
    let included = false
    let excluded = false

    for (const scope of scopeItems) {
      const s = scope.toLowerCase().trim()
      const match = checkMatch(target, s)
      results.push({ scope: s, ...match })
      if (match.matches) included = true
    }
    for (const scope of excludedItems) {
      const s = scope.toLowerCase().trim()
      const match = checkMatch(target, s)
      results.push({ scope: s, ...match, excluded: true })
      if (match.matches) excluded = true
    }
    const inScope = included && !excluded

    const output = [
      `Target: ${target}`,
      `In scope: ${inScope ? "YES" : "NO"}`,
      `Scope source: ${scopeSource}`,
      `Persisted authorization manifest: ${scopeConfigured ? "configured" : "not used"}`,
      "",
      "Scope check details:",
      ...(results.length ? results.map((r) => `  ${r.matches ? (r.excluded ? "[EXCLUDED]" : "[MATCH]") : "[NO]"} ${r.scope} — ${r.reason}`) : ["  (no scope entries supplied)"]),
    ]

    if (!inScope) {
      output.push("")
      output.push(excluded
        ? "WARNING: Target matches an explicit exclusion. Exclusions override all include entries."
        : "WARNING: Target is NOT in scope. Do NOT perform active testing on this target.")
    }

    return {
      title: inScope ? `In scope: ${target}` : `OUT OF SCOPE: ${target}`,
      output: output.join("\n"),
      metadata: { target, inScope, scopeConfigured, scopeSource, excluded, results },
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

import z from "zod"
import { Tool } from "./tool"
import { TargetMemory } from "../target"
import { matchingScopeItems } from "../target/scope-index"
export { checkMatch } from "../target/scope-match"

const MAX_SCOPE_MATCHES_IN_OUTPUT = 8

function toScopeURL(input: string, defaultProtocol = "https:"): URL | undefined {
  const value = input.trim()
  if (!value) return undefined
  try {
    let url: URL
    const lower = value.toLowerCase()
    if (lower.startsWith("http://") || lower.startsWith("https://")) {
      url = new URL(value)
    } else {
      if (value.includes("://")) return undefined
      let authority = value
      while (authority.startsWith("/")) authority = authority.slice(1)
      const delimiterPositions = [authority.indexOf("/"), authority.indexOf("?"), authority.indexOf("#")].filter((i) => i >= 0)
      const hostEnd = delimiterPositions.length ? Math.min(...delimiterPositions) : authority.length
      const hostPart = authority.slice(0, hostEnd)
      if (!hostPart) return undefined
      if (!hostPart.startsWith("[") && hostPart.split(":").length > 2) {
        authority = "[" + hostPart + "]" + authority.slice(hostPart.length)
      }
      url = new URL(defaultProtocol + "//" + authority)
    }
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) return undefined
    return url
  } catch {
    return undefined
  }
}

function previewMatches(items: string[]): string {
  if (!items.length) return "(none)"
  const preview = items.slice(0, MAX_SCOPE_MATCHES_IN_OUTPUT).join(", ")
  return preview + (items.length > MAX_SCOPE_MATCHES_IN_OUTPUT
    ? " (+" + (items.length - MAX_SCOPE_MATCHES_IN_OUTPUT) + " more)"
    : "")
}


export const ScopeCheckTool = Tool.define("scope_check", {
  description:
    "Validate a target against the persisted authorization scope before testing. Supports exact hosts, wildcard domain families (including the apex), IPv4 CIDRs, exact IPv6 literals, host:port entries, and explicit HTTP(S) URL scopes constrained by scheme, port, and exact path or /* path subtree. Scope-file imports preserve additional compact program-specific identifiers as raw evidence, but unsupported formats never authorize an HTTP target. During target hunting, pass target_url to load the authoritative scope manifest from the existing CyberStrike target workspace; an unconfigured or missing manifest fails closed. Without target_url, supplied scope_items are informational caller-provided entries, not persisted authorization.",
  parameters: z.object({
    target: z.string().describe("The target to check (hostname, IP literal, host:port, or HTTP(S) URL)"),
    target_url: z.string().optional().describe("Existing CyberStrike target workspace URL; when supplied, its persisted scope manifest is authoritative and scope_items are ignored"),
    scope_items: z
      .array(z.string())
      .optional()
      .describe("Caller-provided scope entries for standalone checks only; use target_url for the persisted target scope"),
  }),
  async execute(params): Promise<{ title: string; output: string; metadata: Tool.Metadata }> {
    const target = params.target.trim()
    let scopeItems = params.scope_items ?? []
    let excludedItems: string[] = []
    let scopeSource = "caller-provided (not persisted authorization)"
    let scopeConfigured = false
    let authoritativeDecision: Awaited<ReturnType<typeof TargetMemory.checkURLScope>> | undefined
    let candidateURL: URL | undefined

    if (params.target_url) {
      let workspace
      let persisted: Awaited<ReturnType<typeof TargetMemory.getScope>>
      try {
        workspace = await TargetMemory.get(params.target_url)
        persisted = await TargetMemory.getScope(params.target_url)
        // A child without its own scope inherits the saved parent scope. Its own
        // scope, when configured, is still intersected with the parent at decision time.
        if ((!persisted || persisted.status !== "configured" || persisted.scopeItems.length === 0) && workspace?.parentTargetID) {
          const parent = TargetMemory.list().find((item) => item.id === workspace!.parentTargetID)
          if (parent) persisted = await TargetMemory.getScope(parent.targetURL)
        }
      } catch (error) {
        return {
          title: "Target scope could not be loaded",
          output: error instanceof Error ? error.message : String(error),
          metadata: { target, inScope: false, scopeConfigured: false, scopeError: true },
        }
      }
      if (!workspace || !persisted || persisted.status !== "configured" || persisted.scopeItems.length === 0) {
        return {
          title: "Target scope is not configured",
          output: [
            "Target under test: " + target,
            "Workspace target: " + params.target_url,
            "In scope: NO",
            "No configured parent/child authorization scope was found.",
            "Configure it with: cyberstrike target scope <url> --include <domain> --source <program> --reference <official-https-url>",
            "If the user explicitly confirms one exact asset is in scope, configure only that exact asset with target_workspace(action=\"configure_scope\", user_confirmed_scope=true) for an initial manifest or merge_existing=true for an existing manifest, then save the confirmation in target notes. Do not demand a separate policy link or ask for proof again. Otherwise, configure verified program scope before active testing.",
          ].join("\n"),
          metadata: { target, inScope: false, scopeConfigured: false, scopeSource: "missing-or-unconfigured", results: [] },
        }
      }
      scopeItems = persisted.scopeItems
      excludedItems = persisted.excludedItems
      scopeConfigured = true
      scopeSource = persisted.authorizationSource ?? "persisted manifest (source missing)"
      try {
        candidateURL = toScopeURL(target, new URL(workspace.targetURL).protocol)
        if (!candidateURL) throw new Error("Target must be a hostname, host:port, IP literal, or HTTP(S) URL.")
        authoritativeDecision = await TargetMemory.checkURLScope(candidateURL.href)
      } catch (error) {
        return {
          title: "Target scope decision failed closed",
          output: error instanceof Error ? error.message : String(error),
          metadata: { target, inScope: false, scopeConfigured, scopeError: true },
        }
      }
    }

    if (!candidateURL) candidateURL = toScopeURL(target)
    if (!candidateURL) {
      return {
        title: "Invalid scope target",
        output: "Target must be a hostname, host:port, IP literal, or HTTP(S) URL. No scope decision was made.",
        metadata: { target, inScope: false, scopeConfigured, invalidTarget: true },
      }
    }

    // Reuse indexed scope results. Do not iterate over or emit every entry in a large manifest.
    const includeMatches = authoritativeDecision
      ? authoritativeDecision.includeMatches
      : matchingScopeItems(candidateURL, scopeItems)
    const excludeMatches = authoritativeDecision
      ? authoritativeDecision.excludeMatches
      : matchingScopeItems(candidateURL, excludedItems)
    const included = includeMatches.length > 0
    const excluded = excludeMatches.length > 0
    const inScope = included && !excluded && (authoritativeDecision?.allowed ?? true)
    const informationalOnly = !params.target_url
    const allMatched = [
      ...includeMatches.map((scope) => ({ scope, matches: true, reason: "matches target", excluded: false })),
      ...excludeMatches.map((scope) => ({ scope, matches: true, reason: "explicit exclusion matches target", excluded: true })),
    ]
    const displayedMatches = allMatched.slice(0, MAX_SCOPE_MATCHES_IN_OUTPUT)
    const output = [
      "Target: " + target,
      informationalOnly
        ? "Matches supplied scope entries: " + (included && !excluded ? "YES" : "NO")
        : "In scope: " + (inScope ? "YES" : "NO"),
      "Scope source: " + scopeSource,
      "Persisted authorization manifest: " + (scopeConfigured ? "configured" : "not used"),
      "Scope inventory size: " + scopeItems.length + " include entries; " + excludedItems.length + " exclusions",
      "Matching inclusions (" + includeMatches.length + "): " + previewMatches(includeMatches),
      "Matching exclusions (" + excludeMatches.length + "): " + previewMatches(excludeMatches),
      ...(informationalOnly
        ? ["Authorization: NOT VERIFIED — caller-provided scope entries are informational only. Do not treat a match as permission to test."]
        : []),
      ...(authoritativeDecision
        ? ["Authoritative active-scope decision: " + authoritativeDecision.reason]
        : []),
      "",
      "Matching scope details (non-matching manifest entries omitted):",
      ...(displayedMatches.length
        ? displayedMatches.map((item) => "  " + (item.excluded ? "[EXCLUDED]" : "[MATCH]") + " " + item.scope + " — " + item.reason)
        : ["  (no scope entries match this target)"]),
    ]

    if (!inScope) {
      output.push("")
      output.push(excluded
        ? "WARNING: Target matches an explicit exclusion. Exclusions override all include entries."
        : informationalOnly
          ? "WARNING: No supplied scope entry matches this target; the match is informational only."
          : "WARNING: Target is NOT in scope. Do NOT perform active testing on this target.")
    }

    const matchesSuppliedScope = included && !excluded && (authoritativeDecision?.allowed ?? true)
    return {
      title: informationalOnly
        ? (included && !excluded ? "Informational scope match: " + target + " (authorization unverified)" : "No informational scope match: " + target)
        : inScope ? "In scope: " + target : "OUT OF SCOPE: " + target,
      output: output.join("\n"),
      metadata: {
        target,
        inScope: scopeConfigured && inScope,
        matchesSuppliedScope,
        authorizationVerified: scopeConfigured && Boolean(authoritativeDecision?.allowed),
        scopeMatchOnly: informationalOnly,
        scopeConfigured,
        scopeSource,
        excluded,
        include_match_count: includeMatches.length,
        exclude_match_count: excludeMatches.length,
        include_match_preview: includeMatches.slice(0, MAX_SCOPE_MATCHES_IN_OUTPUT),
        exclude_match_preview: excludeMatches.slice(0, MAX_SCOPE_MATCHES_IN_OUTPUT),
        results: displayedMatches,
      },
    }
  },
})

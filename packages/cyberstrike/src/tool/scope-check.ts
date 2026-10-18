import z from "zod"
import { Tool } from "./tool"
import { TargetMemory } from "../target"
import { checkMatch } from "../target/scope-match"
export { checkMatch } from "../target/scope-match"

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
            "Do NOT perform active testing until the official program scope has been reviewed and configured.",
          ].join("\n"),
          metadata: { target, inScope: false, scopeConfigured: false, scopeSource: "missing-or-unconfigured", results: [] },
        }
      }
      scopeItems = persisted.scopeItems
      excludedItems = persisted.excludedItems
      scopeConfigured = true
      scopeSource = persisted.authorizationSource ?? "persisted manifest (source missing)"
      try {
        const candidateURL = /^https?:\/\//i.test(target)
          ? target
          : new URL(workspace.targetURL).protocol + "//" + target.replace(/^\/+/, "")
        authoritativeDecision = await TargetMemory.checkURLScope(candidateURL)
      } catch (error) {
        return {
          title: "Target scope decision failed closed",
          output: error instanceof Error ? error.message : String(error),
          metadata: { target, inScope: false, scopeConfigured, scopeError: true },
        }
      }
    }

    const results: Array<{ scope: string; matches: boolean; reason: string; excluded?: boolean }> = []
    let included = false
    let excluded = false

    for (const scope of scopeItems) {
      const s = scope.trim()
      const match = checkMatch(target, s)
      results.push({ scope: s, ...match })
      if (match.matches) included = true
    }
    for (const scope of excludedItems) {
      const s = scope.trim()
      const match = checkMatch(target, s)
      results.push({ scope: s, ...match, excluded: true })
      if (match.matches) excluded = true
    }
    if (authoritativeDecision) {
      if (!authoritativeDecision.allowed) included = false
      if (authoritativeDecision.excludeMatches.length > 0) excluded = true
    }
    const inScope = included && !excluded && (authoritativeDecision?.allowed ?? true)

    const informationalOnly = !params.target_url
    const output = [
      `Target: ${target}`,
      informationalOnly
        ? `Matches supplied scope entries: ${inScope ? "YES" : "NO"}`
        : `In scope: ${inScope ? "YES" : "NO"}`,
      `Scope source: ${scopeSource}`,
      `Persisted authorization manifest: ${scopeConfigured ? "configured" : "not used"}`,
      ...(informationalOnly
        ? ["Authorization: NOT VERIFIED — caller-provided scope entries are informational only. Do not treat a match as permission to test."]
        : []),
      ...(authoritativeDecision ? ["Authoritative active-scope decision: " + authoritativeDecision.reason] : []),
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
      title: informationalOnly
        ? (inScope ? `Informational scope match: ${target} (authorization unverified)` : `No informational scope match: ${target}`)
        : inScope ? `In scope: ${target}` : `OUT OF SCOPE: ${target}`,
      output: output.join("\n"),
      metadata: {
        target,
        inScope: scopeConfigured && inScope,
        matchesSuppliedScope: inScope,
        authorizationVerified: scopeConfigured && Boolean(authoritativeDecision?.allowed),
        scopeMatchOnly: informationalOnly,
        scopeConfigured,
        scopeSource,
        excluded,
        results,
      },
    }
  },
})

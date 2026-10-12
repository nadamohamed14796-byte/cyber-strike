import z from "zod"
import { Tool } from "./tool"
import { TargetMemory } from "../target"
import { checkMatch } from "../target/scope-match"
export { checkMatch } from "../target/scope-match"

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

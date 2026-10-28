import z from "zod"
import { Tool } from "./tool"
import { LazyToolRegistry } from "./lazy-registry"
import { Log } from "../util/log"

const log = Log.create({ service: "tool.tool-search" })

/**
 * ToolSearch - Meta-tool for dynamic tool discovery
 *
 * Enables AI agents to work with hundreds of MCP tools
 * without overwhelming the context window.
 */
export const ToolSearchTool = Tool.define("tool_search", async () => {
  return {
    description: [
      "Start from one concrete evidence gap and the output needed to close it; search connected tools by capability, protocol, and observable behavior rather than a fixed phase checklist. Search is discovery, not a tool allowlist.",
      "Reuse an already-loaded tool only when its documented inputs and outputs fit the current gap. Search when the needed capability is missing or uncertain, not just to generate activity.",
      "Results are ranked by exact tool-name/description matches and query coverage. Match reasons explain the ranking, but rank is not proof that a tool is suitable, installed for the target runtime, safe, or authorized.",
      "If results are absent or too narrow, retry with useful synonyms, a capability term, protocol, or observable behavior; make the query materially different and do not repeat an unchanged search.",
      "Tool schemas are not included in the shortlist. Load a small set of plausible exact IDs with load_tools, inspect their full schemas, and invoke only the definitions that fit the required inputs and outputs.",
      "After each invocation, inspect actual output and errors before selecting the next tool. Add another tool only for a distinct coverage gap, corroboration, or recovery.",
      "Example query shapes (illustrative only):",
      '- "<active checkpoint> <missing evidence>"',
      '- "<observed protocol or technology> enumeration"',
      '- "<specific behavior> analysis or validation"',
    ].join("\n"),
    parameters: z.object({
      query: z.string().describe("Search query describing the capability you need"),
      limit: z.number().int().positive().optional().default(10).describe("Maximum number of ranked candidates to return (default: 10); increase it when comparing a broader set of available tools."),
    }),
    async execute(params, _ctx) {
      const { query, limit } = params

      log.info("searching tools", { query, limit })

      const results = LazyToolRegistry.searchDetailed(query, limit)
      const output = results.length === 0 ? "No matching tools found for the supplied capability terms." : [
        "Ranked " + results.length + " candidate tool(s). Ranking is a shortlist, not proof of suitability:",
        "",
        ...results.map((match, index) => {
          const candidate = match.tool
          const loaded = LazyToolRegistry.isLoaded(candidate.id) ? " [LOADED]" : ""
          return String(index + 1) + ". **" + candidate.name + "**" + loaded + "\n   ID: " + candidate.id + "\n   Relevance: " + match.score.toFixed(1) + "; exact query coverage: " + Math.round(match.coverage * 100) + "%\n   Matched terms: " + match.matchedTerms.join(", ") + "\n   Why: " + match.reasons.join("; ") + "\n   " + candidate.summary + "\n   Category: " + candidate.category
        }),
        "",
        "Load only a small shortlist with load_tools, inspect each full schema, and invoke only tools whose real inputs/outputs fit the evidence gap.",
      ].join("\n")
      const stats = LazyToolRegistry.stats()

      return {
        title: `Found ${results.length} tools`,
        output: [
          output,
          "",
          "---",
          `Tool Stats: ${stats.loaded}/${stats.available} loaded | ~${stats.estimatedTokens} tokens used | ${stats.budgetRemaining} budget remaining`,
        ].join("\n"),
        metadata: {
          query,
          resultCount: results.length,
          toolIds: results.map((match) => match.tool.id),
          matches: results.map((match) => ({
            id: match.tool.id,
            name: match.tool.name,
            score: Math.round(match.score * 10) / 10,
            coverage: Math.round(match.coverage * 100),
            matchedTerms: match.matchedTerms,
            reasons: match.reasons,
          })),
        },
      }
    },
  }
})

export const LoadToolsTool = Tool.define("load_tools", async () => {
  return {
    description: [\n      "Load selected connected-tool definitions into context so they can be used.",\n      "Use tool_search to discover candidates, then load only the exact IDs whose documented capabilities fit the current task.",\n      "Do not load or run every candidate. Do not treat tool names, search ranking, or catalog examples as proof of suitability.",\n      "Inspect loaded full schemas and verify real inputs, outputs, and side effects before invocation; the loaded definitions become available in the next turn.",\n      "Load additional tools only when new evidence creates a new need. Keep context use practical without imposing a fixed number of tools per checkpoint.",\n    ].join("\n"),\n    parameters: z.object({
      tool_ids: z.array(z.string()).describe("Tool IDs to load (from tool_search results)"),
    }),
    async execute(params, _ctx) {
      const { tool_ids } = params

      log.info("loading tools", { tool_ids })

      const loaded = await LazyToolRegistry.load(tool_ids)
      const stats = LazyToolRegistry.stats()

      const output = [
        `Loaded ${loaded.length} tool(s):`,
        "",
        ...loaded.map((t) => `- ${t.id}`),
        "",
        "These tools are now available for use.",
        "",
        "---",
        `Tool Stats: ${stats.loaded}/${stats.available} loaded | ~${stats.estimatedTokens} tokens used | ${stats.budgetRemaining} budget remaining`,
      ].join("\n")

      return {
        title: `Loaded ${loaded.length} tools`,
        output,
        metadata: {
          loadedCount: loaded.length,
          loadedIds: loaded.map((t) => t.id),
          stats,
        },
      }
    },
  }
})

export const UnloadToolsTool = Tool.define("unload_tools", async () => {
  return {
    description: [
      "Remove tools from context to free up token budget.",
      "Use this when you no longer need certain tools.",
    ].join("\n"),
    parameters: z.object({
      tool_ids: z.array(z.string()).describe("Tool IDs to unload"),
    }),
    async execute(params, _ctx) {
      const { tool_ids } = params

      log.info("unloading tools", { tool_ids })

      LazyToolRegistry.unload(tool_ids)

      const stats = LazyToolRegistry.stats()

      return {
        title: `Unloaded ${tool_ids.length} tools`,
        output: [
          `Unloaded ${tool_ids.length} tool(s).`,
          "",
          `Tool Stats: ${stats.loaded}/${stats.available} loaded | ~${stats.estimatedTokens} tokens used | ${stats.budgetRemaining} budget remaining`,
        ].join("\n"),
        metadata: {
          unloadedCount: tool_ids.length,
          unloadedIds: tool_ids,
          stats,
        },
      }
    },
  }
})

export const ListLoadedToolsTool = Tool.define("list_loaded_tools", async () => {
  return {
    description: "List all currently loaded tools, available MCP tools, and context usage.",
    parameters: z.object({}),
    async execute(_params, _ctx) {
      const loaded = LazyToolRegistry.getLoaded()
      const stats = LazyToolRegistry.stats()
      const allLazy = LazyToolRegistry.getAll()

      const lines: string[] = []

      if (loaded.length > 0) {
        lines.push(`Currently loaded tools (${loaded.length}):`, "")
        for (const t of loaded) lines.push(`- ${t.id}`)
        lines.push("")
      } else {
        lines.push("No tools currently loaded.", "")
      }

      if (allLazy.length > 0) {
        const byServer = new Map<string, string[]>()
        for (const t of allLazy) {
          const server = t.mcpServer ?? "unknown"
          if (!byServer.has(server)) byServer.set(server, [])
          byServer.get(server)!.push(t.name)
        }
        lines.push(`Available MCP tools (${allLazy.length}):`, "")
        for (const [server, toolNames] of byServer) {
          lines.push(`**${server}** (${toolNames.length} tools):`)
          for (const name of toolNames) lines.push(`  - ${name}`)
          lines.push("")
        }
        lines.push("Use `tool_search` to find tools by capability, then `load_tools` to activate them.")
      } else {
        lines.push("No MCP tools available. Connect an MCP server first.")
      }

      lines.push("", "---")
      lines.push(`Available: ${stats.available} | Loaded: ${stats.loaded}`)
      lines.push(`Token usage: ~${stats.estimatedTokens} / ${stats.estimatedTokens + stats.budgetRemaining}`)

      return {
        title: `${loaded.length} tools loaded, ${stats.available} available`,
        output: lines.join("\n"),
        metadata: {
          loadedCount: loaded.length,
          loadedIds: loaded.map((t) => t.id),
          stats,
        },
      }
    },
  }
})

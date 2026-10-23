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
      "Discover available connected tools by the current task, active checkpoint, evidence gap, asset type, protocol, or observed technology.",
      "Search afresh when entering a new checkpoint or when new evidence changes the needed capability; reuse already-loaded tool definitions when the need has not changed.",
      "Search is discovery, not a tool allowlist. Results are ranked candidates, not a requirement to use any particular tool.",
      "If results are missing or too narrow, retry with distinct synonyms, the capability name, protocol, or observable behavior. Increase limit when comparing more candidates.",
      "Inspect the selected tool's real schema and capabilities, then load relevant exact IDs with load_tools before invocation.",
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

      const results = LazyToolRegistry.search(query, limit)
      const output = LazyToolRegistry.formatSearchResults(results)
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
          toolIds: results.map((t) => t.id),
        },
      }
    },
  }
})

export const LoadToolsTool = Tool.define("load_tools", async () => {
  return {
    description: [
      "Load selected connected-tool definitions into context so they can be used.",
      "Use tool_search to discover candidates, then load only the exact IDs whose documented capabilities fit the current task.",
      "Do not load or run every candidate. Do not treat tool names, search ranking, or catalog examples as proof of suitability.",
      "Inspect the loaded schema and use the returned tool definitions; loaded tools will be available in the next turn.",
      "",
      "Load additional tools when new evidence creates a new need. Keep context use practical without imposing a fixed number of tools per checkpoint.",
    ].join("\n"),
    parameters: z.object({
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

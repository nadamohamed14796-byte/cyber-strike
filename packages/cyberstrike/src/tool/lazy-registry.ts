import { Log } from "../util/log"
import { MCP } from "../mcp"
import { Bus } from "../bus"
import type { Tool as AITool } from "ai"

const log = Log.create({ service: "tool.lazy-registry" })

/**
 * Lazy Tool Registry
 *
 * Dynamic tool loading to prevent context overflow.
 *
 * Problem:
 * - Each tool definition consumes ~500 tokens (description + parameters)
 * - 100 MCP tools = 50,000 tokens just for tool definitions
 *
 * Solution:
 * - Store only tool metadata (name, summary, keywords) - ~50 tokens each
 * - Full tool definitions loaded on-demand via ToolSearch
 * - Keep only actively-used tools in context
 */
export namespace LazyToolRegistry {
  export interface LazyTool {
    id: string
    name: string
    summary: string
    description: string
    keywords: string[]
    category: string
    source: "mcp" | "plugin" | "builtin"
    mcpServer?: string
  }

  export interface ToolSearchMatch {
    tool: LazyTool
    score: number
    coverage: number
    matchedTerms: string[]
    reasons: string[]
  }

  export interface LoadedTool {
    id: string
    tool: AITool
  }

  // State
  const lazyTools = new Map<string, LazyTool>()
  const loadedTools = new Map<string, LoadedTool>()
  const loadedToolIds = new Set<string>()

  const TOOL_CONTEXT_BUDGET = 30000
  const AVG_TOKENS_PER_TOOL = 500

  export async function init(): Promise<void> {
    log.info("initializing lazy tool registry")

    const mcpStatus = await MCP.status()
    const boltStatusMap = await MCP.boltStatus()
    const allStatus = { ...mcpStatus, ...boltStatusMap }
    const clients = await MCP.clients()

    const connectedServers = new Set<string>()
    for (const [serverName, status] of Object.entries(allStatus)) {
      if (status.status !== "connected") continue
      const client = clients[serverName]
      if (!client) continue
      connectedServers.add(serverName)
      try {
        const toolsResult = await client.listTools()
        reconcileServerTools(serverName, toolsResult.tools)
        log.info("collected tool metadata", { server: serverName, count: toolsResult.tools.length })
      } catch (err) {
        // Preserve last known metadata on transient listing failures.
        log.error("failed to collect tool metadata", { server: serverName, error: err })
      }
    }

    // A disconnected server can no longer provide callable tools.
    for (const serverName of new Set([...lazyTools.values()].map((tool) => tool.mcpServer).filter(Boolean) as string[])) {
      if (!connectedServers.has(serverName)) removeServerTools(serverName)
    }

    log.info("lazy tool registry initialized", {
      totalTools: lazyTools.size,
      loadedTools: loadedTools.size,
    })

    ensureSubscribed()
  }

  /**
   * Refresh tools from a specific server (called when ToolListChanged notification fires)
   */
  export async function refresh(serverName: string): Promise<void> {
    const clients = await MCP.clients()
    const client = clients[serverName]
    if (!client) return

    try {
      const toolsResult = await client.listTools()
      reconcileServerTools(serverName, toolsResult.tools)
      log.info("refreshed tools from server", {
        server: serverName,
        serverTools: toolsResult.tools.length,
        totalTools: lazyTools.size,
      })
    } catch (err) {
      log.error("failed to refresh tools", { server: serverName, error: err })
    }
  }

  // Ensure we only subscribe once
  let subscribed = false
  function ensureSubscribed() {
    if (subscribed) return
    subscribed = true
    Bus.subscribe(MCP.ToolsChanged, async (payload) => {
      log.info("tools changed notification, refreshing", { server: payload.properties.server })
      await refresh(payload.properties.server)
    })
  }



  function removeServerTools(serverName: string): void {
    for (const [id, tool] of lazyTools) {
      if (tool.mcpServer !== serverName) continue
      lazyTools.delete(id)
      loadedTools.delete(id)
      loadedToolIds.delete(id)
    }
  }

  /** Replace one server's snapshot after a successful listTools call. */
  export function reconcileServerTools(
    serverName: string,
    definitions: Array<{ name: string; description?: string }>,
  ): void {
    const next = new Map<string, LazyTool>()
    for (const mcpTool of definitions) {
      const id = MCP.toolID(serverName, mcpTool.name)
      const description = mcpTool.description || mcpTool.name
      const keywords = extractKeywords(mcpTool.name, description)
      next.set(id, {
        id,
        name: mcpTool.name,
        summary: description.slice(0, 100),
        description,
        keywords,
        category: categorize(keywords),
        source: "mcp",
        mcpServer: serverName,
      })
    }

    // Preserve loaded executable definitions when metadata is unchanged. The
    // registry is refreshed during each turn, so dropping every loaded entry
    // here would make load_tools appear to work for only one turn.
    for (const [id, existing] of lazyTools) {
      if (existing.mcpServer !== serverName) continue
      const updated = next.get(id)
      const unchanged = updated &&
        existing.name === updated.name &&
        existing.summary === updated.summary &&
        existing.description === updated.description &&
        existing.category === updated.category &&
        existing.keywords.length === updated.keywords.length &&
        existing.keywords.every((keyword, index) => keyword === updated.keywords[index])
      if (unchanged) {
        next.set(id, existing)
        continue
      }
      lazyTools.delete(id)
      loadedTools.delete(id)
      loadedToolIds.delete(id)
    }

    for (const [id, tool] of next) lazyTools.set(id, tool)
  }

  export function search(query: string, limit = 10): LazyTool[] {
    return searchDetailed(query, limit).map((match) => match.tool)
  }

  /** Rank by exact capability coverage; weak substring matches cannot qualify a tool alone. */
  export function searchDetailed(query: string, limit = 10): ToolSearchMatch[] {
    if (!query.trim() || !Number.isFinite(limit) || limit <= 0) return []
    const queryTokens = [...new Set(normalizeSearchTokens(query))]
    if (queryTokens.length === 0) return []
    const documents = [...lazyTools.values()].map((tool) => {
      const nameTokens = new Set(normalizeSearchTokens(tool.name))
      const descriptionTokens = new Set(normalizeSearchTokens(tool.description))
      const categoryTokens = new Set(normalizeSearchTokens(tool.category))
      const allTokens = new Set([...nameTokens, ...descriptionTokens, ...categoryTokens])
      return { tool, nameTokens, descriptionTokens, categoryTokens, allTokens }
    })
    const frequency = new Map<string, number>()
    for (const document of documents) {
      for (const token of document.allTokens) frequency.set(token, (frequency.get(token) ?? 0) + 1)
    }
    const queryPhrase = queryTokens.join(" ")
    const matches: ToolSearchMatch[] = []
    for (const document of documents) {
      let score = 0
      let exactMatches = 0
      const matchedTerms: string[] = []
      const reasons: string[] = []
      for (const token of queryTokens) {
        const count = frequency.get(token) ?? 0
        if (count === 0) continue
        const rarity = 1 + Math.log((documents.length + 1) / (count + 1))
        if (document.nameTokens.has(token)) {
          score += 12 * rarity
          exactMatches++
          matchedTerms.push(token)
          reasons.push('"' + token + '" appears in the tool name')
        } else if (document.descriptionTokens.has(token)) {
          score += 4 * rarity
          exactMatches++
          matchedTerms.push(token)
          reasons.push('"' + token + '" appears in the tool description')
        } else if (document.categoryTokens.has(token)) {
          score += 1.5 * rarity
          exactMatches++
          matchedTerms.push(token)
          reasons.push('"' + token + '" matches the tool category')
        } else if (token.length >= 5 && [...document.allTokens].some((candidate) => candidate.length >= 5 && (candidate.startsWith(token) || token.startsWith(candidate)))) {
          score += 0.5 * rarity
        }
      }
      if (exactMatches === 0) continue
      const coverage = exactMatches / queryTokens.length
      score += coverage * 8
      const namePhrase = normalizeSearchTokens(document.tool.name).join(" ")
      const descriptionPhrase = normalizeSearchTokens(document.tool.description).join(" ")
      if (queryPhrase && namePhrase.includes(queryPhrase)) score += 20
      else if (queryPhrase && descriptionPhrase.includes(queryPhrase)) score += 7
      matches.push({ tool: document.tool, score, coverage, matchedTerms, reasons })
    }
    matches.sort((a, b) => b.score - a.score || b.coverage - a.coverage || Number(isLoaded(b.tool.id)) - Number(isLoaded(a.tool.id)) || a.tool.name.localeCompare(b.tool.name))
    return matches.slice(0, Math.floor(limit))
  }
  export async function load(toolIds: string[]): Promise<LoadedTool[]> {
    const newlyLoaded: LoadedTool[] = []

    const currentCount = loadedTools.size
    const newCount = toolIds.filter((id) => !loadedToolIds.has(id)).length
    const estimatedTokens = (currentCount + newCount) * AVG_TOKENS_PER_TOOL

    if (estimatedTokens > TOOL_CONTEXT_BUDGET) {
      log.warn("tool context budget exceeded, unloading least used tools", {
        current: currentCount,
        new: newCount,
        estimated: estimatedTokens,
        budget: TOOL_CONTEXT_BUDGET,
      })
    }

    const mcpTools = await MCP.tools()

    for (const id of toolIds) {
      if (loadedToolIds.has(id)) {
        const existing = loadedTools.get(id)
        if (existing) newlyLoaded.push(existing)
        continue
      }

      const lazyTool = lazyTools.get(id)
      if (!lazyTool) {
        log.warn("tool not found in lazy registry", { id })
        continue
      }

      const fullTool = mcpTools[id]
      if (!fullTool) {
        log.warn("tool not found in MCP", { id })
        continue
      }

      const loaded: LoadedTool = {
        id,
        tool: fullTool,
      }

      loadedTools.set(id, loaded)
      loadedToolIds.add(id)
      newlyLoaded.push(loaded)

      log.info("loaded tool", { id, source: lazyTool.source })
    }

    return newlyLoaded
  }

  export function unload(toolIds: string[]): void {
    for (const id of toolIds) {
      loadedTools.delete(id)
      loadedToolIds.delete(id)
      log.info("unloaded tool", { id })
    }
  }

  export function getLoaded(): LoadedTool[] {
    return Array.from(loadedTools.values())
  }

  export function getAll(): LazyTool[] {
    return Array.from(lazyTools.values())
  }

  export function isLoaded(id: string): boolean {
    return loadedToolIds.has(id)
  }

  export function stats(): {
    available: number
    loaded: number
    estimatedTokens: number
    budgetRemaining: number
  } {
    const loaded = loadedTools.size
    const estimatedTokens = loaded * AVG_TOKENS_PER_TOOL
    return {
      available: lazyTools.size,
      loaded,
      estimatedTokens,
      budgetRemaining: TOOL_CONTEXT_BUDGET - estimatedTokens,
    }
  }

  export function formatSearchResults(tools: LazyTool[]): string {
    if (tools.length === 0) {
      return "No matching tools found."
    }

    const lines = [
      `Found ${tools.length} matching tool(s):`,
      "",
      ...tools.map((t, i) => {
        const loaded = isLoaded(t.id) ? " [LOADED]" : ""
        return `${i + 1}. **${t.name}**${loaded}\n   ID: \`${t.id}\`\n   ${t.summary}\n   Category: ${t.category}`
      }),
      "",
      "Use `load_tools` with the tool IDs to make them available for use.",
    ]

    return lines.join("\n")
  }

  const SEARCH_STOP_WORDS = new Set([
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does", "did",
    "will", "would", "could", "should", "may", "might", "must", "shall", "can", "need", "to", "of", "in", "for", "on",
    "with", "at", "by", "from", "as", "into", "through", "during", "before", "after", "above", "below", "between", "under",
    "again", "further", "then", "once", "and", "but", "or", "nor", "so", "yet", "this", "that", "these", "those",
    "use", "using", "used", "tool", "tools", "available", "support", "supports", "provide", "provides", "help", "helps",
    "return", "returns", "result", "results", "description", "current",
  ])
  const SEARCH_TOKEN_ALIASES: Record<string, string> = {
    js: "javascript", ecmascript: "javascript", analysis: "analyze", analyzing: "analyze", analyzed: "analyze",
    discovery: "discover", discovering: "discover", discovered: "discover", enumeration: "enumerate", enumerating: "enumerate",
    enumerated: "enumerate", collection: "collect", collecting: "collect", collected: "collect", crawling: "crawl",
    crawler: "crawl", crawlers: "crawl", verification: "verify", verifying: "verify", verified: "verify",
    validation: "validate", validating: "validate", validated: "validate", correlation: "correlate", correlating: "correlate",
    testing: "test", tests: "test", fuzzing: "fuzz", installation: "install", installing: "install", extraction: "extract", extracting: "extract",
  }
  function normalizeSearchTokens(value: string): string[] {
    return value.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().replace(/[^a-z0-9]+/g, " ").split(/\s+/).filter(Boolean).map((word) => {
      let token = SEARCH_TOKEN_ALIASES[word] ?? word
      if (token.endsWith("ies") && token.length > 4) token = token.slice(0, -3) + "y"
      else if (token.endsWith("es") && token.length > 5 && /(?:ches|shes|sses|xes|zes)$/.test(token)) token = token.slice(0, -2)
      else if (token.endsWith("s") && token.length > 4 && !/(ss|us|is)$/.test(token)) token = token.slice(0, -1)
      return SEARCH_TOKEN_ALIASES[token] ?? token
    }).filter((token) => token.length > 1 && !SEARCH_STOP_WORDS.has(token))
  }
  function extractKeywords(name: string, description: string): string[] {
    const text = `${name} ${description}`.toLowerCase()

    const stopWords = new Set([
      "the",
      "a",
      "an",
      "is",
      "are",
      "was",
      "were",
      "be",
      "been",
      "being",
      "have",
      "has",
      "had",
      "do",
      "does",
      "did",
      "will",
      "would",
      "could",
      "should",
      "may",
      "might",
      "must",
      "shall",
      "can",
      "need",
      "dare",
      "ought",
      "used",
      "to",
      "of",
      "in",
      "for",
      "on",
      "with",
      "at",
      "by",
      "from",
      "as",
      "into",
      "through",
      "during",
      "before",
      "after",
      "above",
      "below",
      "between",
      "under",
      "again",
      "further",
      "then",
      "once",
      "and",
      "but",
      "or",
      "nor",
      "so",
      "yet",
      "this",
      "that",
      "these",
      "those",
    ])

    const words = text
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 2 && !stopWords.has(w))

    return [...new Set(words)]
  }

  function categorize(keywords: string[]): string {
    const categories: Record<string, string[]> = {
      web: ["http", "web", "url", "api", "request", "response", "html", "css", "javascript", "browser"],
      network: ["network", "port", "scan", "nmap", "tcp", "udp", "ip", "dns", "socket"],
      file: ["file", "read", "write", "directory", "path", "folder"],
      security: ["security", "vulnerability", "exploit", "attack", "inject", "xss", "sql", "csrf"],
      cloud: ["aws", "azure", "gcp", "cloud", "s3", "ec2", "lambda", "bucket"],
      database: ["database", "sql", "query", "mysql", "postgres", "mongo", "redis"],
      git: ["git", "commit", "branch", "merge", "repository", "clone"],
      shell: ["shell", "bash", "command", "terminal", "exec", "process"],
    }

    for (const [category, categoryKeywords] of Object.entries(categories)) {
      for (const keyword of keywords) {
        if (categoryKeywords.some((ck) => keyword.includes(ck) || ck.includes(keyword))) {
          return category
        }
      }
    }

    return "general"
  }

  export function clear(): void {
    lazyTools.clear()
    loadedTools.clear()
    loadedToolIds.clear()
  }
}

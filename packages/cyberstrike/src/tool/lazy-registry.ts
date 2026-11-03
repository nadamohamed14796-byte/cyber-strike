import { createHash } from "crypto"
import { Log } from "../util/log"
import { MCP } from "../mcp"
import { Bus } from "../bus"
import type { Tool as AITool } from "ai"
import { Instance } from "../project/instance"

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
    inputSchemaFingerprint: string
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

  type RegistryState = {
    lazyTools: Map<string, LazyTool>
    loadedTools: Map<string, LoadedTool>
    loadedToolIds: Set<string>
    clients: Map<string, object>
    refreshing: Map<string, Promise<void>>
    initializing?: Promise<void>
    unsubscribe?: () => void
  }

  // MCP clients, Bus subscriptions and project tool registries are all scoped to
  // Instance.directory. Keeping this state per project prevents two active
  // projects with the same MCP server name from sharing tools or live clients.
  const state = Instance.state<RegistryState>(
    () => ({
      lazyTools: new Map(),
      loadedTools: new Map(),
      loadedToolIds: new Set(),
      clients: new Map(),
      refreshing: new Map(),
    }),
    async (current) => {
      current.unsubscribe?.()
      current.unsubscribe = undefined
      current.lazyTools.clear()
      current.loadedTools.clear()
      current.loadedToolIds.clear()
      current.clients.clear()
      current.refreshing.clear()
    },
  )

  const TOOL_CONTEXT_BUDGET = 30000
  const AVG_TOKENS_PER_TOOL = 500

  export async function init(): Promise<void> {
    const current = state()
    if (current.initializing) return current.initializing

    const pending = (async () => {
      log.info("initializing lazy tool registry")
      const [mcpStatus, boltStatusMap, clients] = await Promise.all([
        MCP.status(),
        MCP.boltStatus(),
        MCP.clients(),
      ])
      const allStatus = { ...mcpStatus, ...boltStatusMap }
      const connectedEntries = Object.entries(allStatus).filter(
        ([serverName, status]) => status.status === "connected" && Boolean(clients[serverName]),
      )
      const connectedServers = new Set(connectedEntries.map(([serverName]) => serverName))

      ensureSubscribed(current)

      // Independent MCP servers must not serialize model startup. Reuse a
      // snapshot while the underlying client identity is unchanged; the
      // ToolsChanged event below refreshes it when the server changes its schema.
      await Promise.all(
        connectedEntries.map(([serverName]) => refreshServerTools(current, serverName, clients[serverName]!)),
      )

      const knownServers = new Set([
        ...current.clients.keys(),
        ...[...current.lazyTools.values()].map((tool) => tool.mcpServer).filter(Boolean) as string[],
      ])
      for (const serverName of knownServers) {
        if (connectedServers.has(serverName)) continue
        removeServerTools(current, serverName)
        current.clients.delete(serverName)
      }

      log.info("lazy tool registry initialized", {
        totalTools: current.lazyTools.size,
        loadedTools: current.loadedTools.size,
      })
    })()

    current.initializing = pending
    try {
      await pending
    } finally {
      if (current.initializing === pending) current.initializing = undefined
    }
  }

  /** Refresh one server after a ToolListChanged notification or client change. */
  export async function refresh(serverName: string): Promise<void> {
    const current = state()
    const clients = await MCP.clients()
    const client = clients[serverName]
    if (!client) {
      removeServerTools(current, serverName)
      current.clients.delete(serverName)
      return
    }
    await refreshServerTools(current, serverName, client, true)
  }

  async function refreshServerTools(
    current: RegistryState,
    serverName: string,
    client: { listTools(): Promise<{ tools: Array<{ name: string; description?: string; inputSchema?: unknown }> }> },
    force = false,
  ): Promise<void> {
    const inFlight = current.refreshing.get(serverName)
    if (inFlight) {
      await inFlight
      if (!force && current.clients.get(serverName) === client) return
    }
    if (!force && current.clients.get(serverName) === client) return

    // A replacement connection invalidates executable closures from the old
    // client even when the server returns an identical schema.
    if (current.clients.get(serverName) !== client) invalidateLoadedServerTools(current, serverName)

    const pending = (async () => {
      try {
        const toolsResult = await client.listTools()
        const latestClients = await MCP.clients()
        if (latestClients[serverName] !== client) return
        reconcileServerToolsInState(current, serverName, toolsResult.tools)
        current.clients.set(serverName, client)
        log.info("collected tool metadata", { server: serverName, count: toolsResult.tools.length })
      } catch (err) {
        // Preserve searchable metadata on transient failures, but do not treat
        // a replacement client as loaded until its own schema is confirmed.
        log.error("failed to collect tool metadata", { server: serverName, error: err })
      }
    })()
    current.refreshing.set(serverName, pending)
    try {
      await pending
    } finally {
      if (current.refreshing.get(serverName) === pending) current.refreshing.delete(serverName)
    }
  }

  function ensureSubscribed(current: RegistryState): void {
    if (current.unsubscribe) return
    current.unsubscribe = Bus.subscribe(MCP.ToolsChanged, async (payload) => {
      log.info("tools changed notification, refreshing", { server: payload.properties.server })
      await refresh(payload.properties.server)
    })
  }

  function invalidateLoadedServerTools(current: RegistryState, serverName: string): void {
    for (const [id, tool] of current.lazyTools) {
      if (tool.mcpServer !== serverName) continue
      current.loadedTools.delete(id)
      current.loadedToolIds.delete(id)
    }
  }

  function removeServerTools(current: RegistryState, serverName: string): void {
    for (const [id, tool] of current.lazyTools) {
      if (tool.mcpServer !== serverName) continue
      current.lazyTools.delete(id)
      current.loadedTools.delete(id)
      current.loadedToolIds.delete(id)
    }
  }

  function fingerprintInputSchema(schema: unknown): string {
    const stable = (value: unknown): string => {
      if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]"
      if (value !== null && typeof value === "object") {
        const object = value as Record<string, unknown>
        return "{" + Object.keys(object).sort().map((key) =>
          JSON.stringify(key) + ":" + stable(object[key]),
        ).join(",") + "}"
      }
      return JSON.stringify(value) ?? String(value)
    }
    return createHash("sha256").update(stable(schema)).digest("hex")
  }

  function reconcileServerToolsInState(
    current: RegistryState,
    serverName: string,
    definitions: Array<{ name: string; description?: string; inputSchema?: unknown }>,
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
        inputSchemaFingerprint: fingerprintInputSchema(mcpTool.inputSchema),
      })
    }

    // Preserve a loaded definition only if metadata is unchanged AND the
    // connection identity was retained by refreshServerTools.
    for (const [id, existing] of current.lazyTools) {
      if (existing.mcpServer !== serverName) continue
      const updated = next.get(id)
      const unchanged = updated &&
        existing.name === updated.name &&
        existing.summary === updated.summary &&
        existing.description === updated.description &&
        existing.category === updated.category &&
        existing.inputSchemaFingerprint === updated.inputSchemaFingerprint &&
        existing.keywords.length === updated.keywords.length &&
        existing.keywords.every((keyword, index) => keyword === updated.keywords[index])
      if (unchanged) {
        next.set(id, existing)
        continue
      }
      current.lazyTools.delete(id)
      current.loadedTools.delete(id)
      current.loadedToolIds.delete(id)
    }

    for (const [id, tool] of next) current.lazyTools.set(id, tool)
  }

  /** Replace one server's snapshot after a successful listTools call. */
  export function reconcileServerTools(
    serverName: string,
    definitions: Array<{ name: string; description?: string; inputSchema?: unknown }>,
  ): void {
    reconcileServerToolsInState(state(), serverName, definitions)
  }

  export function search(query: string, limit = 10): LazyTool[] {
    return searchDetailed(query, limit).map((match) => match.tool)
  }

  /** Rank by exact capability coverage; weak substring matches cannot qualify a tool alone. */
  export function searchDetailed(query: string, limit = 10): ToolSearchMatch[] {
    if (!query.trim() || !Number.isFinite(limit) || limit <= 0) return []
    const queryTokens = [...new Set(normalizeSearchTokens(query))]
    if (queryTokens.length === 0) return []

    const documents = [...state().lazyTools.values()].map((tool) => {
      const nameTokens = new Set(normalizeSearchTokens(tool.name))
      const descriptionTokens = new Set(normalizeSearchTokens(tool.description))
      const categoryTokens = new Set(normalizeSearchTokens(tool.category))
      const allTokens = new Set([...nameTokens, ...descriptionTokens, ...categoryTokens])
      return { tool, nameTokens, descriptionTokens, categoryTokens, allTokens }
    })
    const frequency = new Map<string, number>()
    for (const document of documents) {
      for (const token of document.allTokens) {
        frequency.set(token, (frequency.get(token) ?? 0) + 1)
      }
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
        } else if (
          token.length >= 5 &&
          [...document.allTokens].some((candidate) =>
            candidate.length >= 5 && (candidate.startsWith(token) || token.startsWith(candidate)),
          )
        ) {
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

    matches.sort((a, b) =>
      b.score - a.score ||
      b.coverage - a.coverage ||
      Number(isLoaded(b.tool.id)) - Number(isLoaded(a.tool.id)) ||
      a.tool.name.localeCompare(b.tool.name),
    )
    return matches.slice(0, Math.floor(limit))
  }

  export async function load(toolIds: string[]): Promise<LoadedTool[]> {
    const current = state()
    const requestedIDs = [...new Set(toolIds)]
    const newlyLoaded: LoadedTool[] = []
    const toLoad = requestedIDs.filter((id) => !current.loadedToolIds.has(id) && current.lazyTools.has(id))

    const estimatedTokens = (current.loadedTools.size + toLoad.length) * AVG_TOKENS_PER_TOOL
    if (estimatedTokens > TOOL_CONTEXT_BUDGET) {
      // Loading is intentionally lossless: never silently discard a tool the
      // agent explicitly selected. The budget is advisory, and the caller can
      // inspect/unload tools deliberately after the current evidence task.
      log.warn("tool context budget exceeded; keeping explicitly requested tools loaded", {
        current: current.loadedTools.size,
        new: toLoad.length,
        estimated: estimatedTokens,
        budget: TOOL_CONTEXT_BUDGET,
      })
    }

    // Only enumerate servers that own the explicitly requested lazy tools.
    // MCP.tools() without a filter remains available for legacy all-server callers.
    const requestedServers = [
      ...new Set(
        toLoad
          .map((id) => current.lazyTools.get(id)?.mcpServer)
          .filter((name): name is string => Boolean(name)),
      ),
    ]
    const mcpTools = toLoad.length > 0
      ? await MCP.tools(requestedServers.length > 0 ? requestedServers : undefined)
      : {}
    for (const id of requestedIDs) {
      if (current.loadedToolIds.has(id)) {
        const existing = current.loadedTools.get(id)
        if (existing) newlyLoaded.push(existing)
        continue
      }

      const lazyTool = current.lazyTools.get(id)
      if (!lazyTool) {
        log.warn("tool not found in lazy registry", { id })
        continue
      }

      const fullTool = mcpTools[id]
      if (!fullTool) {
        log.warn("tool not found in MCP", { id })
        continue
      }

      const loaded: LoadedTool = { id, tool: fullTool }
      current.loadedTools.set(id, loaded)
      current.loadedToolIds.add(id)
      newlyLoaded.push(loaded)
      log.info("loaded tool", { id, source: lazyTool.source })
    }

    return newlyLoaded
  }

  export function unload(toolIds: string[]): void {
    const current = state()
    for (const id of toolIds) {
      current.loadedTools.delete(id)
      current.loadedToolIds.delete(id)
      log.info("unloaded tool", { id })
    }
  }

  export function getLoaded(): LoadedTool[] {
    return Array.from(state().loadedTools.values())
  }

  export function getAll(): LazyTool[] {
    return Array.from(state().lazyTools.values())
  }

  export function isLoaded(id: string): boolean {
    return state().loadedToolIds.has(id)
  }

  export function stats(): {
    available: number
    loaded: number
    estimatedTokens: number
    budgetRemaining: number
  } {
    const current = state()
    const loaded = current.loadedTools.size
    const estimatedTokens = loaded * AVG_TOKENS_PER_TOOL
    return {
      available: current.lazyTools.size,
      loaded,
      estimatedTokens,
      budgetRemaining: TOOL_CONTEXT_BUDGET - estimatedTokens,
    }
  }

  export function formatSearchResults(tools: LazyTool[]): string {
    if (tools.length === 0) return "No matching tools found."

    const lines = [
      `Found ${tools.length} matching tool(s):`,
      "",
      ...tools.map((tool, index) => {
        const loaded = isLoaded(tool.id) ? " [LOADED]" : ""
        return `${index + 1}. **${tool.name}**${loaded}\n   ID: \`${tool.id}\`\n   ${tool.summary}\n   Category: ${tool.category}`
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
    js: "javascript", maps: "map", ecmascript: "javascript", analysis: "analyze", analyzing: "analyze", analyzed: "analyze",
    discovery: "discover", discovering: "discover", discovered: "discover", enumeration: "enumerate", enumerating: "enumerate",
    enumerated: "enumerate", collection: "collect", collecting: "collect", collected: "collect", crawling: "crawl",
    crawler: "crawl", crawlers: "crawl", verification: "verify", verifying: "verify", verified: "verify",
    validation: "validate", validating: "validate", validated: "validate", correlation: "correlate", correlating: "correlate",
    testing: "test", tests: "test", fuzzing: "fuzz", installation: "install", installing: "install", extraction: "extract", extracting: "extract",
  }

  function normalizeSearchTokens(value: string): string[] {
    return value
      // Preserve the canonical language name before splitting generic camelCase tokens.
      .replace(/javascript/gi, "javascript")
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, " ")
      .split(/\s+/)
      .filter(Boolean)
      .map((word) => {
        let token = SEARCH_TOKEN_ALIASES[word] ?? word
        if (token.endsWith("ies") && token.length > 4) token = token.slice(0, -3) + "y"
        else if (token.endsWith("es") && token.length > 5 && /(?:ches|shes|sses|xes|zes)$/.test(token)) token = token.slice(0, -2)
        else if (token.endsWith("s") && token.length > 4 && !/(ss|us|is)$/.test(token)) token = token.slice(0, -1)
        return SEARCH_TOKEN_ALIASES[token] ?? token
      })
      .filter((token) => token.length > 1 && !SEARCH_STOP_WORDS.has(token))
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
    const current = state()
    current.lazyTools.clear()
    current.loadedTools.clear()
    current.loadedToolIds.clear()
    current.clients.clear()
  }
}

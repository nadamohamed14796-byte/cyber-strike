import { checkMatch } from "./scope-match"

type CompiledScopeItems = {
  exactHosts: Set<string>
  wildcardDomains: Set<string>
  cidrs: string[]
  urlPatterns: string[]
  hostPorts: string[]
  typedEntries: string[]
  wildcardPatterns: string[]
}
const compiledScopeItemsCache = new WeakMap<string[], CompiledScopeItems>()


/** Compile large scope manifests once; common exact-host checks then use O(1) set lookups. */
function compileScopeItems(items: string[]): CompiledScopeItems {
  const cached = compiledScopeItemsCache.get(items)
  if (cached) return cached
  const exactHosts = new Set<string>()
  const wildcardDomains = new Set<string>()
  const cidrs: string[] = []
  const urlPatterns: string[] = []
  const hostPorts: string[] = []
  const typedEntries: string[] = []
  const wildcardPatterns: string[] = []
  for (const item of items) {
    if (/^(?:domain|wildcard|url|cidr|ip address|api|ai model|smart contracts?|source code|executable|hardware(?:\/iot)?|ios(?:: app store|: testflight|: \.ipa)?|android(?: play store|: \.apk)?|windows: microsoft store|aws account|azure account|aws cloud config|azure cloud config|other(?: asset)?)[ \t]*:/i.test(item)) typedEntries.push(item)
    else if (/^https?:\/\//i.test(item)) urlPatterns.push(item)
    else if (/^\d+(?:\.\d+){3}\/.+$/.test(item) || (item.includes("/") && item.includes(":"))) cidrs.push(item)
    else if (/^[^:/]+:\d{1,5}$/.test(item)) hostPorts.push(item)
    else if (item.startsWith("*.")) wildcardDomains.add(item.slice(2))
    else if (item.includes("*") || /\{[^{}]+\}/.test(item)) wildcardPatterns.push(item)
    else exactHosts.add(item)
  }
  const compiled = { exactHosts, wildcardDomains, cidrs, urlPatterns, hostPorts, typedEntries, wildcardPatterns }
  compiledScopeItemsCache.set(items, compiled)
  return compiled
}

/** Return only the entries that match this URL without scanning every host in a large file. */
export function matchingScopeItems(candidate: URL | string, items: string[]): string[] {
  const url = typeof candidate === "string" ? new URL(candidate) : candidate
  const index = compileScopeItems(items)
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "")
  const matches: string[] = []
  if (index.exactHosts.has(hostname)) matches.push(hostname)

  // An explicit wildcard represents the whole domain family, including the
  // apex. Walk URL suffixes instead of iterating all wildcard patterns.
  const labels = hostname.split(".")
  for (let offset = 0; offset < labels.length; offset++) {
    const suffix = labels.slice(offset).join(".")
    if (index.wildcardDomains.has(suffix)) matches.push("*." + suffix)
  }
  for (const pattern of [...index.urlPatterns, ...index.hostPorts, ...index.cidrs, ...index.typedEntries, ...index.wildcardPatterns]) {
    if (checkMatch(url.href, pattern).matches) matches.push(pattern)
  }
  return matches
}

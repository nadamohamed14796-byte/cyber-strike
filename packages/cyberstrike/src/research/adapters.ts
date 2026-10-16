import type { ResearchSource } from "./sources"

function withQuery(url: string, key: string, value: number) {
  const parsed = new URL(url)
  parsed.searchParams.set(key, String(value))
  return parsed.toString()
}

function withPathPage(url: string, page: number) {
  const parsed = new URL(url)
  const path = parsed.pathname.replace(/\/page\/\d+\/?$/i, "").replace(/\/$/, "")
  parsed.pathname = path + "/page/" + page
  return parsed.toString()
}

/**
 * Return only the source's canonical starting URLs. Pagination is generated lazily
 * by nextDiscoveryPage as each page is visited, so the crawler does not allocate
 * thousands of future URLs or silently truncate a large archive at a fixed ceiling.
 */
export function discoverySeeds(source: ResearchSource) {
  return [...new Set(source.seedUrls)]
}

/**
 * Produce the next URL in a known public pagination scheme. Only one successor is
 * generated at a time; the crawler stops the chain when a page is empty, repeats
 * the prior page content, or returns a normal end-of-pagination response.
 */
export function nextDiscoveryPage(source: ResearchSource, value: string) {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return undefined
  }

  switch (source.id) {
    case "hackerone-hacktivity":
      if (parsed.pathname.includes("/overview")) {
        const current = Number(parsed.searchParams.get("pageIndex") ?? "0")
        if (!Number.isSafeInteger(current) || current < -1) return undefined
        return withQuery(value, "pageIndex", current + 1)
      }
      {
        const current = Number(parsed.searchParams.get("page") ?? "1")
        if (!Number.isSafeInteger(current) || current < 1) return undefined
        return withQuery(value, "page", current + 1)
      }
    case "medium-security": {
      if (!/^\/tag\//i.test(parsed.pathname)) return undefined
      const current = Number(parsed.searchParams.get("page") ?? "1")
      if (!Number.isSafeInteger(current) || current < 1) return undefined
      return withQuery(value, "page", current + 1)
    }
    case "bugcrowd-crowdstream":
    case "github": {
      const current = Number(parsed.searchParams.get("page") ?? "1")
      if (!Number.isSafeInteger(current) || current < 1) return undefined
      return withQuery(value, "page", current + 1)
    }
    case "intigriti":
    case "infosec-writeups":
    case "hackerone-blog":
    case "bugcrowd-blog":
    case "yeswehack":
    case "nahamsec":
    case "pentesterland":
    case "assetnote":
    case "projectdiscovery":
    case "edoverflow":
    case "devcore":
    case "liveoverflow": {
      const match = parsed.pathname.match(/\/page\/(\d+)\/?$/)
      const current = match ? Number(match[1]) : 1
      if (!Number.isSafeInteger(current) || current < 1) return undefined
      return withPathPage(value, current + 1)
    }
    default:
      return undefined
  }
}

/** True for URLs shaped like a page in a supported pagination scheme. */
export function isDiscoveryPaginationURL(source: ResearchSource, value: string) {
  try {
    const parsed = new URL(value)
    if (source.id === "hackerone-hacktivity") {
      if (parsed.pathname.includes("/overview")) return parsed.searchParams.has("pageIndex")
      return parsed.searchParams.has("page") && /^\d+$/.test(parsed.searchParams.get("page") ?? "")
    }
    if (source.id === "medium-security") {
      return /^\/tag\//i.test(parsed.pathname) && parsed.searchParams.has("page") && /^\d+$/.test(parsed.searchParams.get("page") ?? "")
    }
    if (["bugcrowd-crowdstream", "github"].includes(source.id)) {
      return parsed.searchParams.has("page") && /^\d+$/.test(parsed.searchParams.get("page") ?? "")
    }
    if ([
      "intigriti", "infosec-writeups", "hackerone-blog", "bugcrowd-blog", "yeswehack",
      "nahamsec", "pentesterland", "assetnote", "projectdiscovery", "edoverflow", "devcore", "liveoverflow",
    ].includes(source.id)) {
      return /\/page\/\d+\/?$/i.test(parsed.pathname)
    }
    return false
  } catch {
    return false
  }
}

export function sourceDocumentPriority(source: ResearchSource, url: string) {
  const path = new URL(url).pathname.toLowerCase()
  switch (source.id) {
    case "hackerone-hacktivity":
      return /hacktivity|reports?/.test(path) ? 30 : 0
    case "bugcrowd-crowdstream":
      return /crowdstream|reports?/.test(path) ? 30 : 0
    case "intigriti":
      return /blog|writeup|research/.test(path) ? 25 : 0
    case "yeswehack":
      return /blog|writeup|research/.test(path) ? 25 : 0
    case "github":
      return /search|issues|blob|tree/.test(path) ? 20 : 0
    default:
      return 0
  }
}

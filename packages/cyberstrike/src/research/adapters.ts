import type { ResearchSource } from "./sources"

const PAGE_CAP = 100

function withQuery(url: string, key: string, value: number) {
  const parsed = new URL(url)
  parsed.searchParams.set(key, String(value))
  return parsed.toString()
}

function withPathPage(url: string, page: number) {
  const parsed = new URL(url)
  const path = parsed.pathname.replace(/\/$/, "")
  parsed.pathname = path + "/page/" + page
  return parsed.toString()
}

/**
 * Source-specific discovery seeds. These are public archive/search pagination
 * hints only; the crawler still follows canonical links and sitemaps and never
 * bypasses authentication or access controls.
 */
export function discoverySeeds(source: ResearchSource, maxPages: number) {
  const pages = Math.max(1, Math.min(maxPages, PAGE_CAP))
  const seeds = new Set(source.seedUrls)

  const addQueryPages = (urls: string[], key = "page") => {
    for (const url of urls) {
      for (let page = 2; page <= pages; page++) seeds.add(withQuery(url, key, page))
    }
  }

  const addPathPages = (urls: string[]) => {
    for (const url of urls) {
      for (let page = 2; page <= pages; page++) seeds.add(withPathPage(url, page))
    }
  }

  switch (source.id) {
    case "hackerone-hacktivity":
      for (const url of source.seedUrls) {
        const parsed = new URL(url)
        if (parsed.pathname.includes("/overview")) {
          for (let page = 1; page < pages; page++) {
            parsed.searchParams.set("pageIndex", String(page))
            seeds.add(parsed.toString())
          }
        } else {
          addQueryPages([url])
        }
      }
      break
    case "bugcrowd-crowdstream":
      addQueryPages(source.seedUrls)
      break
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
    case "liveoverflow":
      addPathPages(source.seedUrls)
      addQueryPages(source.seedUrls)
      break
    case "medium":
      addQueryPages(source.seedUrls)
      break
    case "github":
      addQueryPages(source.seedUrls)
      break
    default:
      break
  }

  return [...seeds]
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
    case "medium":
      return /tag\/bug-bounty|bug-bounty-hunting/.test(path) ? 35 : 0
    case "github":
      return /search|issues|blob|tree/.test(path) ? 20 : 0
    default:
      return 0
  }
}

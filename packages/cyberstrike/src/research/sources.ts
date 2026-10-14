/** Bump when classification/extraction semantics change so old rejected queue rows can be safely revisited once. */
export const RESEARCH_LEARNING_VERSION = 8
/** Increment when the model-led article study format changes, not for heuristic extraction changes. */
export const RESEARCH_MODEL_STUDY_VERSION = 2

export type ResearchSourceKind = "disclosure" | "academy" | "writeup" | "blog" | "reference" | "research"

export type ResearchSource = {
  id: string
  name: string
  kind: ResearchSourceKind
  seedUrls: string[]
  hosts: string[]
  trust: number
  /** Source-specific discovery/relevance policy. */
  includeTerms?: string[]
  excludeTerms?: string[]
  includePaths?: string[]
  excludePaths?: string[]
}

export const RESEARCH_SOURCES: ResearchSource[] = [
  {
    id: "hackerone-hacktivity",
    name: "HackerOne Hacktivity",
    kind: "disclosure",
    seedUrls: [
      "https://hackerone.com/hacktivity",
      "https://hackerone.com/hacktivity/overview?pageIndex=0&queryString=disclosed%3Atrue&sortDirection=DESC&sortField=latest_disclosable_activity_at",
    ],
    hosts: ["hackerone.com"],
    trust: 95,
  },
  {
    id: "bugcrowd-crowdstream",
    name: "Bugcrowd CrowdStream",
    kind: "disclosure",
    seedUrls: ["https://bugcrowd.com/crowdstream"],
    hosts: ["bugcrowd.com"],
    trust: 95,
  },
  {
    id: "intigriti",
    name: "Intigriti",
    kind: "writeup",
    seedUrls: ["https://www.intigriti.com/researchers/blog"],
    hosts: ["intigriti.com"],
    trust: 90,
  },
  {
    id: "yeswehack",
    name: "YesWeHack",
    kind: "disclosure",
    seedUrls: ["https://blog.yeswehack.com/"],
    hosts: ["yeswehack.com"],
    trust: 90,
  },
  {
    id: "portswigger",
    name: "PortSwigger Web Security Academy",
    kind: "academy",
    seedUrls: ["https://portswigger.net/web-security/all-labs"],
    hosts: ["portswigger.net"],
    trust: 100,
  },
  {
    id: "pentesterland",
    name: "PentesterLand",
    kind: "writeup",
    seedUrls: ["https://pentester.land/writeups/", "https://pentester.land/"],
    hosts: ["pentester.land"],
    trust: 90,
  },
  // The generic Medium tag crawler is intentionally omitted because it produced excessive off-topic articles.
  {
    id: "infosec-writeups",
    name: "InfoSec Write-ups",
    kind: "writeup",
    seedUrls: ["https://infosecwriteups.com/tagged/bug-bounty", "https://infosecwriteups.com/"],
    hosts: ["infosecwriteups.com"],
    trust: 85,
  },
  {
    id: "infosec-weekly",
    name: "The Infosec Newsletter (Weekly InfoSec Write-ups)",
    kind: "writeup",
    seedUrls: ["https://weekly.infosecwriteups.com/"],
    hosts: ["weekly.infosecwriteups.com"],
    trust: 80,
    includeTerms: [
      "bug bounty",
      "vulnerability",
      "security research",
      "writeup",
      "authentication bypass",
      "xss",
      "ssrf",
      "idor",
      "injection",
      "web security",
      "penetration testing",
      "cors",
      "cross-origin resource sharing",
      "information disclosure",
      "information-disclosure",
      "privilege escalation",
      "privilege-escalation",
      "security misconfiguration",
      "security-misconfiguration",
      "account takeover",
      "account-takeover",
      "mass assignment",
      "mass-assignment",
      "nosql injection",
      "nosqli",
      "host header injection",
      "host-header-injection",
      "mfa bypass",
      "mfa-bypass",
      "rate limit bypass",
      "rate-limit-bypass",
      "websocket",
      "saml",
    ],
    excludeTerms: ["job alert", "career advice", "general news"],
  },
  {
    id: "securitycipher-bounty-writeups",
    name: "SecurityCipher Daily Bug Bounty Writeups",
    kind: "writeup",
    seedUrls: ["https://securitycipher.com/bounty-writeups/"],
    hosts: ["securitycipher.com"],
    trust: 85,
    includeTerms: [
      "bug bounty",
      "writeup",
      "vulnerability",
      "idor",
      "xss",
      "ssrf",
      "sqli",
      "authorization",
      "access control",
      "cors",
      "cross-origin resource sharing",
      "information disclosure",
      "information-disclosure",
      "privilege escalation",
      "privilege-escalation",
      "security misconfiguration",
      "security-misconfiguration",
      "account takeover",
      "account-takeover",
      "mass assignment",
      "mass-assignment",
      "nosql injection",
      "nosqli",
      "host header injection",
      "host-header-injection",
      "mfa bypass",
      "mfa-bypass",
      "rate limit bypass",
      "rate-limit-bypass",
      "websocket",
      "saml",
      "race condition",
      "api security",
      "recon",
    ],
    includePaths: ["/bounty-writeups/"],
    excludePaths: ["/wp-admin/", "/wp-login.php"],
  },
  {
    id: "hackerone-blog",
    name: "HackerOne Blog",
    kind: "blog",
    seedUrls: ["https://www.hackerone.com/blog"],
    hosts: ["hackerone.com"],
    trust: 90,
  },
  {
    id: "bugcrowd-blog",
    name: "Bugcrowd Blog",
    kind: "blog",
    seedUrls: ["https://www.bugcrowd.com/blog/"],
    hosts: ["bugcrowd.com"],
    trust: 90,
  },
  {
    id: "nahamsec",
    name: "NahamSec Blog",
    kind: "writeup",
    seedUrls: ["https://nahamsec.com/"],
    hosts: ["nahamsec.com"],
    trust: 90,
  },
  {
    id: "assetnote",
    name: "Assetnote",
    kind: "research",
    seedUrls: ["https://blog.assetnote.io/"],
    hosts: ["blog.assetnote.io", "assetnote.io"],
    trust: 95,
  },
  {
    id: "projectdiscovery",
    name: "ProjectDiscovery Blog",
    kind: "research",
    seedUrls: ["https://projectdiscovery.io/blog"],
    hosts: ["projectdiscovery.io"],
    trust: 95,
  },
  {
    id: "trickster0",
    name: "Trickster0",
    kind: "writeup",
    seedUrls: ["https://trickster0.medium.com/"],
    hosts: ["medium.com"],
    // Medium is noisy and the host contains unrelated authors' content. Require
    // real security/writeup language instead of accepting generic articles.
    includeTerms: [
      "bug bounty",
      "responsible disclosure",
      "security vulnerability",
      "security research",
      "vulnerability disclosure",
      "proof of concept",
      "access control",
      "cors",
      "cross-origin resource sharing",
      "privilege escalation",
      "privilege-escalation",
      "account takeover",
      "account-takeover",
      "mass assignment",
      "mass-assignment",
      "nosql injection",
      "nosqli",
      "host header injection",
      "host-header-injection",
      "mfa bypass",
      "mfa-bypass",
      "rate limit bypass",
      "rate-limit-bypass",
      "websocket",
      "saml",
      "information disclosure",
      "information-disclosure",
      "security misconfiguration",
      "security-misconfiguration",
      "path traversal",
      "request smuggling",
      "prototype pollution",
      "subdomain takeover",
      "race condition",
      "idor",
      "xss",
      "ssrf",
      "csrf",
      "sqli",
      "xxe",
      "rce",
      "cve",
    ],
    excludeTerms: ["job alert", "career advice", "general news", "personal update"],
    trust: 90,
  },
  {
    id: "edoverflow",
    name: "EdOverflow",
    kind: "writeup",
    seedUrls: ["https://edoverflow.com/"],
    hosts: ["edoverflow.com"],
    trust: 95,
  },
  {
    id: "devcore",
    name: "DEVCORE / Orange Tsai",
    kind: "research",
    seedUrls: ["https://devco.re/en/"],
    hosts: ["devco.re"],
    trust: 100,
  },
  {
    id: "liveoverflow",
    name: "LiveOverflow",
    kind: "writeup",
    seedUrls: ["https://liveoverflow.com/"],
    hosts: ["liveoverflow.com"],
    trust: 90,
  },
  {
    id: "hacktricks",
    name: "HackTricks",
    kind: "reference",
    seedUrls: ["https://book.hacktricks.xyz/"],
    hosts: ["book.hacktricks.xyz", "hacktricks.xyz"],
    trust: 90,
  },
  {
    id: "payloadsallthethings",
    name: "PayloadsAllTheThings",
    kind: "reference",
    seedUrls: ["https://github.com/swisskyrepo/PayloadsAllTheThings"],
    hosts: ["github.com"],
    trust: 90,
  },
  {
    id: "github",
    name: "GitHub security writeups",
    kind: "writeup",
    seedUrls: [
      "https://github.com/search?q=bug+bounty+writeup&type=repositories",
      "https://github.com/search?q=bug+bounty+writeup&type=code",
    ],
    hosts: ["github.com"],
    trust: 80,
  },
  {
    id: "src-hunter-skill",
    name: "MyuriKanao src-hunter-skill",
    kind: "reference",
    seedUrls: [
      "https://github.com/MyuriKanao/src-hunter-skill/tree/main/references/h1-reports/raw/reports",
      "https://github.com/MyuriKanao/src-hunter-skill",
      "https://github.com/MyuriKanao/src-hunter-skill/blob/main/SKILL.md",
      "https://github.com/MyuriKanao/src-hunter-skill/blob/main/README.en.md",
    ],
    hosts: ["github.com"],
    trust: 90,
  },
  {
    id: "owasp-cheat-sheets",
    name: "OWASP Cheat Sheet Series",
    kind: "reference",
    seedUrls: ["https://cheatsheetseries.owasp.org/"],
    hosts: ["cheatsheetseries.owasp.org"],
    includePaths: ["/cheatsheets/"],
    trust: 100,
  },
  {
    id: "trailofbits",
    name: "Trail of Bits Security Research",
    kind: "research",
    seedUrls: ["https://blog.trailofbits.com/"],
    hosts: ["blog.trailofbits.com"],
    // The blog uses year-first article URLs, e.g. /2026/06/22/article-slug/.
    includePaths: ["/20"],
    trust: 100,
  },
  {
    id: "zdi",
    name: "Zero Day Initiative Research Blog",
    kind: "research",
    seedUrls: ["https://www.zerodayinitiative.com/blog/"],
    hosts: ["zerodayinitiative.com"],
    includePaths: ["/blog/"],
    trust: 95,
  },
  {
    id: "elastic-security-labs",
    name: "Elastic Security Labs",
    kind: "research",
    seedUrls: ["https://www.elastic.co/security-labs/blog"],
    hosts: ["elastic.co"],
    includePaths: ["/security-labs/"],
    trust: 95,
  },
]

/**
 * Resolve a legacy public-research URL to its configured source without guessing
 * when multiple source feeds share a host. Explicit metadata wins only when its
 * source allowlist matches the URL; otherwise path-specific seed prefixes may
 * disambiguate shared hosts such as HackerOne and GitHub.
 */
export function resolveResearchSourceForURL(value: string, preferredID?: string) {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return undefined
  }
  if (url.protocol !== "https:" || (url.port && url.port !== "443") || url.username || url.password) return undefined
  const matchesHost = (source: ResearchSource) =>
    source.hosts.some((host) => url.hostname === host || url.hostname.endsWith("." + host))
  const hostCandidates = RESEARCH_SOURCES.filter(matchesHost)
  const pathname = url.pathname.toLowerCase()
  const pathScore = (source: ResearchSource) => {
    let score = 0
    for (const seed of source.seedUrls) {
      try {
        const seedURL = new URL(seed)
        const seedHost = seedURL.hostname.toLowerCase()
        const seedHostAllowed = source.hosts.some((host) =>
          seedHost === host || seedHost.endsWith("." + host),
        )
        if (!seedHostAllowed || seedURL.pathname === "/") continue
        const prefix = seedURL.pathname.toLowerCase().replace(/\/+$/, "")
        if (pathname === prefix || pathname.startsWith(prefix + "/")) {
          score = Math.max(score, prefix.length)
        }
      } catch {
        // Invalid configured seeds do not participate in provenance inference.
      }
    }
    return score
  }

  if (preferredID) {
    const preferred = hostCandidates.find((source) => source.id === preferredID)
    if (preferred) {
      // A unique host mapping is enough. On shared providers, explicit provenance
      // must also match that source's configured path family or it is contradictory.
      if (hostCandidates.length === 1 || pathScore(preferred) > 0) return preferred
      return undefined
    }
    // A known configured source that rejects this host is contradictory provenance.
    // Unknown legacy aliases (for example "hackerone" or "default") have no trust
    // policy of their own, so allow only an unambiguous host-and-seed-path inference.
    if (RESEARCH_SOURCES.some((source) => source.id === preferredID)) return undefined
  }

  if (hostCandidates.length === 1) return hostCandidates[0]

  const scored = hostCandidates.map((source) => ({ source, score: pathScore(source) }))
  const highest = Math.max(0, ...scored.map((item) => item.score))
  if (!highest) return undefined
  const winners = scored.filter((item) => item.score === highest).map((item) => item.source)
  return winners.length === 1 ? winners[0] : undefined
}

export function getResearchSource(id: string) {
  return RESEARCH_SOURCES.find((source) => source.id === id)
}

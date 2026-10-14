import { createHash } from "node:crypto"
import { ReportKnowledge } from "../learning/report-knowledge"
import { RESEARCH_LEARNING_VERSION, RESEARCH_SOURCES, type ResearchSource, type ResearchSourceKind } from "./sources"
import { discoverySeeds, isDiscoveryPaginationURL, nextDiscoveryPage, sourceDocumentPriority } from "./adapters"
import { fetchResearchText as fetchText, researchSourceHasCredentials } from "./safe-fetch"

const MAX_CANDIDATE_SCORE = 100
const MAX_CACHED_RESEARCH_TEXT = 100_000
const AUTH_RETRY_COOLDOWN_MS = 10 * 60_000
const DEFAULT_LIMIT = 50
const MAX_LIMIT = 500

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number) {
  const candidate = value === undefined || !Number.isFinite(value) ? fallback : value
  return Math.max(minimum, Math.min(Math.floor(candidate), maximum))
}

function paginationSeriesKey(source: ResearchSource, value: string) {
  const url = new URL(value)
  if (source.id === "hackerone-hacktivity" && url.pathname.includes("/overview")) {
    url.searchParams.delete("pageIndex")
  } else if (["hackerone-hacktivity", "bugcrowd-crowdstream", "github"].includes(source.id)) {
    url.searchParams.delete("page")
  } else {
    url.pathname = url.pathname.replace(/\/page\/\d+\/?$/i, "")
  }
  return url.toString()
}

function hostAllowed(url: URL, source: ResearchSource) {
  return source.hosts.some((host) => url.hostname === host || url.hostname.endsWith("." + host))
}

function normalizeUrl(value: string, base?: URL) {
  try {
    const url = new URL(value, base)
    // Never persist or request URLs carrying embedded credentials. Query-based
    // secrets are stripped before URLs enter the queue, logs, or knowledge records;
    // authenticated research should use the source-scoped environment session.
    if (url.username || url.password) return undefined
    url.hash = ""
    for (const key of [...url.searchParams.keys()]) {
      const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, "")
      const trackingParameter = /^(?:utmsource|utmmedium|utmcampaign|utmterm|utmcontent|ref)$/.test(normalizedKey)
      // Signed cloud URLs and provider-specific credentials use many key names
      // (for example X-Amz-Signature and AWS_SECRET_ACCESS_KEY). Match sensitive
      // concepts rather than a short exact-name list before persisting source URLs.
      const sensitiveParameter =
        /(?:token|secret|password|passwd|privatekey|signature|credential|apikey|authorization)/.test(normalizedKey) ||
        /^(?:auth|sid|session|sessionid|sig)$/.test(normalizedKey)
      if (trackingParameter || sensitiveParameter) url.searchParams.delete(key)
    }
    return url.toString()
  } catch {
    return undefined
  }
}

export function normalizeResearchUrl(value: string, base?: URL) {
  return normalizeUrl(value, base)
}

/**
 * Redact credential-like values before any source text or extracted PoC is persisted.
 * Public writeups are untrusted and can accidentally contain live tokens or secrets.
 */
export function redactResearchSecrets(input: string): string {
  return input
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/gi, "[PRIVATE KEY REDACTED]")
    .replace(/(authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+[^\s"'<>]+/gi, "$1: [REDACTED]")
    .replace(/(cookie|set-cookie)\s*:\s*[^\s"'<>]+/gi, "$1: [REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer [REDACTED]")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b/g, "[API KEY REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT REDACTED]")
    .replace(/((?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|csrf[_-]?token|session[_-]?id|sessionid|private[_-]?key|secret[_-]?key|password|passwd|token|secret|sid)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s"'&,;<>]+)/gi, "$1[REDACTED]")
    .replace(/([?&][A-Za-z0-9_.%-]*(?:token|secret|password|passwd|private[_-]?key|signature|credential|api[_-]?key|authorization|csrf|session|auth|sig)[A-Za-z0-9_.%-]*=)[^&#\s"'<>]+/gi, "$1[REDACTED]")
}

function cleanHtml(html: string) {
  const main =
    html.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i)?.[1] ??
    html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1] ??
    html
  return main
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<svg[\s\S]*?<\/svg>/gi, " ")
    .replace(/<nav\b[^>]*>[\s\S]*?<\/nav>/gi, " ")
    .replace(/<footer\b[^>]*>[\s\S]*?<\/footer>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#39;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/\s+/g, " ")
    .trim()
}

function titleOf(html: string, fallback: string) {
  return (
    html
      .match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]
      ?.replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim() || fallback
  )
}

/**
 * Fetch one queued public research URL through the same source-scoped SSRF-safe
 * fetcher used by discovery, returning only sanitized plain text.
 */
export async function fetchResearchSourceForStudy(sourceID: string, sourceURL: string) {
  const source = RESEARCH_SOURCES.find((entry) => entry.id === sourceID)
  if (!source) throw new Error("unknown research source id")
  const normalized = normalizeUrl(sourceURL)
  if (!normalized) throw new Error("research source URL failed normalization")
  const parsed = new URL(normalized)
  if (parsed.protocol !== "https:" || !hostAllowed(parsed, source)) {
    throw new Error("research URL is outside the configured HTTPS source hosts")
  }
  const html = await fetchText(normalized, source)
  const title = redactResearchSecrets(titleOf(html, normalized))
  const text = redactResearchSecrets(cleanHtml(html))
  if (looksLikeResearchAuthenticationWall(normalized, title, text, html)) {
    throw new Error("authentication required: source returned a login wall")
  }
  return {
    title,
    text,
    contentFingerprint: createHash("sha256").update(text).digest("hex").slice(0, 40),
    contentLength: text.length,
  }
}

function linksOf(html: string, base: URL, source: ResearchSource) {
  const links = new Set<string>()
  for (const match of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    const value = normalizeUrl(match[1], base)
    if (!value) continue
    try {
      const url = new URL(value)
      if (url.protocol !== "https:" || !hostAllowed(url, source)) continue
      if (/\.(png|jpe?g|gif|svg|webp|css|js|zip|pdf|woff2?|mp4|mp3)$/i.test(url.pathname)) continue
      links.add(value)
    } catch {}
  }

  // RSS 2.0 uses <link>https://... </link> rather than an HTML href attribute.
  // Accept feed item links, but never treat the feed's own self-link as a candidate.
  for (const match of html.matchAll(/<link(?:\s[^>]*)?>\s*(https?:\/\/[^<\s]+)\s*<\/link>/gi)) {
    const value = normalizeUrl(match[1], base)
    if (!value) continue
    try {
      const url = new URL(value)
      if (url.protocol !== "https:" || !hostAllowed(url, source)) continue
      if (url.href === base.href) continue
      if (/\.(png|jpe?g|gif|svg|webp|css|js|zip|pdf|woff2?|mp4|mp3)$/i.test(url.pathname)) continue
      links.add(value)
    } catch {}
  }
  return [...links]
}

function matchesTerm(text: string, term: string) {
  const escaped = term.trim().replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")
  if (!escaped) return false
  return new RegExp("(^|[^\\p{L}\\p{N}_])" + escaped + "([^\\p{L}\\p{N}_]|$)", "iu").test(text)
}

export function sourceRelevance(url: string, title: string, text: string, source: ResearchSource) {
  const haystack = (title + " " + text).toLowerCase()
  const path = new URL(url).pathname.toLowerCase()
  const excludedPath = source.excludePaths?.some((value) => path.includes(value.toLowerCase()))
  if (excludedPath) return { accepted: false, score: -100, excluded: true }

  const excluded = source.excludeTerms?.filter((term) => matchesTerm(haystack, term)).length ?? 0
  const included = source.includeTerms?.filter((term) => matchesTerm(haystack, term)).length ?? 0
  const pathBoost = source.includePaths?.some((value) => path.includes(value.toLowerCase())) ? 25 : 0

  // Sources without include terms keep generic relevance, but explicit exclusions
  // remain policy: never let this early return bypass an exclusion-only source config.
  if (!source.includeTerms?.length) {
    return { accepted: excluded === 0, score: pathBoost - excluded * 20, excluded: excluded > 0 }
  }

  // For noisy sources such as Medium, require real security relevance.
  // A title/path hit alone is not enough unless it is a highly specific vuln term.
  const specificVulnerability =
    /\b(idor|xss|ssrf|csrf|sqli|no[- ]?sql injection|nosqli|ssti|xxe|cve|cors|mass[- ]assignment|host[- ]header[- ]injection|host header poisoning|mfa[- ]bypass|rate[- ]limit[- ]bypass|websocket|saml|account[- ]takeover|information[- ]disclosure|privilege[- ]escalation|security[- ]misconfiguration|prototype pollution|request smuggling|race condition|subdomain takeover|path traversal)\b/i.test(
      title + " " + path,
    )
  const accepted = specificVulnerability || included >= 2 || (included >= 1 && pathBoost > 0)
  return { accepted: accepted && excluded === 0, score: included * 12 + pathBoost - excluded * 20, excluded: excluded > 0 }
}

export function isIndexLikeResearchUrl(url: string) {
  try {
    const parsed = new URL(url)
    const path = parsed.pathname.toLowerCase().replace(/\/+$/, "") || "/"
    // Root landing pages are discovery seeds, not automatically learnable articles.
    if (path === "/") return true
    if (/[?&](page|p|offset|start|pageindex)=\d+/i.test(parsed.search)) return true
    if (/\/page\/\d+\/?$/i.test(path)) return true
    if (/\/(all-labs|all-topics|all-courses|all-resources|latest|popular)(\/)?$/.test(path)) return true
    if (/\/(category|categories|topic|topics|tag|tags|archives?|search|help|docs|documentation)(\/|$)/i.test(path))
      return true
    if (/\/(blog|research|hacktivity|writeups?|articles?|news|resources)(\/)?$/.test(path)) return true
    return false
  } catch {
    return true
  }
}

export function isResearchCandidate(url: string, source: ResearchSource) {
  const parsed = new URL(url)
  const path = parsed.pathname.toLowerCase()
  // This curated Medium source is one researcher, not permission to ingest the whole platform.
  if (source.id === "trickster0") {
    const host = parsed.hostname.toLowerCase()
    if (host === "trickster0.medium.com") return path !== "/"
    return host === "medium.com" && /^\/@trickster0(?:\/|$)/i.test(path)
  }
  // These editorial sites publish individual posts at varied URL shapes (slugs or dates),
  // so their article links cannot be identified reliably by generic path keywords alone.
  if (source.id === "infosec-weekly" || source.id === "securitycipher-bounty-writeups") {
    if (path === "/" || path === "/bounty-writeups") return false
    if (
      /\/(about|contact|privacy|terms|login|register|subscribe|membership|wp-admin|wp-login\.php)(\/|$)/i.test(path)
    ) {
      return false
    }
    return true
  }
  if (
    /\/reports?\b|\/hacktivity\b|\/writeups?\b|\/research\b|\/blog\b|\/articles?\b|\/labs?\b|\/disclos|\/advisories?\b|\/learn\b|\/academy\b|\/techniques?\b|\/payloads?\b|\/cheats?heets?\b|\/blob\/|\/tree\//.test(
      path,
    )
  )
    return true
  return /[?&](page|p|offset|start|pageindex)=\d+/i.test(parsed.search)
}

export function classifyResearchTopic(title: string, text: string) {
  const classes: Array<[string, RegExp]> = [
    ["idor", /\bidor\b|insecure direct object|object[- ]level authorization|object[- ]identifier|resource identifier|another user(?:'s)? (?:data|object|account)/],
    ["object-identifier", /object identifier|resource identifier|object id|user id|account id|order id/],
    ["xss", /cross[- ]site scripting|\bxss\b/],
    ["ssrf", /server[- ]side request forgery|\bssrf\b/],
    ["csrf", /cross[- ]site request forgery|\bcsrf\b/],
    ["sqli", /sql injection|\bsqli\b/],
    ["nosqli", /no[- ]?sql injection|\bnosqli\b|mongodb injection/],
    ["mass-assignment", /mass[- ]assignment|over[- ]posting|overposting/],
    ["xxe", /xml external entity|\bxxe\b/],
    ["ssti", /server[- ]side template injection|\bssti\b/],
    ["race-condition", /race condition|time[- ]of[- ]check/],
    ["open-redirect", /open redirect/],
    ["auth-bypass", /authentication bypass|auth bypass/],
    ["mfa-bypass", /mfa[- ]bypass|multi[- ]factor authentication bypass|two[- ]factor authentication bypass|\b2fa[- ]bypass\b/],
    ["host-header-injection", /host[- ]header[- ]injection|host[- ]header[- ]poisoning|password reset poisoning/],
    ["access-control", /access control|authorization bypass|broken access control/],
    ["privilege-escalation", /privilege[- ]escalation|vertical privilege[- ]escalation|horizontal privilege[- ]escalation/],
    ["account-takeover", /account[- ]takeover|account compromise|\bato\b/],
    ["information-disclosure", /information[- ]disclosure|sensitive information exposure|sensitive data exposure|data leakage|exposed sensitive data/],
    ["security-misconfiguration", /security[- ]misconfiguration|misconfiguration|insecure configuration/],
    ["cors", /\bcors\b|cross-origin resource sharing|access-control-allow-origin|cross-origin policy/],
    ["business-logic", /business logic/],
    ["prototype-pollution", /prototype pollution/],
    ["deserialization", /insecure deserialization|deserialization/],
    ["request-smuggling", /request smuggling/],
    ["rate-limit-bypass", /rate[- ]limit[- ]bypass|rate[- ]limit(?:ing)? bypass|bypass rate limits?/],
    ["websocket", /\bwebsockets?\b|web socket/],
    ["saml", /\bsaml\b|security assertion markup language/],
    ["cache-poisoning", /cache poisoning/],
    ["file-upload", /file upload/],
    ["graphql", /graphql/],
    ["jwt", /\bjwt\b|json web token/],
    ["command-injection", /command injection|os command injection/],
    ["path-traversal", /path traversal|directory traversal/],
    ["subdomain-takeover", /subdomain takeover/],
    ["oauth", /oauth|open authorization/],
    ["web-cache", /web cache|cache deception/],
  ]
  const normalizedTitle = title.toLowerCase()
  // When a title names more than one security concept, use the first explicitly
  // named topic instead of whichever regex happens to appear first in this array.
  const titleMatches = classes
    .map(([name, pattern]) => ({ name, index: normalizedTitle.search(pattern) }))
    .filter((match) => match.index >= 0)
    .sort((left, right) => left.index - right.index)
  if (titleMatches.length) return titleMatches[0].name

  const body = text.toLowerCase()
  const ranked = classes
    .map(([name, pattern]) => ({
      name,
      count: (body.match(new RegExp(pattern.source, "g")) ?? []).length,
    }))
    .filter((item) => item.count > 0)
    .sort((a, b) => b.count - a.count)
  if (ranked.length === 1) return ranked[0].name
  // If the body discusses several vulnerability classes, do not label the whole
  // article using whichever class happened to appear first in a hard-coded list.
  if (ranked.length > 1 && ranked[0].count >= 2 && ranked[0].count > ranked[1].count) return ranked[0].name
  return undefined
}
/**
 * Classify the document's actual purpose separately from the configured host/feed.
 * This is deliberately conservative: source kind is a fallback, not proof that a
 * page is a report or a confirmed vulnerability.
 */
export function classifyResearchDocumentType(
  title: string,
  text: string,
  configuredKind: ResearchSourceKind,
): "report" | "writeup" | "blog" | "academy" | "reference" | "research" | "mixed" | "uncertain" {
  const sample = (title + "\\n" + text.slice(0, 12000)).toLowerCase()
  const reportSignals = [
    /\\b(?:disclosed|disclosure|vulnerability report|bug bounty report|security report)\\b/,
    /\\b(?:hackerone|bugcrowd|intigriti|yeswehack)\\b.{0,100}\\b(?:report|submission|disclosed)\\b/,
    /\\b(?:cve-\\d{4}-\\d+)\\b/,
  ].filter((pattern) => pattern.test(sample)).length
  const writeupSignals = [
    /\\b(?:write[- ]?up|writeup|bug bounty journey|my first bug bounty|how i found|how we found)\\b/,
    /\\b(?:i noticed|i discovered|i tested|my approach|the initial hypothesis|what i tried)\\b/,
    /\\b(?:step[- ]by[- ]step|reproduction steps|proof of concept|root cause analysis)\\b/,
  ].filter((pattern) => pattern.test(sample)).length
  const blogSignals = [
    /\\b(?:blog post|in this article|this article explains|guide to|introduction to|best practices)\\b/,
    /\\b(?:why it matters|how it works|overview|explained|lessons learned)\\b/,
  ].filter((pattern) => pattern.test(sample)).length
  const academySignals = /\\b(?:web security academy|lab solution|lab walkthrough|learning objective|practice lab)\\b/.test(sample)
  const referenceSignals = /\\b(?:documentation|reference guide|cheat sheet|payloads all the things|hacktricks)\\b/.test(sample)
  const researchSignals = /\\b(?:technical research|root cause|novel technique|security research|research paper|technical analysis)\\b/.test(sample)

  const scores = [
    ["report", reportSignals] as const,
    ["writeup", writeupSignals] as const,
    ["blog", blogSignals] as const,
    ["research", researchSignals ? 2 : 0] as const,
    ["reference", referenceSignals ? 2 : 0] as const,
    ["academy", academySignals ? 3 : 0] as const,
  ].sort((a, b) => b[1] - a[1])
  const positive = scores.filter((item) => item[1] > 0)
  if (positive.length >= 2 && positive[0][1] > 0 && positive[1][1] > 0 && positive[0][1] === positive[1][1]) {
    return "mixed"
  }
  if (positive.length && positive[0][1] > 0) {
    // A strong explicit lab/documentation signal should not be overwritten by
    // generic report/write-up wording in navigation or related links.
    return positive[0][0]
  }
  if (configuredKind === "academy" || configuredKind === "reference" || configuredKind === "research" || configuredKind === "blog" || configuredKind === "writeup") {
    return configuredKind
  }
  if (configuredKind === "disclosure") return reportSignals ? "report" : "uncertain"
  return "uncertain"
}

function severityOf(text: string) {
  // Avoid turning incidental words ("high-level", "low-level", "medium-sized")
  // into severity labels. Prefer explicit source labels, then a stated CVSS score.
  const labelled = text.match(
    /\b(?:severity|risk(?:\s+level)?|priority)\b\s*(?:(?:is|of|rating)\s*)?[:=-]?\s*(critical|high|medium|low|informational|info)\b/i,
  )
  if (labelled) return labelled[1].toLowerCase() === "info" ? "informational" : labelled[1].toLowerCase()

  const cvss = text.match(/\bCVSS(?:\s+v?[0-9]+(?:\.[0-9]+)?)?(?:\s+score)?\s*[:=]\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b/i)
  if (cvss) {
    const score = Number(cvss[1])
    if (score >= 9) return "critical"
    if (score >= 7) return "high"
    if (score >= 4) return "medium"
    if (score > 0) return "low"
  }
  return "unknown"
}

function cweOf(text: string): string | undefined {
  const match = text.match(/\bCWE\s*[-:#]?\s*(\d{1,5})\b/i)
  return match ? "CWE-" + match[1] : undefined
}

function firstMatchingSentence(text: string, pattern: RegExp) {
  return text
    .split(/(?<=[.!?])\s+/)
    .map((line) => line.trim())
    .find((line) => pattern.test(line) && line.length >= 45)
}

function impactOf(text: string) {
  return firstMatchingSentence(
    text,
    /impact|allows|expos|access|takeover|privilege|execute|delete|modify|read/i,
  )?.slice(0, 1000)
}

function attackVectorOf(text: string) {
  return firstMatchingSentence(text, /endpoint|request|parameter|header|cookie|payload|token|url|api|upload/i)?.slice(
    0,
    1000,
  )
}

function lessonOf(text: string, vulnerabilityClass?: string) {
  const sentences = text
    .split(/(?<=[.!?])\s+/)
    .map((line) => line.trim())
    .filter((line) => line.length >= 45)
  const useful = sentences.filter((line) =>
    /because|caused by|allows|leads to|impact|bypass|authorization|validation|exploit|root cause|misconfigur/i.test(
      line,
    ),
  )
  const selected = useful.slice(0, 3)
  if (selected.length) return selected.join(" ").slice(0, 1600)
  return vulnerabilityClass
    ? "Research pattern for " +
        vulnerabilityClass +
        ": validate prerequisites, exploitability, and impact independently."
    : undefined
}

function matchingSentences(text: string, pattern: RegExp, max = 8, maxLength = 2400) {
  const seen = new Set<string>()
  const selected: string[] = []
  for (const raw of text.split(/(?<=[.!?])\s+|(?<=\n)/)) {
    const sentence = raw.replace(/\s+/g, " ").trim()
    const key = sentence.toLowerCase()
    if (sentence.length < 30 || !pattern.test(sentence) || seen.has(key)) continue
    seen.add(key)
    selected.push(sentence.slice(0, 420))
    if (selected.length >= max) break
  }
  return selected.join("\n").slice(0, maxLength) || undefined
}

function extractResearchSignals(text: string, vulnerabilityClass?: string) {
  const lower = text.toLowerCase()
  const signals = new Set<string>()
  if (vulnerabilityClass) signals.add(vulnerabilityClass)
  const cwe = text.match(/\bCWE\s*[-:#]?\s*(\d{1,5})\b/i)
  if (cwe) signals.add("CWE-" + cwe[1])
  const patterns: Array<[string, RegExp]> = [
    ["idor", /\bidor\b|insecure direct object|object[- ]level authorization|object[- ]identifier|resource identifier|another user(?:'s)? (?:data|object|account)/],
    ["object-identifier", /object identifier|resource identifier|object id|user id|account id|order id/],
    ["authorization-boundary", /authorization|access control|privilege escalation|another user|other account/],
    ["privilege-escalation", /privilege[- ]escalation|vertical privilege[- ]escalation|horizontal privilege[- ]escalation/],
    ["account-takeover", /account[- ]takeover|account compromise|\bato\b/],
    ["information-disclosure", /information[- ]disclosure|sensitive information exposure|sensitive data exposure|data leakage|exposed sensitive data/],
    ["security-misconfiguration", /security[- ]misconfiguration|misconfiguration|insecure configuration/],
    ["cors-policy", /\bcors\b|cross-origin resource sharing|access-control-allow-origin|cross-origin policy/],
    ["mass-assignment", /mass[- ]assignment|over[- ]posting|overposting/],
    ["nosqli", /no[- ]?sql injection|\bnosqli\b|mongodb injection/],
    ["host-header-injection", /host[- ]header[- ]injection|host[- ]header[- ]poisoning|password reset poisoning/],
    ["mfa-bypass", /mfa[- ]bypass|multi[- ]factor authentication bypass|two[- ]factor authentication bypass|\b2fa[- ]bypass\b/],
    ["rate-limit-bypass", /rate[- ]limit[- ]bypass|rate[- ]limit(?:ing)? bypass|bypass rate limits?/],
    ["websocket", /\bwebsockets?\b|web socket/],
    ["saml", /\bsaml\b|security assertion markup language/],
    ["authentication-flow", /authentication|login|session fixation|password reset|account recovery/],
    ["token-or-jwt", /\bjwt\b|bearer token|refresh token|access token|oauth/],
    ["javascript-client", /\.m?js\b|javascript|source map|client-side|frontend/],
    ["api-endpoint", /\bapi\b|endpoint|graphql|rest api/],
    ["file-upload", /file upload|multipart|content-type|filename/],
    ["cache-behavior", /cache-control|cache poisoning|cache deception|cdn/],
    ["race-condition", /race condition|concurrent|time-of-check|toctou/],
    ["server-side-request", /\bssrf\b|server-side request forgery|url fetch/],
    ["injection-sink", /sql injection|command injection|template injection|deserialization/],
    ["business-logic", /business logic|workflow|coupon|payment|quantity|state transition/],
    ["graphql", /\bgraphql\b|graphql endpoint|graphql mutation/],
    ["jwt", /\bjwt\b|json web token/],
    ["oauth", /\boauth\b|open authorization/],
    ["open-redirect", /open redirect|unvalidated redirect/],
    ["path-traversal", /path traversal|directory traversal|parent directory/],
    ["prototype-pollution", /prototype pollution|prototype chain pollution/],
    ["deserialization", /insecure deserialization|unsafe deserialization|deserialize untrusted/],
    ["request-smuggling", /request smuggling|http desynchronization|cl\.te|te\.cl/],
    ["subdomain-takeover", /subdomain takeover|dangling cname/],
    ["command-injection", /command injection|os command injection/],
    ["web-cache", /web cache|cache deception/],
  ]
  for (const [signal, pattern] of patterns) if (pattern.test(lower)) signals.add(signal)
  return [...signals].slice(0, 20)
}

export interface ExtractedResearchDetails {
  severity: string
  cweID?: string
  lesson?: string
  attackVector?: string
  impact?: string
  reproduction?: string
  poc?: string
  prerequisites?: string
  verificationSignals?: string
  falsePositiveCautions?: string
  rootCause?: string
  requestResponseEvidence?: string
  affectedComponents?: string
  affectedVersions?: string
  technologyStack?: string
  remediation?: string
  attackChain?: string
  negativeEvidence?: string
  limitations?: string
  retrievalSignals: string[]
}

export function extractResearchDetails(title: string, text: string, vulnerabilityClass?: string): ExtractedResearchDetails {
  const fullText = title + " " + text
  return {
    severity: severityOf(fullText),
    cweID: cweOf(fullText),
    lesson: lessonOf(text, vulnerabilityClass),
    attackVector: attackVectorOf(text),
    impact: impactOf(text),
    reproduction: matchingSentences(
      text,
      /reproduc|step\s+\d|first,|then,|send(?:ing)? (?:a |the )?request|modify the|change the|payload|parameter|proof[- ]of[- ]concept|\bpoc\b|exploit/i,
      8,
      2400,
    ),
    poc: pocSnippet(text),
    prerequisites: matchingSentences(
      text,
      /prerequisite|requires? (?:an? |the )?(?:account|role|permission|token|feature|condition)|must be (?:logged|authenticated|authorized)|only when|if (?:the|a|an) (?:user|account|role|request|parameter|feature)/i,
      5,
      1400,
    ),
    verificationSignals: matchingSentences(
      text,
      /verify|confirm|reproduc|expected response|response code|response body|compare (?:the )?(?:response|result)|evidence|impact was|demonstrat/i,
      6,
      1800,
    ),
    falsePositiveCautions: matchingSentences(
      text,
      /false positive|not exploitable|does not prove|not sufficient|expected behavior|by design|requires? (?:additional|manual) verification|out of scope|cannot reproduce|not reproducible/i,
      5,
      1400,
    ),
    rootCause: matchingSentences(
      text,
      /root cause|because|missing (?:an? )?(?:authorization|validation|check|control)|authorization.{0,40}missing|lack of|not enforced|trusts? (?:the )?user|fails? to (?:check|validate|verify|authorize)|improper(?:ly)?|insecure(?:ly)?|vulnerab(?:le|ility)/i,
      6,
      1800,
    ),
    requestResponseEvidence: matchingSentences(
      text,
      /(?:GET|POST|PUT|PATCH|DELETE)\s+\/|HTTP\/1\.[01]|request(?: body| header| parameter)?|response(?: body| header| code| status)?|status code|compare (?:the )?(?:response|result)|returned \d{3}|payload/i,
      8,
      2400,
    ),
    affectedComponents: matchingSentences(
      // Include title metadata too: the article may name "API" only in its title
      // while the body contains a lowercase URL path such as /api/objects/123.
      fullText,
      /endpoint|route|parameter|header|cookie|token|API|function|component|feature|source map|javascript|upload|workflow/i,
      5,
      1400,
    ),
    affectedVersions: matchingSentences(
      text,
      /affected versions?|vulnerable versions?|version(?:s)? (?:before|prior to|up to|through|between)|introduced in|fixed in|patched in|release \d|\bv?\d+\.\d+(?:\.\d+)?/i,
      6,
      1600,
    ),
    technologyStack: matchingSentences(
      text,
      /\b(?:react|next\.js|angular|vue(?:\.js)?|express|node\.js|django|flask|rails|laravel|spring|asp\.net|graphql|grpc|kubernetes|docker|nginx|apache|redis|mongodb|postgres(?:ql)?|mysql|oauth|openid|jwt)\b|framework|library|middleware|deployment|architecture/i,
      6,
      1600,
    ),
    remediation: matchingSentences(
      text,
      /remediat|mitigat|fix(?:ed|es)?|patch(?:ed)?|upgrade to|workaround|recommend(?:ation)?|should (?:validate|verify|authorize|restrict|disable|remove|enforce)|apply (?:the )?(?:patch|update)|least privilege/i,
      6,
      1800,
    ),
    attackChain: matchingSentences(
      text,
      /chain(?:ed|ing)?|pivot|combine(?:d|s)? with|leads? to|result(?:s|ed)? in|escalat(?:e|ion)|account[- ]takeover|privilege[- ]escalation|lateral movement|from .* to /i,
      6,
      1800,
    ),
    negativeEvidence: matchingSentences(
      text,
      /did not reproduce|could not reproduce|not exploitable|no impact|no sensitive data|expected behavior|not vulnerable|not affected|failed to demonstrate|does not allow/i,
      5,
      1400,
    ),
    limitations: matchingSentences(
      text,
      /only (?:works|applies|succeeds) when|requires? (?:a |an |the )?(?:specific|certain|authenticated|privileged|owner|non-owner)|depends on|environment|version|not tested|not confirmed|could not|limitation|assumption/i,
      6,
      1800,
    ),
    retrievalSignals: extractResearchSignals(fullText, vulnerabilityClass),
  }
}


function pocSnippet(text: string) {
  // The HTML cleaner intentionally flattens layout, so extract bounded command/request
  // fragments from inline text instead of relying on preserved code-block newlines.
  const patterns = [
    // Keep commands and request fragments as untrusted reference snippets; never execute them.
    /\bcurl\s+(?:-[a-zA-Z]+\s+)*https?:\/\/[^\s"'<>]{1,220}/gi,
    /\bhttp\s+(?:--[a-z0-9-]+(?:=[^\s]+)?\s+)*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+https?:\/\/[^\s"'<>]{1,220}/gi,
    /\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/[^\s"'<>]{1,180}(?:\s+HTTP\/1\.[01])?/gi,
    /\bfetch\s*\([^)]{0,260}\)/gi,
    /\baxios\.(?:get|post|put|patch|delete)\s*\([^)]{0,260}\)/gi,
    /\b(?:requests|httpx|urllib3)\.(?:get|post|put|patch|delete|request)\s*\([^)]{0,400}\)/gi,
  ]
  const candidates: string[] = []
  const seen = new Set<string>()
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const value = match[0].trim()
      if (!value || seen.has(value)) continue
      seen.add(value)
      candidates.push(value)
      if (candidates.length >= 12) break
    }
    if (candidates.length >= 12) break
  }
  return candidates.join("\n").slice(0, 1800) || undefined
}


export function candidateScore(url: string, source: ResearchSource) {
  const parsed = new URL(url)
  const path = parsed.pathname.toLowerCase()
  let score = 0
  if (
    /\/reports?\b|\/hacktivity\b|\/writeups?\b|\/research\b|\/blog\b|\/articles?\b|\/labs?\b|\/disclos|\/advisories?\b|\/learn\b|\/academy\b|\/techniques?\b|\/payloads?\b|\/cheats?heets?\b|\/blob\/|\/tree\//.test(
      path,
    )
  )
    score += 60
  if (/\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{4}\/\d{1,2}/.test(path)) score += 20
  if (/[?&](page|p|offset|start|pageindex)=\d+/i.test(parsed.search)) score += 30
  if (source.kind === "disclosure" && /\/reports?\b|\/hacktivity\//.test(path)) score += 20
  if (source.kind === "academy" && /lab|academy|web-security/.test(path)) score += 20
  if (source.kind === "reference" && /payload|cheat|technique|book|skill/.test(path)) score += 20
  score += sourceDocumentPriority(source, parsed.toString())
  return Math.min(MAX_CANDIDATE_SCORE, score)
}

async function discoverSitemap(source: ResearchSource) {
  const sitemapQueue = source.hosts.flatMap((host) =>
    ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/wp-sitemap.xml"]
      .map((path) => "https://" + host + path),
  )
  const visitedSitemaps = new Set<string>()
  const discoveredPages = new Set<string>()

  while (sitemapQueue.length) {
    const candidate = normalizeUrl(sitemapQueue.shift()!)
    if (!candidate || visitedSitemaps.has(candidate)) continue
    visitedSitemaps.add(candidate)

    let parsed: URL
    try {
      parsed = new URL(candidate)
      if (parsed.protocol !== "https:" || !hostAllowed(parsed, source)) continue
    } catch {
      continue
    }

    let xml: string
    try {
      xml = await fetchText(candidate, source)
    } catch {
      // Sitemap variants are optional. Continue trying every other configured
      // sitemap and rely on ordinary source links if a variant is unavailable.
      continue
    }

    const isSitemapIndex = /<sitemapindex\b/i.test(xml)
    const locations = [...xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)]
      .map((match) => normalizeUrl(match[1].replace(/&amp;/gi, "&"), parsed))
      .filter((value): value is string => !!value)

    for (const location of locations) {
      try {
        const url = new URL(location)
        if (url.protocol !== "https:" || !hostAllowed(url, source)) continue
        if (isSitemapIndex || /\.xml(?:\.gz)?$/i.test(url.pathname)) {
          if (!visitedSitemaps.has(url.toString())) sitemapQueue.push(url.toString())
        } else if (!/\.(png|jpe?g|gif|svg|webp|css|js|zip|woff2?|mp4|mp3)$/i.test(url.pathname)) {
          discoveredPages.add(url.toString())
        }
      } catch {}
    }
  }

  return [...discoveredPages]
}

export type ResearchIngestResult = {
  source: string
  fetched: number
  learned: number
  skipped: number
  failed: number
  blocked_auth: number
  pages_crawled: number
  candidates_discovered: number
  error_samples: string[]
}

export function looksLikeResearchAuthenticationWall(url: string, title: string, text: string, html = "") {
  const pathname = (() => { try { return new URL(url).pathname } catch { return "" } })()
  const heading = title.toLowerCase().trim()
  const body = text.slice(0, 6000).toLowerCase()
  if (/^\/(?:login|log-in|signin|sign-in|register|signup|sign-up|auth)(?:\/|$)/i.test(pathname)) return true
  if (/^(?:sign in|log in)(?: to (?:continue|view|read|access)(?:\b|$))?$|^(?:login|required|create an account|authentication required)$/i.test(heading)) return true
  if (/(?:sign in|log in) to (?:continue|view|read|access)|login required|authentication required|you must be logged in|create an account to (?:view|read|continue)|members only/i.test(body)) return true
  return text.trim().length < 1200 && /<form\b/i.test(html) && /(?:password|sign in|log in|login|email address)/i.test(html) && /(?:login|signin|sign-in|auth|session)/i.test(html)
}

/**
 * Resume authentication-blocked research only for sources with an operator-provided session.
 * Report URLs return to the learning queue; index/crawl pages return to discovery.
 * A cooldown prevents invalid sessions from being retried on every watch cycle.
 */
/**
 * Apply auth-blocked retries against one shared cap. Kept pure around the queue
 * operation so the global budget can be tested without sharing the process-wide DB.
 */
export function retryAuthBlockedWithBudget<S extends { id: string }>(
  sources: readonly S[],
  requestedLimit: number,
  hasCredentials: (source: S) => boolean,
  retry: (limit: number, sourceID: string, minAgeMs: number) => number,
  minAgeMs: number,
): number {
  let remaining = boundedInteger(requestedLimit, DEFAULT_LIMIT, 1, MAX_LIMIT)
  let total = 0
  for (const source of sources) {
    if (remaining <= 0) break
    if (!hasCredentials(source)) continue
    const retried = retry(remaining, source.id, minAgeMs)
    // Queue implementations must respect the passed limit. Clamp accounting as
    // a defensive guard against a faulty adapter reporting an invalid count.
    const used = Number.isFinite(retried) ? Math.max(0, Math.min(remaining, Math.floor(retried))) : 0
    total += used
    remaining -= used
  }
  return total
}

export async function retryAuthenticatedResearch(input: {
  sourceID?: string
  limit?: number
  /** Explicit operator action may bypass cooldown, but never the configured-session requirement. */
  retryImmediately?: boolean
} = {}) {
  const { ResearchQueue } = await import("./queue")
  const sources = input.sourceID ? RESEARCH_SOURCES.filter((source) => source.id === input.sourceID) : RESEARCH_SOURCES
  const limit = boundedInteger(input.limit, DEFAULT_LIMIT, 1, MAX_LIMIT)
  const minAgeMs = input.retryImmediately ? 0 : AUTH_RETRY_COOLDOWN_MS
  return retryAuthBlockedWithBudget(
    sources,
    limit,
    researchSourceHasCredentials,
    (remaining, sourceID, cooldown) => ResearchQueue.retryAuthenticationBlocked(remaining, sourceID, cooldown),
    minAgeMs,
  )
}
export type ResearchSyncOptions = {
  /** Number of reports per learning batch; total queue processing is unbounded. */
  limit?: number
  /** Initial page window; discovery expands it until exhaustion. */
  pages?: number
  /** Retained for compatibility; exhaustive discovery does not use a depth ceiling. */
  depth?: number
  /** Retained for compatibility; sync always drains all claimable work. */
  all?: boolean
}

export async function syncResearchSource(
  source: ResearchSource,
  options: ResearchSyncOptions = {},
): Promise<ResearchIngestResult> {
  const { ResearchQueue } = await import("./queue")
  const batchLimit = boundedInteger(options.limit, DEFAULT_LIMIT, 1, MAX_LIMIT)
  let pageWindow = Math.max(1, Math.floor(options.pages ?? 20))
  const discovery = { pages: 0, candidates: 0, added: 0, blocked_auth: 0, errors: [] as string[] }
  const learned = { learned: 0, skipped: 0, failed: 0, blocked_auth: 0, requeued_legacy: 0, errors: [] as string[] }

  // Page windows expand without a global ceiling. The source is complete only
  // when a pass leaves unused window capacity and the durable state has no blockers.
  while (true) {
    const pass = await discoverResearch({
      sourceID: source.id,
      pages: pageWindow,
      depth: Number.MAX_SAFE_INTEGER,
    })
    const current = pass[0]
    if (!current) break
    discovery.pages += current.pages
    discovery.candidates += current.candidates
    discovery.added += current.added
    discovery.blocked_auth += current.blocked_auth
    discovery.errors.push(...current.errors.slice(0, Math.max(0, 5 - discovery.errors.length)))

    // Drain all claimable rows after each pass. batchLimit limits one claim only,
    // never the total number of reports processed by this sync.
    while (true) {
      const batch = await learnResearchQueue({ limit: batchLimit, sourceID: source.id })
      learned.learned += batch.learned
      learned.skipped += batch.skipped
      learned.failed += batch.failed
      learned.blocked_auth += batch.blocked_auth
      learned.requeued_legacy += batch.requeued_legacy
      learned.errors.push(...batch.errors.slice(0, Math.max(0, 5 - learned.errors.length)))
      if (batch.claimed === 0) break
    }

    const queueStats = ResearchQueue.stats(source.id)
    const blocked =
      current.error_count > 0 ||
      current.blocked_auth > 0 ||
      queueStats.crawl_page_errors > 0 ||
      queueStats.crawl_page_auth_blocked > 0 ||
      queueStats.blocked_auth > 0 ||
      queueStats.retry > 0 ||
      queueStats.studying > 0
    if (blocked || current.pages < pageWindow) break

    const nextWindow = pageWindow * 2
    if (!Number.isSafeInteger(nextWindow) || nextWindow <= pageWindow) {
      discovery.errors.push("runtime integer range exhausted before pagination was proven complete")
      break
    }
    pageWindow = nextWindow
  }

  return {
    source: source.id,
    fetched: discovery.pages,
    learned: learned.learned,
    skipped: learned.skipped,
    failed: learned.failed,
    blocked_auth: discovery.blocked_auth + learned.blocked_auth,
    pages_crawled: discovery.pages,
    candidates_discovered: discovery.candidates,
    error_samples: [...discovery.errors, ...learned.errors].slice(0, 5),
  }
}

const RESEARCH_SOURCE_CONCURRENCY = 4

export async function syncResearch(input: { sourceID?: string } & ResearchSyncOptions = {}) {
  const sources = input.sourceID ? RESEARCH_SOURCES.filter((source) => source.id === input.sourceID) : RESEARCH_SOURCES
  if (sources.length === 0) throw new Error("unknown research source: " + input.sourceID)

  const results: ResearchIngestResult[] = []
  for (let i = 0; i < sources.length; i += RESEARCH_SOURCE_CONCURRENCY) {
    const batch = sources.slice(i, i + RESEARCH_SOURCE_CONCURRENCY)
    const batchResults = await Promise.all(
      batch.map((source) =>
        syncResearchSource(source, {
          limit: input.limit,
          pages: input.pages,
          depth: input.depth,
          all: input.all,
        }),
      ),
    )
    results.push(...batchResults)
  }
  return results
}

/** Discovery-only worker: persist candidate URLs without doing knowledge extraction. */
export async function discoverResearch(input: { sourceID?: string; pages?: number; depth?: number; agentLed?: boolean } = {}) {
  const { ResearchQueue } = await import("./queue")
  const sources = input.sourceID ? RESEARCH_SOURCES.filter((source) => source.id === input.sourceID) : RESEARCH_SOURCES
  if (!sources.length) throw new Error("unknown research source: " + input.sourceID)
  // Page and depth values are per-pass continuation windows only. The caller
  // expands page windows until exhaustion; no global page/depth ceiling applies.
  const maxPages = Math.max(1, Math.floor(Number.isFinite(input.pages) ? input.pages! : 100))
  const maxDepth = Math.max(0, Math.floor(Number.isFinite(input.depth) ? input.depth! : Number.MAX_SAFE_INTEGER))
  // Backfill-aware dedupe: older versions learned reports directly into ReportKnowledge
  // before the durable queue existed. Do not download those URLs again just because
  // they have no corresponding queue row.
  const knownKnowledgeURLs = new Set(
    ReportKnowledge.externalSourceURLs().flatMap((value) => {
      const normalized = normalizeUrl(value)
      return normalized ? [normalized] : []
    }),
  )
  const results: Array<{ source: string; pages: number; candidates: number; added: number; blocked_auth: number; error_count: number; errors: string[] }> = []

  for (const source of sources) {
    const queue: Array<{ url: string; depth: number }> = []
    const primarySeeds = new Set(source.seedUrls.map((url) => normalizeUrl(url)).filter((url): url is string => !!url))
    const queued = new Set<string>()
    const visited = new Set<string>()
    const errors: string[] = []
    const paginationFingerprints = new Map<string, string>()
    let pages = 0
    let candidates = 0
    let added = 0
    let blockedAuth = 0
    let errorCount = 0
    const add = (value: string, depth: number) => {
      const url = normalizeUrl(value)
      if (!url || url.length > 4096 || depth > maxDepth || queued.has(url) || visited.has(url)) return
      try {
        const parsed = new URL(url)
        if (parsed.protocol !== "https:" || !hostAllowed(parsed, source)) return
        if (depth > 0 && !isResearchCandidate(url, source) && !isDiscoveryPaginationURL(source, url)) return
      } catch {
        return
      }
      queued.add(url)
      queue.push({ url, depth })
    }

    for (const seed of discoverySeeds(source)) add(seed, 0)
    for (const url of await discoverSitemap(source)) add(url, 1)

    while (queue.length && pages < maxPages) {
      queue.sort((a, b) => candidateScore(b.url, source) - candidateScore(a.url, source) || a.depth - b.depth)
      const current = queue.shift()!
      if (visited.has(current.url)) continue
      visited.add(current.url)
      const existing = ResearchQueue.find(source.id, current.url)
      const isReportURL = isResearchCandidate(current.url, source) && !isIndexLikeResearchUrl(current.url)
      // Auth-blocked report and index URLs stay parked until the source session is ready
      // and the retry cooldown allows them. Otherwise every sync/watch cycle hammers login walls.
      if (existing?.status === "blocked_auth") continue
      // Never fetch a known report again, including legacy reports already in knowledge.
      // Refresh primary index pages every cycle; cache pagination/sitemap pages for six hours.
      if (isReportURL && (
        (existing && existing.payload?.crawl_page !== true) ||
        knownKnowledgeURLs.has(current.url)
      )) {
        // Count cached frontier nodes against this pass's work window too; otherwise
        // a second pass could mistake a mostly cached archive for a short archive.
        pages++
        // Even when a report's text is already cached/learned, reuse its saved
        // source-allowlisted outgoing links so larger future page passes can keep
        // walking the graph without refetching that report.
        const cachedLinks = existing?.payload?.discovered_links
        if (Array.isArray(cachedLinks)) {
          for (const link of cachedLinks) {
            if (typeof link === "string") add(link, current.depth + 1)
          }
        }
        continue
      }
      if (
        existing?.payload?.crawl_page === true &&
        ResearchQueue.isFreshCrawlPage(source.id, current.url) &&
        (existing.payload?.crawl_error === true || !primarySeeds.has(current.url))
      ) {
        // Count cached frontier nodes against this pass's work window too; the
        // window measures traversal progress, not only fresh network requests.
        pages++
        // Reuse the source-allowlisted link set from fresh crawl pages so
        // repeated discovery passes can continue traversing the graph without
        // repeatedly downloading the same index pages. Older cache rows without
        // this field are fetched once to backfill the frontier.
        if (existing.payload?.crawl_error === true) continue
        const cachedLinks = existing.payload?.discovered_links
        if (Array.isArray(cachedLinks)) {
          for (const link of cachedLinks) {
            if (typeof link === "string") add(link, current.depth + 1)
          }
          continue
        }
      }
      pages++
      try {
        const html = await fetchText(current.url, source)
        const title = redactResearchSecrets(titleOf(html, current.url))
        const text = redactResearchSecrets(cleanHtml(html))
        if (looksLikeResearchAuthenticationWall(current.url, title, text, html)) {
          // Persist both gated reports and gated index pages. This prevents repeat login-wall
          // fetches; retry-auth returns index pages to discovery, never to the learning queue.
          ResearchQueue.blockAuthentication({
            sourceID: source.id,
            sourceURL: current.url,
            title,
            reason: "authentication wall detected; configure a source-scoped session, then run research retry-auth",
            payload: {
              source_name: source.name,
              source_kind: source.kind,
              crawl_depth: current.depth,
              ...(isReportURL ? {} : { crawl_page: true }),
            },
          })
          blockedAuth++
          errorCount++
          if (errors.length < 5) errors.push(current.url + " — authentication required")
          continue
        }
        const discoveredLinks = linksOf(html, new URL(current.url), source)
        const contentFingerprint = createHash("sha256").update(text).digest("hex").slice(0, 40)
        const canContinuePagination = primarySeeds.has(current.url) || isDiscoveryPaginationURL(source, current.url) || isIndexLikeResearchUrl(current.url)
        const nextPage = canContinuePagination ? nextDiscoveryPage(source, current.url) : undefined
        const seriesKey = paginationSeriesKey(source, current.url)
        const previousFingerprint = paginationFingerprints.get(seriesKey)
        const repeatsPreviousPage = previousFingerprint === contentFingerprint
        paginationFingerprints.set(seriesKey, contentFingerprint)
        const hasRelevantChildren = discoveredLinks.some((link) => isResearchCandidate(link, source) && !isIndexLikeResearchUrl(link))
        if (nextPage && !repeatsPreviousPage && hasRelevantChildren) {
          discoveredLinks.push(nextPage)
        }
        for (const link of discoveredLinks) {
          candidates++
          add(link, current.depth + 1)
        }

        // Match the learner's minimum text length so short pages are rejected
        // during discovery instead of occupying a durable queue slot first.
        if (text.length >= 250 && (current.depth === 0 || isResearchCandidate(current.url, source))) {
          const relevance = sourceRelevance(current.url, title, text, source)
          const canQueue = relevance.accepted || (input.agentLed === true && !relevance.excluded)
          if (canQueue && !isIndexLikeResearchUrl(current.url)) {
            const row = ResearchQueue.enqueue({
              sourceID: source.id,
              sourceURL: current.url,
              title,
              payload: {
                source_name: source.name,
                source_kind: source.kind,
                source_trust: source.trust,
                crawl_depth: current.depth,
                candidate_score: candidateScore(current.url, source),
                source_relevance_precheck: { accepted: relevance.accepted, score: relevance.score, agent_review_requested: !relevance.accepted },
                // Discovery already fetched and sanitized this report. Cache a bounded excerpt
                // so the learner never makes a duplicate HTTP request for this URL. Preserve the
                // original length and full-content fingerprint for transparent truncation metadata.
                cached_text: text.slice(0, MAX_CACHED_RESEARCH_TEXT),
                cached_text_truncated: text.length > MAX_CACHED_RESEARCH_TEXT,
                content_length: text.length,
                content_fingerprint: createHash("sha256").update(text).digest("hex").slice(0, 40),
              },
            })
            if (row.created) added++
          }
        }
        ResearchQueue.markVisitedPage({
          sourceID: source.id,
          sourceURL: current.url,
          title,
          contentFingerprint,
          discoveredLinks,
        })
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        // A generated pagination URL returning a normal not-found response is the
        // archive's end marker, not a crawl failure. Persist that terminal page so
        // later passes do not repeatedly request it.
        if (isDiscoveryPaginationURL(source, current.url) && /\bHTTP\s+(?:400|404)\b/i.test(message)) {
          ResearchQueue.markVisitedPage({
            sourceID: source.id,
            sourceURL: current.url,
            title: "Pagination exhausted",
            discoveredLinks: [],
          })
          continue
        }
        errorCount++
        if (/\bHTTP\s+(?:401|403)\b|authentication required|login required|sign in required/i.test(message)) {
          ResearchQueue.blockAuthentication({
            sourceID: source.id,
            sourceURL: current.url,
            reason: message,
            payload: {
              source_name: source.name,
              source_kind: source.kind,
              crawl_depth: current.depth,
              ...(isReportURL ? {} : { crawl_page: true }),
            },
          })
          blockedAuth++
          if (errors.length < 5) errors.push(current.url + " — authentication required (" + message + ")")
        } else {
          // Persist transient/network failures so watch mode does not refetch the
          // same broken page every cycle. Failed records stay in discovery, not
          // the learning queue, and become eligible again after the crawl TTL.
          ResearchQueue.markFailedCrawlPage({
            sourceID: source.id,
            sourceURL: current.url,
            reason: message,
          })
          if (errors.length < 5) errors.push(current.url + " — " + message)
        }
      }
      if (current.depth >= maxDepth) continue
    }
    results.push({ source: source.id, pages, candidates, added, blocked_auth: blockedAuth, error_count: errorCount, errors })
  }
  return results
}

/** Learning-only worker: claim persisted candidates, extract a lesson, and record a terminal/retry state. */
export async function learnResearchQueue(input: { limit?: number; workerID?: string; sourceID?: string } = {}) {
  const { ResearchQueue } = await import("./queue")
  const workerID = input.workerID ?? "learn-" + process.pid + "-" + crypto.randomUUID()
  const limit = boundedInteger(input.limit, DEFAULT_LIMIT, 1, MAX_LIMIT)
  const legacyRequeued = ResearchQueue.requeueLegacyRejected(limit, input.sourceID)
  const result = {
    worker: workerID,
    claimed: 0,
    learned: 0,
    skipped: 0,
    failed: 0,
    blocked_auth: 0,
    requeued_legacy: legacyRequeued,
    errors: [] as string[],
  }

  // Reuse the same source-scoped retry path as CLI/update instead of retrying
  // 100 rows independently per source. This keeps auth recovery bounded globally
  // and preserves the cooldown/session-configuration gates in one place.
  await retryAuthenticatedResearch({ sourceID: input.sourceID, limit })

  for (let i = 0; i < limit; i++) {
    const item = ResearchQueue.claimNext(workerID, input.sourceID)
    if (!item) break
    result.claimed++
    const source = RESEARCH_SOURCES.find((entry) => entry.id === item.source_id)
    if (!source) {
      ResearchQueue.complete(item.sequence, item.lease_owner, "rejected", "unknown source id")
      result.skipped++
      continue
    }
    try {
      const cachedText = typeof item.payload.cached_text === "string" ? item.payload.cached_text : undefined
      let html = ""
      let title = redactResearchSecrets(item.title ?? item.source_url)
      let text: string
      if (cachedText) {
        text = cachedText
      } else {
        html = await fetchText(item.source_url, source)
        text = redactResearchSecrets(cleanHtml(html))
        title = redactResearchSecrets(titleOf(html, item.source_url))
      }
      if (looksLikeResearchAuthenticationWall(item.source_url, title, text, html)) {
        const blocked = ResearchQueue.blockAuthentication({
          sourceID: item.source_id,
          sourceURL: item.source_url,
          title,
          reason: "authentication wall detected; configure a source-scoped session, then run research retry-auth",
          payload: { source_name: source.name, source_kind: source.kind, crawl_depth: item.payload.crawl_depth },
          claim: { sequence: item.sequence, leaseOwner: item.lease_owner },
        })
        // The claim may have expired/reclaimed, or the queue may already hold a
        // terminal model-study result. Count the transition that actually occurred.
        if (blocked?.status === "blocked_auth") result.blocked_auth++
        else result.skipped++
        continue
      }
      if (text.length < 250) {
        ResearchQueue.complete(item.sequence, item.lease_owner, "rejected", "page content too short")
        result.skipped++
        continue
      }
      const relevance = sourceRelevance(item.source_url, title, text, source)
      if (!relevance.accepted || isIndexLikeResearchUrl(item.source_url)) {
        ResearchQueue.complete(item.sequence, item.lease_owner, "rejected", "page failed research relevance gate")
        result.skipped++
        continue
      }
      const documentType = classifyResearchDocumentType(title, text, source.kind)
      const vulnerabilityClass = classifyResearchTopic(title, text)
      // A recognizable vulnerability class is useful but is not mandatory for
      // a relevant blog, write-up, reference, academy lesson, or technical study.
      // Relevance is already checked above; preserve the actual document type.
      if (documentType === "uncertain" && !vulnerabilityClass) {
        ResearchQueue.complete(item.sequence, item.lease_owner, "rejected", "document type and security topic could not be established")
        result.skipped++
        continue
      }

      // Discovery hashes the full sanitized source text before caching a bounded
      // excerpt. Preserve that full-document fingerprint rather than replacing it
      // with the hash of the truncated cached excerpt.
      const discoveredFingerprint = item.payload.content_fingerprint
      const contentFingerprint =
        typeof discoveredFingerprint === "string" && /^[a-f0-9]{40}$/i.test(discoveredFingerprint)
          ? discoveredFingerprint
          : createHash("sha256").update(text).digest("hex").slice(0, 40)
      const sourceContentLength = typeof item.payload.content_length === "number" && Number.isFinite(item.payload.content_length)
        ? item.payload.content_length
        : text.length
      const cachedTextTruncated = item.payload.cached_text_truncated === true || sourceContentLength > text.length
      const extracted = extractResearchDetails(title, text, vulnerabilityClass)
      const ingested = ReportKnowledge.ingestExternalDetailed({
        title,
        severity: extracted.severity,
        vulnerabilityClass,
        cweID: extracted.cweID,
        sourceURL: item.source_url,
        attackVector: extracted.attackVector,
        impact: extracted.impact,
        reproduction: extracted.reproduction,
        poc: extracted.poc,
        lesson: extracted.lesson,
        sourceTrust: source.trust,
        tags: Array.from(new Set([source.id, source.kind, documentType, ...extracted.retrievalSignals])),
        metadata: {
          research_source: source.id,
          research_source_name: source.name,
          source_trust: source.trust,
          content_fingerprint: contentFingerprint,
          candidate_score: item.payload.candidate_score ?? 0,
          crawl_depth: item.payload.crawl_depth ?? 0,
          // Keep a useful bounded study excerpt, not just a title/short snippet.
          // This is cleaned public-source text, still untrusted and not target evidence.
          excerpt: text.slice(0, 12000),
          content_length: sourceContentLength,
          content_truncated_for_learning: cachedTextTruncated,
          stored_excerpt_length: Math.min(text.length, 12000),
          queue_id: item.public_id,
          extraction_version: RESEARCH_LEARNING_VERSION,
          study_method: "bounded-heuristic-extraction",
          extracted: {
            vulnerability_class: vulnerabilityClass ?? null,
            classification_method: "title-first-dominant-body-v2",
            severity: extracted.severity,
            cwe_id: extracted.cweID ?? null,
            lesson: extracted.lesson ?? null,
            attack_vector: extracted.attackVector ?? null,
            impact: extracted.impact ?? null,
            reproduction_steps: extracted.reproduction ?? null,
            poc_snippet: extracted.poc ?? null,
            prerequisites: extracted.prerequisites ?? null,
            verification_signals: extracted.verificationSignals ?? null,
            false_positive_cautions: extracted.falsePositiveCautions ?? null,
            root_cause: extracted.rootCause ?? null,
            request_response_evidence: extracted.requestResponseEvidence ?? null,
            affected_components: extracted.affectedComponents ?? null,
            affected_versions: extracted.affectedVersions ?? null,
            technology_stack: extracted.technologyStack ?? null,
            remediation: extracted.remediation ?? null,
            attack_chain: extracted.attackChain ?? null,
            negative_evidence: extracted.negativeEvidence ?? null,
            limitations: extracted.limitations ?? null,
            retrieval_signals: extracted.retrievalSignals,
            extraction_coverage: {
              present: [
                extracted.lesson,
                extracted.cweID,
                extracted.attackVector,
                extracted.impact,
                extracted.reproduction,
                extracted.poc,
                extracted.prerequisites,
                extracted.verificationSignals,
                extracted.falsePositiveCautions,
                extracted.rootCause,
                extracted.requestResponseEvidence,
                extracted.affectedComponents,
                extracted.affectedVersions,
                extracted.technologyStack,
                extracted.remediation,
                extracted.attackChain,
                extracted.negativeEvidence,
                extracted.limitations,
              ].filter(Boolean).length,
              total: 18,
              note: "Field presence only; not a quality score or practical validation.",
            },
          },
        },
      })
      if (!ingested) throw new Error("knowledge ingestion returned no record")
      if (ingested.created) {
        result.learned++
      } else {
        result.skipped++
      }
      ResearchQueue.complete(item.sequence, item.lease_owner, "learned")
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      const authRequired = /\bHTTP\s+(?:401|403)\b|authentication required|login required|sign in required/i.test(message)
      const completed = ResearchQueue.complete(
        item.sequence,
        item.lease_owner,
        authRequired ? "blocked_auth" : item.attempts >= 3 ? "rejected" : "retry",
        message,
      )
      // A slow worker may lose its lease while fetching/studying. Do not report a
      // stale failure or stop this batch when its completion was correctly fenced out.
      if (!completed) {
        result.skipped++
        continue
      }
      if (authRequired) result.blocked_auth++
      result.failed++
      if (result.errors.length < 5) result.errors.push(item.public_id + " " + item.source_url + " — " + message)
      // Do not immediately reclaim the same failing item repeatedly in one batch.
      break
    }
  }
  return result
}

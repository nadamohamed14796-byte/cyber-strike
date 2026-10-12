import { createHash } from "node:crypto"
import { ReportKnowledge } from "../learning/report-knowledge"
import { RESEARCH_SOURCES, type ResearchSource } from "./sources"
import { discoverySeeds, sourceDocumentPriority } from "./adapters"
import { fetchResearchText as fetchText } from "./safe-fetch"

const MAX_LINKS_PER_PAGE = 160
const MAX_CANDIDATE_SCORE = 100
const DEFAULT_LIMIT = 50
const MAX_LIMIT = 500
const DEFAULT_PAGES = 250
const MAX_PAGES = 1000
const DEFAULT_DEPTH = 2
const MAX_DEPTH = 4

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number) {
  const candidate = value === undefined || !Number.isFinite(value) ? fallback : value
  return Math.max(minimum, Math.min(Math.floor(candidate), maximum))
}

function hostAllowed(url: URL, source: ResearchSource) {
  return source.hosts.some((host) => url.hostname === host || url.hostname.endsWith("." + host))
}

function normalizeUrl(value: string, base?: URL) {
  try {
    const url = new URL(value, base)
    url.hash = ""
    for (const key of ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref"]) {
      url.searchParams.delete(key)
    }
    return url.toString()
  } catch {
    return undefined
  }
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
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b/g, "[API KEY REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[JWT REDACTED]")
    .replace(/((?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|csrf[_-]?token|session[_-]?id|sessionid|private[_-]?key|secret[_-]?key|password|passwd|token|secret|sid)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s"'&,;<>]+)/gi, "$1[REDACTED]")
    .replace(/([?&](?:access_token|refresh_token|csrf_token|sessionid|private_key|token|api_key|apikey|secret|password|signature|sig|auth|session)=)[^&#\s"'<>]+/gi, "$1[REDACTED]")
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
      if (links.size >= MAX_LINKS_PER_PAGE) break
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
      if (links.size >= MAX_LINKS_PER_PAGE) break
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
  if (excludedPath) return { accepted: false, score: -100 }

  const excluded = source.excludeTerms?.filter((term) => matchesTerm(haystack, term)).length ?? 0
  const included = source.includeTerms?.filter((term) => matchesTerm(haystack, term)).length ?? 0
  const pathBoost = source.includePaths?.some((value) => path.includes(value.toLowerCase())) ? 25 : 0

  // Sources without a policy keep the generic crawler behaviour.
  if (!source.includeTerms?.length) return { accepted: true, score: pathBoost }

  // For noisy sources such as Medium, require real security relevance.
  // A title/path hit alone is not enough unless it is a highly specific vuln term.
  const specificVulnerability =
    /\b(idor|xss|ssrf|csrf|sqli|ssti|xxe|cve|account takeover|prototype pollution|request smuggling|race condition|subdomain takeover|path traversal)\b/i.test(
      title + " " + path,
    )
  const accepted = specificVulnerability || included >= 2 || (included >= 1 && pathBoost > 0)
  return { accepted: accepted && excluded === 0, score: included * 12 + pathBoost - excluded * 20 }
}

export function isIndexLikeResearchUrl(url: string) {
  try {
    const parsed = new URL(url)
    const path = parsed.pathname.toLowerCase().replace(/\/+$/, "") || "/"
    // Root landing pages are discovery seeds, not automatically learnable articles.
    if (path === "/") return true
    if (/[?&](page|p|offset|start|pageindex)=\d+/i.test(parsed.search)) return true
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
  if (source.id === "medium") {
    const segments = path.split("/").filter(Boolean)
    if (
      path.startsWith("/@") ||
      (segments.length >= 2 &&
        !/^(tag|me|membership|about|help|search|plans|topics|media|home|latest)$/i.test(segments[0]))
    ) {
      return true
    }
  }
  if (
    /\/reports?\b|\/hacktivity\b|\/writeups?\b|\/research\b|\/blog\b|\/articles?\b|\/labs?\b|\/disclos|\/advisories?\b|\/learn\b|\/academy\b|\/techniques?\b|\/payloads?\b|\/cheats?heets?\b|\/blob\/|\/tree\//.test(
      path,
    )
  )
    return true
  return /[?&](page|p|offset|start|pageindex)=\d+/i.test(parsed.search)
}

function classify(text: string) {
  const lower = text.toLowerCase()
  const classes: Array<[string, RegExp]> = [
    ["idor", /\bidor\b|insecure direct object|object[- ]level authorization|object[- ]identifier|resource identifier|another user(?:'s)? (?:data|object|account)/],
    ["object-identifier", /object identifier|resource identifier|object id|user id|account id|order id/],
    ["xss", /cross[- ]site scripting|\bxss\b/],
    ["ssrf", /server[- ]side request forgery|\bssrf\b/],
    ["csrf", /cross[- ]site request forgery|\bcsrf\b/],
    ["sqli", /sql injection|\bsqli\b/],
    ["xxe", /xml external entity|\bxxe\b/],
    ["ssti", /server[- ]side template injection|\bssti\b/],
    ["race-condition", /race condition|time[- ]of[- ]check/],
    ["open-redirect", /open redirect/],
    ["auth-bypass", /authentication bypass|auth bypass/],
    ["access-control", /access control|authorization bypass/],
    ["business-logic", /business logic/],
    ["prototype-pollution", /prototype pollution/],
    ["deserialization", /insecure deserialization|deserialization/],
    ["request-smuggling", /request smuggling/],
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
  return classes.find(([, pattern]) => pattern.test(lower))?.[0]
}

function severityOf(text: string) {
  const match = text.match(/\b(critical|high|medium|low|informational)\b/i)
  return match?.[1]?.toLowerCase() ?? "unknown"
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
  const patterns: Array<[string, RegExp]> = [
    ["idor", /\bidor\b|insecure direct object|object[- ]level authorization|object[- ]identifier|resource identifier|another user(?:'s)? (?:data|object|account)/],
    ["object-identifier", /object identifier|resource identifier|object id|user id|account id|order id/],
    ["authorization-boundary", /authorization|access control|privilege escalation|another user|other account/],
    ["authentication-flow", /authentication|login|session fixation|password reset|account recovery/],
    ["token-or-jwt", /\bjwt\b|bearer token|refresh token|access token|oauth/],
    ["javascript-client", /\.m?js\b|javascript|source map|client-side|frontend/],
    ["api-endpoint", /\bapi\b|endpoint|graphql|rest api/],
    ["file-upload", /file upload|multipart|content-type|filename/],
    ["cache-behavior", /cache-control|cache poisoning|cache deception|cdn/],
    ["cors-policy", /\bcors\b|access-control-allow-origin/],
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
      /chain(?:ed|ing)?|pivot|combine(?:d|s)? with|leads? to|result(?:s|ed)? in|escalat(?:e|ion)|account takeover|privilege escalation|lateral movement|from .* to /i,
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
  const origin = "https://" + source.hosts[0]
  try {
    const html = await fetchText(origin + "/sitemap.xml", source)
    return [...html.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)]
      .map((match) => normalizeUrl(match[1]))
      .filter((value): value is string => !!value)
      .slice(0, MAX_LINKS_PER_PAGE)
  } catch {
    return []
  }
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
  if (/\/(?:login|log-in|signin|sign-in|register|signup|sign-up|auth)(?:\/|$)/i.test(pathname)) return true
  if (/^(?:sign in|log in|login|create an account|authentication required)(?:\b|\s*[-|])/i.test(heading)) return true
  if (/(?:sign in|log in) to (?:continue|view|read|access)|login required|authentication required|you must be logged in|create an account to (?:view|read|continue)|members only/i.test(body)) return true
  return text.trim().length < 1200 && /<form\b/i.test(html) && /(?:password|sign in|log in|login|email address)/i.test(html) && /(?:login|signin|sign-in|auth|session)/i.test(html)
}

export type ResearchSyncOptions = {
  limit?: number
  pages?: number
  depth?: number
  /** Exhaust the discovered queue until the page budget is reached. */
  all?: boolean
}

export async function syncResearchSource(
  source: ResearchSource,
  options: ResearchSyncOptions = {},
): Promise<ResearchIngestResult> {
  const exhaustive = options.all === true
  const limit = boundedInteger(options.limit, DEFAULT_LIMIT, 1, MAX_LIMIT)
  const maxPages = boundedInteger(options.pages, DEFAULT_PAGES, 1, MAX_PAGES)
  const maxDepth = boundedInteger(options.depth, DEFAULT_DEPTH, 0, MAX_DEPTH)

  // Route every sync through the durable queue. This keeps direct API callers and
  // the CLI on the same idempotent discovery/learning path instead of re-learning
  // previously completed reports through an in-memory-only crawl.
  const discovered = await discoverResearch({ sourceID: source.id, pages: maxPages, depth: maxDepth })
  const discovery = discovered[0]
  const learned = await learnResearchQueue({
    limit: exhaustive ? MAX_LIMIT : limit,
    sourceID: source.id,
  })
  return {
    source: source.id,
    fetched: discovery?.pages ?? 0,
    learned: learned.learned,
    skipped: learned.skipped,
    failed: learned.failed,
    blocked_auth: (discovery?.blocked_auth ?? 0) + learned.blocked_auth,
    pages_crawled: discovery?.pages ?? 0,
    candidates_discovered: discovery?.candidates ?? 0,
    error_samples: [...(discovery?.errors ?? []), ...learned.errors].slice(0, 5),
  }
}

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
export async function discoverResearch(input: { sourceID?: string; pages?: number; depth?: number } = {}) {
  const { ResearchQueue } = await import("./queue")
  const sources = input.sourceID ? RESEARCH_SOURCES.filter((source) => source.id === input.sourceID) : RESEARCH_SOURCES
  if (!sources.length) throw new Error("unknown research source: " + input.sourceID)
  const maxPages = Math.max(1, Math.min(input.pages ?? 100, MAX_PAGES))
  const maxDepth = Math.max(0, Math.min(input.depth ?? 2, MAX_DEPTH))
  const results: Array<{ source: string; pages: number; candidates: number; added: number; blocked_auth: number; errors: string[] }> = []

  for (const source of sources) {
    const queue: Array<{ url: string; depth: number }> = []
    const queued = new Set<string>()
    const visited = new Set<string>()
    const errors: string[] = []
    let pages = 0
    let candidates = 0
    let added = 0
    let blockedAuth = 0
    const add = (value: string, depth: number) => {
      const url = normalizeUrl(value)
      if (!url || depth > maxDepth || queued.has(url) || visited.has(url)) return
      try {
        const parsed = new URL(url)
        if (parsed.protocol !== "https:" || !hostAllowed(parsed, source)) return
        if (depth > 0 && !isResearchCandidate(url, source)) return
      } catch {
        return
      }
      queued.add(url)
      queue.push({ url, depth })
    }

    for (const seed of discoverySeeds(source, maxPages)) add(seed, 0)
    for (const url of await discoverSitemap(source)) add(url, 1)

    while (queue.length && pages < maxPages) {
      queue.sort((a, b) => candidateScore(b.url, source) - candidateScore(a.url, source) || a.depth - b.depth)
      const current = queue.shift()!
      if (visited.has(current.url)) continue
      visited.add(current.url)
      if (current.depth > 0 && isResearchCandidate(current.url, source) && ResearchQueue.find(source.id, current.url)) continue
      pages++
      try {
        const html = await fetchText(current.url, source)
        const title = redactResearchSecrets(titleOf(html, current.url))
        const text = redactResearchSecrets(cleanHtml(html))
        if (looksLikeResearchAuthenticationWall(current.url, title, text, html)) {
          ResearchQueue.blockAuthentication({
            sourceID: source.id, sourceURL: current.url, title,
            reason: "authentication wall detected; configure a source-scoped session, then run research retry-auth",
            payload: { source_name: source.name, source_kind: source.kind, crawl_depth: current.depth },
          })
          blockedAuth++
          errors.push(current.url + " — authentication required")
          continue
        }
        for (const link of linksOf(html, new URL(current.url), source)) {
          candidates++
          add(link, current.depth + 1)
        }

        if (text.length >= 120 && (current.depth === 0 || isResearchCandidate(current.url, source))) {
          const relevance = sourceRelevance(current.url, title, text, source)
          if (relevance.accepted && !isIndexLikeResearchUrl(current.url)) {
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
                // Discovery already fetched and sanitized this report. Cache the bounded text
                // so the learning worker does not issue a second HTTP request for the same page.
                cached_text: text.slice(0, 12000),
                content_fingerprint: createHash("sha256").update(text).digest("hex").slice(0, 40),
              },
            })
            if (row.created) added++
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        if (/\bHTTP\s+(?:401|403)\b|authentication required|login required|sign in required/i.test(message)) {
          ResearchQueue.blockAuthentication({
            sourceID: source.id, sourceURL: current.url, reason: message,
            payload: { source_name: source.name, source_kind: source.kind, crawl_depth: current.depth },
          })
          blockedAuth++
          errors.push(current.url + " — authentication required (" + message + ")")
        } else if (errors.length < 5) errors.push(current.url + " — " + message)
      }
      if (current.depth >= maxDepth) continue
    }
    results.push({ source: source.id, pages, candidates, added, blocked_auth: blockedAuth, errors })
  }
  return results
}

/** Learning-only worker: claim persisted candidates, extract a lesson, and record a terminal/retry state. */
export async function learnResearchQueue(input: { limit?: number; workerID?: string; sourceID?: string } = {}) {
  const { ResearchQueue } = await import("./queue")
  const workerID = input.workerID ?? "learn-" + process.pid + "-" + crypto.randomUUID()
  const limit = Math.max(1, Math.min(input.limit ?? 50, MAX_LIMIT))
  const result = { worker: workerID, claimed: 0, learned: 0, skipped: 0, failed: 0, blocked_auth: 0, errors: [] as string[] }

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
        ResearchQueue.complete(item.sequence, item.lease_owner, "blocked_auth", "authentication wall detected; configure a source-scoped session, then run research retry-auth")
        result.blocked_auth++
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
      const vulnerabilityClass = classify(title + " " + text)
      if (!vulnerabilityClass && source.kind !== "reference" && source.kind !== "academy") {
        ResearchQueue.complete(item.sequence, item.lease_owner, "rejected", "no recognizable security topic")
        result.skipped++
        continue
      }

      const contentFingerprint = createHash("sha256").update(text).digest("hex").slice(0, 40)
      const extracted = extractResearchDetails(title, text, vulnerabilityClass)
      const ingested = ReportKnowledge.ingestExternalDetailed({
        title,
        severity: extracted.severity,
        vulnerabilityClass,
        sourceURL: item.source_url,
        attackVector: extracted.attackVector,
        impact: extracted.impact,
        reproduction: extracted.reproduction,
        poc: extracted.poc,
        lesson: extracted.lesson,
        sourceTrust: source.trust,
        tags: Array.from(new Set([source.id, source.kind, ...extracted.retrievalSignals])),
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
          content_length: text.length,
          stored_excerpt_length: Math.min(text.length, 12000),
          queue_id: item.public_id,
          extraction_version: 4,
          study_method: "bounded-heuristic-extraction",
          extracted: {
            vulnerability_class: vulnerabilityClass ?? null,
            severity: extracted.severity,
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
              total: 17,
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
      ResearchQueue.complete(item.sequence, item.lease_owner, authRequired ? "blocked_auth" : item.attempts >= 3 ? "rejected" : "retry", message)
      if (authRequired) result.blocked_auth++
      result.failed++
      if (result.errors.length < 5) result.errors.push(item.public_id + " " + item.source_url + " — " + message)
      // Do not immediately reclaim the same failing item repeatedly in one batch.
      break
    }
  }
  return result
}

import { expect, test } from "bun:test"
import { RESEARCH_SOURCES, researchSourceHostAllowed, researchSourcePathAllowed, resolveResearchSourceForURL } from "../../src/research/sources"
import { isIndexLikeResearchContent, isIndexLikeResearchUrl, isResearchCandidate, linksOf, sourceRelevance } from "../../src/research/ingest"
import { discoverySeeds, isDiscoveryPaginationURL, nextDiscoveryPage } from "../../src/research/adapters"

const trickster0 = RESEARCH_SOURCES.find((source) => source.id === "trickster0")!

test("repository-backed GitHub sources cannot crawl sibling repositories", () => {
  const srcHunter = RESEARCH_SOURCES.find((source) => source.id === "src-hunter-skill")!
  const payloads = RESEARCH_SOURCES.find((source) => source.id === "payloadsallthethings")!
  const genericGitHub = RESEARCH_SOURCES.find((source) => source.id === "github")!

  expect(researchSourcePathAllowed(
    "https://github.com/MyuriKanao/src-hunter-skill/tree/main/references/h1-reports/raw/reports",
    srcHunter,
  )).toBe(true)
  expect(researchSourcePathAllowed(
    "https://github.com/MyuriKanao/src-hunter-skill/blob/main/references/h1-reports/raw/reports/report.md",
    srcHunter,
  )).toBe(true)
  expect(researchSourcePathAllowed("https://github.com/MyuriKanao/src-hunter-skill-evil/blob/main/report.md", srcHunter)).toBe(false)
  expect(researchSourcePathAllowed("https://github.com/attacker/other-repo/blob/main/report.md", srcHunter)).toBe(false)

  expect(researchSourcePathAllowed("https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection", payloads)).toBe(true)
  expect(researchSourcePathAllowed("https://github.com/swisskyrepo/PayloadsAllTheThings-evil/blob/main/README.md", payloads)).toBe(false)
  expect(researchSourcePathAllowed("https://github.com/another/repo/blob/main/README.md", payloads)).toBe(false)

  // The intentionally generic search source remains able to discover writeups across GitHub.
  expect(researchSourcePathAllowed("https://github.com/another/repo/blob/main/security-report.md", genericGitHub)).toBe(true)
})

test("curated Medium feed restricts subdomains and sitemap roots to the configured author", () => {
  const source = RESEARCH_SOURCES.find((item) => item.id === "trickster0")!
  expect(researchSourceHostAllowed("https://trickster0.medium.com/an-idor-report", source)).toBe(true)
  expect(researchSourceHostAllowed("https://medium.com/@trickster0/idor-writeup-123", source)).toBe(true)
  expect(researchSourceHostAllowed("https://anotherwriter.medium.com/general-security-post", source)).toBe(false)
  expect(source.sitemapHosts).toEqual(["trickster0.medium.com"])
})
test("Medium source follows the curated author, not unrelated Medium articles", () => {
  expect(isResearchCandidate("https://trickster0.medium.com/an-idor-report", trickster0)).toBe(true)
  expect(isResearchCandidate("https://medium.com/@trickster0/idor-writeup-123", trickster0)).toBe(true)
  expect(isResearchCandidate("https://medium.com/@anotherwriter/general-security-post", trickster0)).toBe(false)
  expect(isResearchCandidate("https://medium.com/tag/bug-bounty", trickster0)).toBe(false)
})

test("general Medium security feed accepts individual articles but excludes listing/profile pages", () => {
  const source = RESEARCH_SOURCES.find((item) => item.id === "medium-security")!
  expect(isResearchCandidate("https://medium.com/tag/bug-bounty", source)).toBe(false)
  expect(isResearchCandidate("https://medium.com/@researcher/idor-writeup-123abc", source)).toBe(true)
  expect(isResearchCandidate("https://researcher.medium.com/how-i-found-xss-123abc", source)).toBe(true)
  expect(isResearchCandidate("https://medium.com/@researcher", source)).toBe(false)
  expect(isResearchCandidate("https://medium.com/search?q=xss", source)).toBe(false)
  expect(researchSourceHostAllowed("https://researcher.medium.com/an-idor-report", source)).toBe(true)
  expect(researchSourceHostAllowed("https://unrelated.example/an-idor-report", source)).toBe(false)
})

test("legacy generic Medium source IDs do not reopen platform-wide crawling", () => {
  const legacyGenericMedium = { ...trickster0, id: "medium" }
  expect(isResearchCandidate("https://medium.com/@anotherwriter/general-security-post", legacyGenericMedium)).toBe(false)
  expect(isResearchCandidate("https://medium.com/tag/bug-bounty", legacyGenericMedium)).toBe(false)
  expect(isResearchCandidate("https://medium.com/@trickster0/idor-writeup-123", legacyGenericMedium)).toBe(false)
})

test("Medium source relevance rejects off-topic content but retains bounty writeups", () => {
  expect(
    sourceRelevance(
      "https://trickster0.medium.com/an-idor-report",
      "IDOR via missing authorization",
      "A bug bounty writeup explaining the insecure direct object reference and its impact.",
      trickster0,
    ).accepted,
  ).toBe(true)

  expect(
    sourceRelevance(
      "https://trickster0.medium.com/my-weekend",
      "My weekend and career update",
      "A personal travel story with general career advice.",
      trickster0,
    ).accepted,
  ).toBe(false)

  expect(
    sourceRelevance(
      "https://trickster0.medium.com/job-alert",
      "Security job alert",
      "A job alert with hiring and career advice.",
      trickster0,
    ).accepted,
  ).toBe(false)
})

test("SecurityCipher discovery is hard-bounded to the bounty-writeups directory", () => {
  const source = RESEARCH_SOURCES.find((item) => item.id === "securitycipher-bounty-writeups")!
  expect(source.allowedPathPrefixes).toEqual(["/bounty-writeups"])
  expect(researchSourcePathAllowed("https://securitycipher.com/bounty-writeups/", source)).toBe(true)
  expect(researchSourcePathAllowed("https://securitycipher.com/bounty-writeups/2026/example-report", source)).toBe(true)
  expect(researchSourcePathAllowed("https://securitycipher.com/blog/example", source)).toBe(false)
  expect(isResearchCandidate("https://securitycipher.com/bounty-writeups/2026/example-report", source)).toBe(true)
  expect(isResearchCandidate("https://securitycipher.com/blog/example", source)).toBe(false)
})

test("source exclusions apply even when a source has no include-term policy", () => {
  const { includeTerms: _includeTerms, ...base } = trickster0
  const exclusionOnlySource = {
    ...base,
    id: "exclusion-only-test",
    excludeTerms: ["career advice"],
  }

  expect(
    sourceRelevance(
      "https://example.test/articles/post",
      "Career advice for beginners",
      "A general career advice article with no vulnerability research.",
      exclusionOnlySource,
    ).accepted,
  ).toBe(false)

  expect(
    sourceRelevance(
      "https://example.test/articles/post",
      "A technical article",
      "A technical article with no excluded terms.",
      exclusionOnlySource,
    ).accepted,
  ).toBe(true)
})

test("does not classify feed, repository, tree, or all-labs indexes as learnable articles", () => {
  const genericGitHub = RESEARCH_SOURCES.find((source) => source.id === "github")!
  const srcHunter = RESEARCH_SOURCES.find((source) => source.id === "src-hunter-skill")!
  const securityCipher = RESEARCH_SOURCES.find((source) => source.id === "securitycipher-bounty-writeups")!
  const bugcrowd = RESEARCH_SOURCES.find((source) => source.id === "bugcrowd-crowdstream")!
  const infosec = RESEARCH_SOURCES.find((source) => source.id === "infosec-writeups")!

  expect(isIndexLikeResearchUrl("https://trickster0.medium.com/")).toBe(true)
  expect(isIndexLikeResearchUrl("https://portswigger.net/web-security/all-labs")).toBe(true)
  expect(isIndexLikeResearchUrl("https://portswigger.net/web-security/authentication")).toBe(false)

  const repoRoot = "https://github.com/MyuriKanao/src-hunter-skill"
  const reportsDir = repoRoot + "/tree/main/references/h1-reports/raw/reports"
  const reportFile = repoRoot + "/blob/main/references/h1-reports/raw/reports/report.md"
  expect(isResearchCandidate(repoRoot, genericGitHub)).toBe(true)
  expect(isResearchCandidate(repoRoot, srcHunter)).toBe(true)
  expect(isIndexLikeResearchUrl(repoRoot)).toBe(true)
  expect(isIndexLikeResearchUrl(reportsDir)).toBe(true)
  expect(isResearchCandidate(reportsDir, srcHunter)).toBe(true)
  expect(isIndexLikeResearchUrl(reportFile)).toBe(false)
  expect(isResearchCandidate(reportFile, srcHunter)).toBe(true)

  const securityCipherIndex = "https://securitycipher.com/bounty-writeups/"
  expect(isIndexLikeResearchUrl(securityCipherIndex)).toBe(true)
  expect(isResearchCandidate(securityCipherIndex, securityCipher)).toBe(false)
  expect(isIndexLikeResearchUrl("https://securitycipher.com/bounty-writeups/2026/example-report")).toBe(false)
  expect(isResearchCandidate("https://securitycipher.com/bounty-writeups/2026/example-report", securityCipher)).toBe(true)

  expect(isIndexLikeResearchUrl("https://bugcrowd.com/crowdstream")).toBe(true)
  expect(isResearchCandidate("https://bugcrowd.com/crowdstream", bugcrowd)).toBe(false)
  expect(isIndexLikeResearchUrl("https://infosecwriteups.com/tagged/bug-bounty")).toBe(true)
  expect(isResearchCandidate("https://infosecwriteups.com/tagged/bug-bounty", infosec)).toBe(false)
})

test("hyphenated vulnerability names pass curated source relevance filters", () => {
  expect(sourceRelevance(
    "https://trickster0.medium.com/account-takeover-report",
    "Account-takeover via an OAuth flow",
    "A technical report describing account-takeover impact and responsible disclosure.",
    trickster0,
  ).accepted).toBe(true)
})


test("legacy source inference uses allowlisted path prefixes and refuses ambiguous shared hosts", () => {
  expect(resolveResearchSourceForURL("https://hackerone.com/hacktivity/reports/123")?.id).toBe("hackerone-hacktivity")
  expect(resolveResearchSourceForURL("https://hackerone.com/hacktivity/reports/123", "hackerone")?.id).toBe("hackerone-hacktivity")
  expect(resolveResearchSourceForURL("https://www.hackerone.com/blog/security-research")?.id).toBe("hackerone-blog")
  expect(resolveResearchSourceForURL("https://www.hackerone.com/blog/security-research", "default")?.id).toBe("hackerone-blog")
  expect(resolveResearchSourceForURL("https://portswigger.net/web-security/access-control/idor", "default")?.id).toBe("portswigger")
  expect(resolveResearchSourceForURL("https://hackerone.com/unclassified/path")).toBeUndefined()

  // Contradictory explicit provenance is not silently replaced with an inferred source.
  expect(resolveResearchSourceForURL("https://hackerone.com/hacktivity/reports/123", "hackerone-blog")).toBeUndefined()
  expect(resolveResearchSourceForURL("http://hackerone.com/hacktivity/reports/123")).toBeUndefined()
  expect(resolveResearchSourceForURL("https://user:pass@hackerone.com/hacktivity/reports/123")).toBeUndefined()
})


test("source pagination stays lazy and continues beyond the former hard ceiling", () => {
  const hackerOne = RESEARCH_SOURCES.find((source) => source.id === "hackerone-hacktivity")!
  const seeds = discoverySeeds(hackerOne)
  expect(seeds).toEqual([...new Set(hackerOne.seedUrls)])

  const overview = seeds.find((url) => new URL(url).pathname.includes("/overview"))
  expect(overview).toBeDefined()
  const firstPage = nextDiscoveryPage(hackerOne, overview!)
  expect(firstPage).toBeDefined()
  expect(new URL(firstPage!).searchParams.get("pageIndex")).toBe("1")
  expect(isDiscoveryPaginationURL(hackerOne, firstPage!)).toBe(true)

  const page1000 = nextDiscoveryPage(hackerOne, "https://hackerone.com/hacktivity/overview?pageIndex=999&queryString=disclosed%3Atrue")
  expect(page1000).toBeDefined()
  expect(new URL(page1000!).searchParams.get("pageIndex")).toBe("1000")
  const page1001 = nextDiscoveryPage(hackerOne, page1000!)
  expect(page1001).toBeDefined()
  expect(new URL(page1001!).searchParams.get("pageIndex")).toBe("1001")
  expect(isDiscoveryPaginationURL(hackerOne, page1001!)).toBe(true)
})


test("HackerOne recovers report URLs embedded in client-rendered listing state", () => {
  const source = RESEARCH_SOURCES.find((item) => item.id === "hackerone-hacktivity")!
  const base = new URL("https://hackerone.com/hacktivity/overview?pageIndex=0")
  const html = String.raw`<script id="__APP_STATE__" type="application/json">{
    "reports":[
      {"url":"\\/reports\\/12345"},
      {"url":"https:\\/\\/hackerone.com\\/reports\\/67890"},
      {"url":"/reports/new"}
    ]
  }</script>`
  const links = linksOf(html, base, source)
  expect(links).toContain("https://hackerone.com/reports/12345")
  expect(links).toContain("https://hackerone.com/reports/67890")
  expect(links.some((url) => url.endsWith("/reports/new"))).toBe(false)
})


test("content-shaped archives are traversed but not treated as complete reports", () => {
  const indexText = "Recent bug bounty writeups and disclosed reports. Browse the latest submissions and research articles."
  expect(isIndexLikeResearchContent({
    title: "Bug Bounty Archive",
    text: indexText,
    discoveredLinkCount: 28,
  })).toBe(true)

  // A real report with reproduction and impact evidence remains learnable even
  // when it links to many related references.
  expect(isIndexLikeResearchContent({
    title: "IDOR in account export",
    text: "Steps to reproduce: change the account ID. Impact: another user's private export is returned.",
    discoveredLinkCount: 28,
  })).toBe(false)

  // Avoid classifying ordinary prose pages as indexes based on a small link set.
  expect(isIndexLikeResearchContent({
    title: "How I found an authorization bypass",
    text: "I tested the endpoint and confirmed that changing the account identifier exposed another user's data.",
    discoveredLinkCount: 4,
  })).toBe(false)
})

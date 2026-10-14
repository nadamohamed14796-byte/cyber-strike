import { expect, test } from "bun:test"
import { RESEARCH_SOURCES, resolveResearchSourceForURL } from "../../src/research/sources"
import { isIndexLikeResearchUrl, isResearchCandidate, sourceRelevance } from "../../src/research/ingest"
import { discoverySeeds, isDiscoveryPaginationURL, nextDiscoveryPage } from "../../src/research/adapters"

const trickster0 = RESEARCH_SOURCES.find((source) => source.id === "trickster0")!

test("Medium source follows the curated author, not unrelated Medium articles", () => {
  expect(isResearchCandidate("https://trickster0.medium.com/an-idor-report", trickster0)).toBe(true)
  expect(isResearchCandidate("https://medium.com/@trickster0/idor-writeup-123", trickster0)).toBe(true)
  expect(isResearchCandidate("https://medium.com/@anotherwriter/general-security-post", trickster0)).toBe(false)
  expect(isResearchCandidate("https://medium.com/tag/bug-bounty", trickster0)).toBe(false)
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

test("does not classify root landing pages or all-labs indexes as learnable articles", () => {
  expect(isIndexLikeResearchUrl("https://trickster0.medium.com/")).toBe(true)
  expect(isIndexLikeResearchUrl("https://portswigger.net/web-security/all-labs")).toBe(true)
  expect(isIndexLikeResearchUrl("https://portswigger.net/web-security/authentication")).toBe(false)
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

import { expect, test } from "bun:test"
import { RESEARCH_SOURCES } from "../../src/research/sources"
import { isIndexLikeResearchUrl, isResearchCandidate, sourceRelevance } from "../../src/research/ingest"
import { discoverySeeds } from "../../src/research/adapters"

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


test("source pagination seeds respect the configured budget up to the discovery hard limit", () => {
  const hackerOne = RESEARCH_SOURCES.find((source) => source.id === "hackerone-hacktivity")!
  const normal = discoverySeeds(hackerOne, 10)
  expect(normal.filter((url) => new URL(url).pathname.includes("/overview"))).toHaveLength(10)
  expect(normal.some((url) => new URL(url).searchParams.get("pageIndex") === "9")).toBe(true)

  const exhaustive = discoverySeeds(hackerOne, 1000)
  const pageURLs = exhaustive.filter((url) => new URL(url).pathname.includes("/overview"))
  expect(pageURLs).toHaveLength(1000)
  expect(pageURLs.some((url) => new URL(url).searchParams.get("pageIndex") === "999")).toBe(true)

  // Requests above the crawler's hard ceiling are still bounded.
  expect(discoverySeeds(hackerOne, 5000)).toHaveLength(exhaustive.length)
})

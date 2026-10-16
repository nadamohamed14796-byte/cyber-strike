import { describe, expect, test } from "bun:test"
import { discoverySeeds, isDiscoveryPaginationURL, nextDiscoveryPage } from "./adapters"
import { RESEARCH_SOURCES } from "./sources"

describe("research pagination adapters", () => {
  test("uses canonical source seeds instead of allocating a capped page list", () => {
    const source = RESEARCH_SOURCES.find((item) => item.id === "hackerone-hacktivity")!
    expect(discoverySeeds(source)).toEqual([...new Set(source.seedUrls)])
  })

  test("continues HackerOne pageIndex pagination beyond the former 1000-page ceiling", () => {
    const source = RESEARCH_SOURCES.find((item) => item.id === "hackerone-hacktivity")!
    const current = "https://hackerone.com/hacktivity/overview?pageIndex=1000&queryString=disclosed%3Atrue"
    expect(nextDiscoveryPage(source, current)).toBe(
      "https://hackerone.com/hacktivity/overview?pageIndex=1001&queryString=disclosed%3Atrue",
    )
    expect(isDiscoveryPaginationURL(source, "https://hackerone.com/hacktivity/overview?pageIndex=1001")).toBe(true)
  })

  test("continues path-based archive pagination beyond the former ceiling", () => {
    const source = RESEARCH_SOURCES.find((item) => item.id === "intigriti")!
    expect(nextDiscoveryPage(source, "https://www.intigriti.com/researchers/blog/page/1000")).toBe(
      "https://www.intigriti.com/researchers/blog/page/1001",
    )
    expect(isDiscoveryPaginationURL(source, "https://www.intigriti.com/researchers/blog/page/1001")).toBe(true)
  })

  test("continues Medium security topic feeds without a fixed page ceiling", () => {
    const source = RESEARCH_SOURCES.find((item) => item.id === "medium-security")!
    expect(nextDiscoveryPage(source, "https://medium.com/tag/bug-bounty?page=1000")).toBe(
      "https://medium.com/tag/bug-bounty?page=1001",
    )
    expect(isDiscoveryPaginationURL(source, "https://medium.com/tag/bug-bounty?page=1001")).toBe(true)
    expect(nextDiscoveryPage(source, "https://medium.com/@researcher/idor-writeup")).toBeUndefined()
  })

  test("increments query pagination and rejects malformed page numbers", () => {
    const source = RESEARCH_SOURCES.find((item) => item.id === "github")!
    expect(nextDiscoveryPage(source, "https://github.com/search?q=bug+bounty&page=1000")).toBe(
      "https://github.com/search?q=bug+bounty&page=1001",
    )
    expect(nextDiscoveryPage(source, "https://github.com/search?q=bug+bounty&page=invalid")).toBeUndefined()
  })
})

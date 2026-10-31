import { expect, test } from "bun:test"
import type { Page } from "playwright"
import { makeMatcher } from "../src/scope.ts"
import { jsbundle } from "../src/discovery/detectors/jsbundle.ts"

const inScope = makeMatcher(["*.example.test"])
const baseUrl = "https://app.example.test/"

function pageWithScripts(scripts: { external: string[]; inline: string[] }): Page {
  return {
    evaluate: async () => scripts,
  } as unknown as Page
}

test("jsbundle processes every external script and inline source beyond former size caps", async () => {
  const external = Array.from({ length: 35 }, (_, index) => `https://static.example.test/bundle-${index}.js`)
  const fetched = new Set<string>()
  const largeBundle = "/*" + "x".repeat(3_100_000) + "*/ fetch(\"/api/from-large-bundle\")"
  const inline = "/*" + "y".repeat(600_000) + "*/ fetch(\"/api/from-large-inline\")"

  const result = await jsbundle.detect({
    page: pageWithScripts({ external, inline: [inline] }),
    baseUrl,
    inScope,
    fetchText: async (url) => {
      fetched.add(url)
      const index = Number(url.match(/bundle-(\d+)\.js$/)?.[1] ?? 0)
      return index === 34 ? largeBundle : `fetch(\"/api/script-${index}\")`
    },
  })

  expect(fetched.size).toBe(35)
  expect(result.endpoints).toHaveLength(36)
  expect(result.endpoints.some((item) => item.url.endsWith("/api/from-large-bundle"))).toBe(true)
  expect(result.endpoints.some((item) => item.url.endsWith("/api/from-large-inline"))).toBe(true)
  expect(jsbundle.timeoutMs).toBeNull()
})

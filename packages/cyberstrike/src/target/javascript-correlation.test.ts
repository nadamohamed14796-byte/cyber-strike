import { describe, expect, test } from "bun:test"
import { mergeStructuredJavaScriptEndpoints, type JavaScriptEndpointCandidate } from "./javascript-correlation"

function candidate(input: {
  queryParameters: string[]
  bodyParameters: string[]
  headerNames: string[]
  authSignals: string[]
  cookieSignals: string[]
  sourceFile: string
  method?: string
}): JavaScriptEndpointCandidate {
  return {
    id: input.sourceFile,
    literal: "/api/items",
    host: "api.example.test",
    origin: "https://api.example.test",
    path: "/api/items",
    method: input.method ?? "GET",
    pathParameters: [],
    queryParameters: input.queryParameters,
    bodyParameters: input.bodyParameters,
    headerNames: input.headerNames,
    authSignals: input.authSignals,
    cookieSignals: input.cookieSignals,
    sourceFiles: [input.sourceFile],
    observedRequestIDs: [],
    observedInTraffic: false,
    confidence: "candidate",
  }
}

describe("mergeStructuredJavaScriptEndpoints", () => {
  test("merges parameter variants into one route while preserving metadata", () => {
    const merged = mergeStructuredJavaScriptEndpoints([
      candidate({ queryParameters: ["page"], bodyParameters: ["filter"], headerNames: ["x-tenant"], authSignals: ["bearer"], cookieSignals: ["session"], sourceFile: "bundle-a.js" }),
      candidate({ queryParameters: ["sort"], bodyParameters: ["category"], headerNames: ["x-trace"], authSignals: ["api-key"], cookieSignals: ["preference"], sourceFile: "bundle-b.js" }),
    ], [])
    expect(merged).toHaveLength(1)
    expect(merged[0]?.queryParameters).toEqual(["page", "sort"])
    expect(merged[0]?.bodyParameters).toEqual(["filter", "category"])
    expect(merged[0]?.headerNames).toEqual(["x-tenant", "x-trace"])
    expect(merged[0]?.authSignals).toEqual(["bearer", "api-key"])
    expect(merged[0]?.cookieSignals).toEqual(["session", "preference"])
    expect(merged[0]?.sourceFiles).toEqual(["bundle-a.js", "bundle-b.js"])
  })

  test("keeps different HTTP methods as separate endpoint identities", () => {
    const merged = mergeStructuredJavaScriptEndpoints([
      candidate({ queryParameters: ["page"], bodyParameters: [], headerNames: [], authSignals: [], cookieSignals: [], sourceFile: "get.js" }),
      candidate({ queryParameters: [], bodyParameters: ["name"], headerNames: [], authSignals: [], cookieSignals: [], sourceFile: "post.js", method: "POST" }),
    ], [])
    expect(merged).toHaveLength(2)
    expect(merged.map((item) => item.method).sort()).toEqual(["GET", "POST"])
  })
})

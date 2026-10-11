import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { ReportKnowledge } from "../../src/learning/report-knowledge"
import { tmpdir } from "../fixture/fixture"

test("shared research retrieval uses signal tags and excludes target-specific reports", async () => {
  await using dir = await tmpdir()
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const shared = ReportKnowledge.ingestExternalDetailed({
        title: "JavaScript source map reveals API endpoints",
        severity: "medium",
        vulnerabilityClass: "idor",
        sourceURL: "https://research.example.test/reports/js-api-sourcemap",
        attackVector: "A public JavaScript source map exposed an API route and object identifier.",
        impact: "An authenticated user could access another account's object when authorization was missing.",
        reproduction: "Load the source map, identify the route, then compare owner and non-owner requests.",
        poc: "GET /api/objects/123 HTTP/1.1",
        lesson: "Map client-side routes to API requests and verify object-level authorization using controlled accounts.",
        sourceTrust: 80,
        tags: ["javascript-client", "api-endpoint", "idor"],
        metadata: {
          source_trust: 80,
          extracted: {
            retrieval_signals: ["javascript-client", "api-endpoint", "idor"],
            prerequisites: "Two controlled accounts with different object ownership.",
          },
        },
      })
      const targetSpecific = ReportKnowledge.ingestExternalDetailed({
        title: "Target-specific internal route observation",
        severity: "low",
        sourceURL: "https://research.example.test/reports/private-route",
        targetPattern: "private-target.example",
        lesson: "A route observed only on one target.",
        sourceTrust: 80,
        tags: ["javascript-client"],
        metadata: { source_trust: 80 },
      })

      expect(shared).not.toBeNull()
      expect(targetSpecific).not.toBeNull()

      const matches = ReportKnowledge.recommendations({ signal: "javascript-client", limit: 5 })
      expect(matches.some((row) => row.id === shared?.id)).toBe(true)
      expect(matches.some((row) => row.id === targetSpecific?.id)).toBe(false)

      // Natural-language observations are mapped to stored signal tags, not just exact words.
      const bySignal = ReportKnowledge.recommendations({
        signal: "client-side JavaScript source map reveals a REST API route",
        limit: 5,
      })
      expect(bySignal.some((row) => row.id === shared?.id)).toBe(true)

      const pathTraversal = ReportKnowledge.ingestExternalDetailed({
        title: "Path traversal through a download endpoint",
        severity: "high",
        vulnerabilityClass: "path-traversal",
        sourceURL: "https://research.example.test/reports/download-path-traversal",
        attackVector: "A file path parameter is normalized incorrectly before access checks.",
        impact: "An authenticated user can read files outside the intended directory.",
        reproduction: "Change the download path and compare the returned file with an allowed baseline.",
        lesson: "Check canonicalized paths and prove access outside the intended directory.",
        sourceTrust: 80,
        tags: ["path-traversal"],
        metadata: { source_trust: 80, extracted: { retrieval_signals: ["path-traversal"] } },
      })
      expect(pathTraversal).not.toBeNull()
      const byPathSignal = ReportKnowledge.recommendations({
        signal: "download endpoint path traversal through parent directory",
        limit: 5,
      })
      expect(byPathSignal.some((row) => row.id === pathTraversal?.id)).toBe(true)

      const byReproduction = ReportKnowledge.search({ query: "owner non-owner requests", sourceKind: "external_report", limit: 5 })
      expect(byReproduction.some((row) => row.id === shared?.id)).toBe(true)
      await Instance.dispose()
    },
  })
})

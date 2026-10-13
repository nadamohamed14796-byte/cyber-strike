import { expect, test } from "bun:test"
import { eq } from "drizzle-orm"
import { Instance } from "../../src/project/instance"
import { Database } from "../../src/storage/db"
import { SessionTable } from "../../src/session/session.sql"
import { ReportKnowledgeEventTable, ReportKnowledgeTable } from "../../src/learning/report-knowledge.sql"
import { ReportKnowledge } from "../../src/learning/report-knowledge"
import { tmpdir } from "../fixture/fixture"

test("shared research retrieval uses signal tags and excludes target-specific reports", async () => {
  await using dir = await tmpdir()
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
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

      // Flood the candidate ranking with newer, high-similarity rows that must
      // never enter cross-target recommendations. Filtering only after slicing
      // would hide the eligible shared row below this target-specific noise.
      for (let index = 0; index < 20; index++) {
        await Bun.sleep(2)
        ReportKnowledge.ingestExternalDetailed({
          title: "JavaScript source map reveals API endpoints " + marker + " tenant " + index,
          severity: "medium",
          vulnerabilityClass: "idor",
          sourceURL: "https://research.example.test/reports/" + marker + "/scoped-noise-" + index,
          targetPattern: "private-target-" + marker + "-" + index + ".example",
          lesson: "Map JavaScript routes and compare authorized API object access.",
          sourceTrust: 80,
          tags: ["javascript-client", "api-endpoint", "idor"],
          metadata: {
            source_trust: 80,
            extracted: { retrieval_signals: ["javascript-client", "api-endpoint", "idor"] },
          },
        })
      }

      expect(ReportKnowledge.externalSourceURLs()).toContain("https://research.example.test/reports/js-api-sourcemap")
      expect(ReportKnowledge.externalSourceURLs()).toContain("https://research.example.test/reports/private-route")

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

test("target outcomes do not relabel globally shared external research", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_external_outcome_" + marker
      const now = Date.now()
      Database.use((db) =>
        db.insert(SessionTable).values({
          id: sessionID,
          project_id: Instance.project.id,
          slug: "external-outcome",
          directory: dir.path,
          title: "External research outcome isolation",
          version: "1",
          time_created: now,
          time_updated: now,
        }).run(),
      )

      const title = "Shared external access-control methodology " + marker
      const report = ReportKnowledge.ingestExternalDetailed({
        title,
        severity: "unknown",
        vulnerabilityClass: "idor",
        sourceURL: "https://research.example.test/" + marker + "/shared-methodology",
        lesson: "Compare a controlled owner-account baseline with a second controlled account.",
        sourceTrust: 85,
        tags: ["idor", "authorization-boundary"],
        metadata: { source_trust: 85, extracted: { retrieval_signals: ["idor", "authorization-boundary"] } },
      })
      expect(report).not.toBeNull()
      if (!report) throw new Error("test external report was not persisted")

      ReportKnowledge.recordOutcome({
        reportID: report.id,
        sessionID,
        outcome: "disproven",
        signal: "owner-vs-non-owner check on this target",
        evidence: "The second account received an authorization denial on this target.",
        hook: "verification",
      })

      const stored = ReportKnowledge.search({ query: title, sourceKind: "external_report", limit: 10 })
        .find((row) => row.id === report.id)
      expect(stored?.status).toBe("observed")
      expect(stored?.times_rejected).toBe(0)
      expect(stored?.outcome).toBe("observed")

      const events = Database.use((db) =>
        db.select().from(ReportKnowledgeEventTable)
          .where(eq(ReportKnowledgeEventTable.report_id, report.id))
          .all(),
      )
      expect(events.some((event) =>
        event.session_id === sessionID &&
        event.outcome === "disproven" &&
        event.hook === "verification"
      )).toBe(true)

      await Instance.dispose()
    },
  })
})


test("finding-validation feedback ranks shared references without poisoning global truth", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_reference_feedback_" + marker
      const now = Date.now()
      Database.use((db) =>
        db.insert(SessionTable).values({
          id: sessionID,
          project_id: Instance.project.id,
          slug: "reference-feedback",
          directory: dir.path,
          title: "Reference feedback test",
          version: "1",
          time_created: now,
          time_updated: now,
        }).run(),
      )

      const shared = ReportKnowledge.ingestExternalDetailed({
        title: "CORS and authorization research reference " + marker,
        severity: "unknown",
        vulnerabilityClass: "cors",
        sourceURL: "https://research.example.test/" + marker + "/cors-reference",
        lesson: "Compare the observed CORS response headers against the intended cross-origin policy.",
        sourceTrust: 80,
        tags: ["cors-policy", "cors"],
        metadata: { source_trust: 80, extracted: { retrieval_signals: ["cors-policy"] } },
      })
      const scoped = ReportKnowledge.ingestExternalDetailed({
        title: "Target-scoped CORS note " + marker,
        severity: "unknown",
        sourceURL: "https://research.example.test/" + marker + "/scoped-cors-reference",
        targetPattern: "tenant-" + marker + ".example",
        lesson: "This note belongs to one target only.",
        sourceTrust: 80,
        tags: ["cors-policy"],
        metadata: { source_trust: 80 },
      })
      expect(shared).not.toBeNull()
      expect(scoped).not.toBeNull()
      if (!shared || !scoped) throw new Error("test references were not persisted")

      const corsMatches = ReportKnowledge.recommendations({
        signal: "CORS cross-origin response policy",
        vulnerabilityClass: "cors",
        limit: 3,
      })
      expect(corsMatches.some((row) => row.id === shared.id)).toBe(true)

      const feedback = {
        reportID: shared.id,
        sessionID,
        signal: "finding-validation:confirmed",
        metadata: { validation_verdict: "confirmed", feedback_basis: "agent-marked-materially-influential" },
      }
      // A guessed record ID cannot raise ranking until that exact public reference
      // was actually surfaced in the current session tree.
      expect(ReportKnowledge.recordReferenceUse({ ...feedback, outcome: "useful" })).toBe(false)
      expect(ReportKnowledge.recordReferenceUse({
        ...feedback,
        outcome: "observed",
        hook: "research-context",
        signal: "automatic-context",
        metadata: { feedback_basis: "reference-surfaced-in-context" },
      })).toBe(true)
      expect(ReportKnowledge.recordReferenceUse({ ...feedback, outcome: "useful" })).toBe(true)
      expect(ReportKnowledge.recordReferenceUse({ ...feedback, outcome: "useful" })).toBe(false)
      expect(ReportKnowledge.recordReferenceUse({ ...feedback, outcome: "observed" })).toBe(true)
      expect(ReportKnowledge.recordReferenceUse({ ...feedback, reportID: scoped.id, outcome: "useful" })).toBe(false)

      const stored = Database.use((db) =>
        db.select().from(ReportKnowledgeTable).where(eq(ReportKnowledgeTable.id, shared.id)).get(),
      )
      expect(stored?.times_useful).toBe(1)
      expect(stored?.times_rejected).toBe(0)
      expect(stored?.status).toBe("observed")
      expect(stored?.outcome).toBe("observed")

      const stats = ReportKnowledge.stats()
      expect(stats.externalReferencesUsed).toBe(1)
      expect(stats.externalReferenceUsefulnessEvents).toBe(1)

      const events = Database.use((db) =>
        db.select().from(ReportKnowledgeEventTable)
          .where(eq(ReportKnowledgeEventTable.report_id, shared.id))
          .all(),
      )
      expect(events.filter((event) => event.session_id === sessionID && event.hook === "finding-validation")).toHaveLength(2)
      expect(events.some((event) => event.outcome === "useful")).toBe(true)
      expect(events.some((event) => event.outcome === "observed")).toBe(true)

      await Instance.dispose()
    },
  })
})


test("re-ingesting an existing public source enriches newly extracted CWE and class fields", async () => {
  await using dir = await tmpdir()
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const sourceURL = "https://research.example.test/reports/cwe-backfill-" + crypto.randomUUID()
      const first = ReportKnowledge.ingestExternalDetailed({
        title: "CORS policy report",
        severity: "unknown",
        sourceURL,
        lesson: "A public report about a cross-origin policy.",
        sourceTrust: 80,
        metadata: { source_trust: 80, extracted: { extraction_version: 6 } },
      })
      expect(first).not.toBeNull()
      if (!first) throw new Error("initial report was not persisted")

      const second = ReportKnowledge.ingestExternalDetailed({
        title: "CORS policy report",
        severity: "high",
        vulnerabilityClass: "cors",
        cweID: "CWE-942",
        sourceURL,
        lesson: "The cross-origin policy allows an unintended origin.",
        sourceTrust: 80,
        tags: ["cors", "cors-policy", "CWE-942"],
        metadata: {
          source_trust: 80,
          extracted: { extraction_version: 7, cwe_id: "CWE-942" },
        },
      })
      expect(second).not.toBeNull()
      expect(second?.id).toBe(first.id)
      expect(second?.created).toBe(false)

      const row = Database.use((db) =>
        db.select().from(ReportKnowledgeTable).where(eq(ReportKnowledgeTable.id, first.id)).get(),
      )
      expect(row?.vulnerability_class).toBe("cors")
      expect(row?.cwe_id).toBe("CWE-942")
      expect(row?.severity).toBe("high")
      expect(row?.tags).toEqual(expect.arrayContaining(["cors", "cors-policy", "CWE-942"]))
      expect((row?.metadata?.extracted as Record<string, unknown>)?.extraction_version).toBe(7)
      await Instance.dispose()
    },
  })
})

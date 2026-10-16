import { afterEach, beforeEach, expect, test } from "bun:test"
import { eq } from "drizzle-orm"
import { Instance } from "../../src/project/instance"
import { Database } from "../../src/storage/db"
import { SessionTable } from "../../src/session/session.sql"
import { ReportKnowledgeEventTable, ReportKnowledgeTable } from "../../src/learning/report-knowledge.sql"
import { ReportKnowledge } from "../../src/learning/report-knowledge"
import { ResearchQueue } from "../../src/research/queue"
import { ResearchQueueTable } from "../../src/research/queue.sql"
import { ResearchCycleTable } from "../../src/research/cycle.sql"
import { ResearchCycle } from "../../src/research/cycle"
import { RESEARCH_SOURCES } from "../../src/research/sources"
import { queueLegacyKnowledgeForModelStudy, ResearchStudyTool } from "../../src/tool/research-study"
import { ResearchKnowledgeTool } from "../../src/tool/research-knowledge"
import { tmpdir } from "../fixture/fixture"

// Direct tool integration tests get an explicitly initialized study-phase cycle when no cycle exists.
// Dedicated phase-gate tests create a collecting cycle and pass its ID to verify premature study is blocked.
async function executeResearchTool(tool: any, params: any, context: any) {
  const needsCycle = ["discover", "next", "read", "save", "complete"].includes(params.action)
  let cycle = ResearchCycle.current()
  if (needsCycle && !cycle) {
    const created = ResearchCycle.begin(RESEARCH_SOURCES.map((source) => source.id))
    for (const source of RESEARCH_SOURCES) {
      ResearchCycle.recordDiscovery({
        cycleID: created.cycle_id, sourceID: source.id, pageWindow: 20, pages: 0, candidates: 0, queuedNew: 0,
        blockedAuth: 0, errorCount: 0, errors: [],
      })
    }
    cycle = ResearchCycle.current()
  }
  const cycleID = params.cycle_id ?? (needsCycle ? cycle?.cycle_id : undefined)
  return tool["execute"]({ ...params, ...(cycleID ? { cycle_id: cycleID } : {}) }, context)
}

// These integration tests share the worker-local SQLite database. Clear only the
// research fixtures before each case so queue claims and legacy backfill counts are deterministic.
beforeEach(() => {
  Database.use((db) => {
    db.delete(ResearchQueueTable).run()
    db.delete(ReportKnowledgeEventTable).run()
    db.delete(ReportKnowledgeTable).run()
    db.delete(ResearchCycleTable).run()
  })
})

// Temporary source aliases are test fixtures, not process-wide configuration.
afterEach(() => {
  for (let index = RESEARCH_SOURCES.length - 1; index >= 0; index--) {
    if (/^portswigger-(?:study-test|filter-test|backfill-test|legacy-study-test)-/.test(RESEARCH_SOURCES[index]!.id)) {
      RESEARCH_SOURCES.splice(index, 1)
    }
  }
})

test("agent-led research study persists model analysis and completes its queue lease", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_agent_research_study_" + marker.replace(/-/g, "").slice(0, 18)
      const baseSource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!baseSource) throw new Error("PortSwigger test source is not configured")
      const sourceID = "portswigger-study-test-" + marker
      RESEARCH_SOURCES.push({
        ...baseSource,
        id: sourceID,
        // Make test URLs belong to this temporary alias even while the real
        // PortSwigger source is registered; production source resolution stays strict.
        seedUrls: ["https://portswigger.net/web-security/"],
      })
      const sourceURL = "https://portswigger.net/web-security/access-control/idor?study-test=" + marker
      const sourceText = [
        "IDOR (insecure direct object reference) occurs when the server does not verify object-level authorization.",
        "CWE-639: Authorization Bypass Through User-Controlled Key.",
        "Severity: High.",
        "Prerequisite: use two controlled accounts with different object ownership.",
        "Reproduction: capture the owner GET /api/objects/123 request and repeat it using the second account; compare the response with the owner's baseline.",
        "Impact: the second account may read another user's private record.",
        "False-positive caution: a public object or a record intentionally shared with both accounts is not evidence of an authorization flaw.",
        "Verification signal: confirm the returned object belongs to the owner and is not intended to be publicly readable.",
      ].join(" ")

      const now = Date.now()
      Database.use((db) => db.insert(SessionTable).values({
        id: sessionID,
        project_id: Instance.project.id,
        slug: "agent-research-study",
        directory: dir.path,
        title: "Agent research study integration test",
        version: "1",
        time_created: now,
        time_updated: now,
      }).run())

      const queued = ResearchQueue.enqueue({
        sourceID,
        sourceURL,
        title: "IDOR with CWE-639 " + marker,
        payload: {
          source_name: "PortSwigger Web Security Academy",
          source_kind: "academy",
          source_trust: 95,
          cached_text: sourceText,
          content_length: sourceText.length,
          content_fingerprint: "a".repeat(40),
          crawl_depth: 0,
          cached_text_truncated: false,
        },
      })
      expect(queued.created).toBe(true)

      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID,
        messageID: "msg_agent_research_study_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any

      const next = await executeResearchTool(tool, {
        action: "next",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
      }, context)
      const batch = JSON.parse(next.output)
      expect(batch.batch_size).toBeGreaterThanOrEqual(1)
      const claimed = batch.items.find((item: { public_id: string }) => item.public_id === queued.id)
      expect(claimed).toBeDefined()
      if (!claimed) throw new Error("the explicitly queued PortSwigger row was not claimed")
      expect(claimed.text).toContain("CWE-639")

      const save = await executeResearchTool(tool, {
        action: "save",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
        items: [{
          public_id: claimed.public_id,
          lease_owner: claimed.lease_owner,
          decision: "learned",
          document_type: "academy",
          vulnerability_class: "idor",
          cwe_id: "CWE-639",
          severity: "high",
          lesson: "Compare the same object request between two controlled identities and verify ownership before treating cross-account access as an authorization flaw.",
          initial_observation: "An authenticated request contains an object identifier and returns a private record.",
          hypotheses: ["Object-level authorization is missing.", "The object is intentionally public or shared."],
          attempted_tests: ["Replay the captured owner request using a second controlled account."],
          successful_tests: ["The second account receives a record proven to belong to the first account."],
          failed_tests: ["A modified identifier returns the same authorized public object."],
          rejected_hypotheses: ["The response alone proves IDOR without confirming object ownership."],
          decisive_evidence: "The returned record's owner identity differs from the authenticated second account, and sharing is not intended.",
          reported_outcome: "Educational lab scenario; this fixture is not a real confirmed production disclosure.",
          verification_status: "educational_example",
          unresolved_questions: ["Would a third role have different access?"],
          pattern_name: "Cross-account object ownership check",
          pattern_summary: "Compare the same object request between controlled identities and verify ownership, privacy, and intentional sharing.",
          trigger_signal: "An authenticated endpoint accepts a caller-controlled user, account, order, or object identifier.",
          test_procedure: ["Capture the owner's baseline request.", "Replay with a second controlled account.", "Compare returned object identity and ownership."],
          expected_positive_signals: ["The second account receives private data owned by the first account."],
          expected_negative_signals: ["The object is intentionally public or shared with both identities."],
          evidence_requirements: ["Owner-account baseline", "Second-account replay", "Evidence identifying the object owner"],
          applicability_conditions: ["The endpoint returns user-owned or otherwise access-controlled objects."],
          non_applicability_conditions: ["The resource is intentionally public or the caller is authorized to access it."],
          attack_vector: "A caller changes an object identifier in an authenticated request.",
          impact: "Private data may be disclosed across account boundaries.",
          prerequisites: "Two controlled accounts with different object ownership and a valid baseline request.",
          reproduction_steps: "Capture the owner request, replay it with the second account, and compare the object identity and response body.",
          root_cause: "The server relies on a caller-controlled object key without enforcing ownership authorization.",
          request_response_evidence: "Compare the owner baseline and cross-account response, including the object owner field and response body.",
          verification_signals: ["The second account receives the exact private object owned by the first account."],
          false_positive_cautions: ["The object may intentionally be public or shared with both accounts."],
          retrieval_signals: ["idor", "object-identifier", "authorization-boundary", "CWE-639"],
        }],
      }, context)

      const saved = JSON.parse(save.output)
      expect(saved.saved).toBe(1)
      expect(saved.results[0].result).toBe("learned")
      const knowledgeID = saved.results[0].knowledge_id
      const knowledge = Database.use((db) => db.select().from(ReportKnowledgeTable)
        .where(eq(ReportKnowledgeTable.id, knowledgeID)).get())
      expect(knowledge?.source_url).toBe(sourceURL)
      expect(knowledge?.source_kind).toBe("external_report")
      expect(knowledge?.status).toBe("observed")
      expect(knowledge?.vulnerability_class).toBe("idor")
      expect(knowledge?.cwe_id).toBe("CWE-639")
      expect(knowledge?.metadata?.study_method).toBe("llm-assisted-agent-command-v1")
      expect(knowledge?.metadata?.document_type).toBe("academy")
      const extracted = knowledge?.metadata?.extracted as Record<string, unknown> | undefined
      expect(extracted?.document_type).toBe("academy")
      expect(extracted?.failed_tests).toEqual(["A modified identifier returns the same authorized public object."])
      expect(extracted?.pattern_name).toBe("Cross-account object ownership check")
      expect(extracted?.test_procedure).toHaveLength(3)
      expect(knowledge?.metadata?.model_study_version).toBe(3)
      expect(knowledge?.metadata?.excerpt).toContain("two controlled accounts")

      // Verify the hunt-time retrieval tool exposes the actual structured lesson,
      // rather than merely proving that the row exists in SQLite.
      const researchKnowledge = await ResearchKnowledgeTool.init()
      const retrieved = await researchKnowledge.execute({
        signal: "IDOR object identifier authorization",
        vulnerability_class: "idor",
        cwe: "CWE-639",
        limit: 5,
      }, context)
      expect(retrieved.metadata.matches).toBeGreaterThan(0)
      expect(retrieved.output).toContain("Document type: academy")
      expect(retrieved.output).toContain("Tests attempted:")
      expect(retrieved.output).toContain("Failed tests described by source: A modified identifier returns the same authorized public object.")
      expect(retrieved.output).toContain("Reusable pattern: Cross-account object ownership check")
      expect(retrieved.output).toContain("Ordered test procedure: Capture the owner's baseline request.")
      
      const completedQueueRow = ResearchQueue.find(sourceID, sourceURL)
      expect(completedQueueRow?.status).toBe("learned")
      expect(completedQueueRow?.payload?.model_study_version).toBe(3)
      expect(ResearchQueue.stats(sourceID).model_study_learned).toBe(1)
      expect(ResearchQueue.stats(sourceID).model_study_completed).toBe(1)
      expect(ResearchQueue.stats(sourceID).model_study_pending).toBe(0)

      const events = Database.use((db) => db.select().from(ReportKnowledgeEventTable)
        .where(eq(ReportKnowledgeEventTable.report_id, knowledgeID)).all())
      expect(events.some((event) => event.hook === "research-study" && event.outcome === "observed")).toBe(false)
      expect(ReportKnowledge.stats().external).toBeGreaterThanOrEqual(1)

      const status = JSON.parse((await executeResearchTool(tool, { action: "stats", source: sourceID, pages: 1000, depth: 3, limit: 3, continue_after_save: false }, context)).output)
      expect(status.queue_source_filter).toBe(sourceID)
      expect(status.queue).toHaveProperty("crawl_page_errors")
      expect(status.queue).toHaveProperty("crawl_page_auth_blocked")
      expect(status.configured_sources).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: "portswigger", name: "PortSwigger Web Security Academy" }),
      ]))
      await Instance.dispose()
    },
  })
})


test("agent-led study can read every chunk of a long source under the tool output cap", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sourceID = "portswigger-study-test-" + marker
      const baseSource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!baseSource) throw new Error("PortSwigger test source is not configured")
      RESEARCH_SOURCES.push({
        ...baseSource,
        id: sourceID,
        seedUrls: ["https://portswigger.net/web-security/"],
      })
      const sourceURL = "https://portswigger.net/web-security/long-study-chunks-" + marker
      const firstMarker = "BEGIN_COMPLETE_RESEARCH_DOCUMENT_" + marker
      const lastMarker = "END_COMPLETE_RESEARCH_DOCUMENT_" + marker
      const sourceText = firstMarker + "\n" +
        ("IDOR object-level authorization procedure, owner baseline, access control verification, and false-positive checks.\n").repeat(700) +
        lastMarker
      const queued = ResearchQueue.enqueue({
        sourceID,
        sourceURL,
        title: "Long IDOR research article " + marker,
        payload: {
          cached_text: sourceText,
          cached_text_truncated: false,
          content_length: sourceText.length,
          content_fingerprint: "c".repeat(40),
          source_kind: "academy",
          source_trust: 95,
        },
      })
      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID: "ses_long_chunks_" + marker.replace(/-/g, "").slice(0, 18),
        messageID: "msg_long_chunks_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const next = await executeResearchTool(tool, {
        action: "next",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
      }, context)
      const batch = JSON.parse(next.output)
      const claimed = batch.items.find((item: { public_id: string }) => item.public_id === queued.id)
      expect(claimed).toBeDefined()
      if (!claimed) throw new Error("the long research item was not claimed")
      expect(claimed.text_offset).toBe(0)
      expect(claimed.has_more_text).toBe(true)
      expect(claimed.text).toContain(firstMarker)
      expect(claimed.text).not.toContain(lastMarker)
      expect(next.metadata.truncated).toBe(false)

      // The queue must not accept a learned/rejected decision until every source
      // chunk has been returned and the durable cursor reaches the document end.
      const prematureSave = await executeResearchTool(tool, {
        action: "save",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
        items: [{
          public_id: claimed.public_id,
          lease_owner: claimed.lease_owner,
          decision: "learned",
          lesson: "This premature save must be blocked while source chunks remain unread.",
        }],
      }, context)
      const prematureResult = JSON.parse(prematureSave.output)
      expect(prematureResult.results[0].result).toBe("unread-source-chunks")
      expect(prematureResult.next_batch).toBeUndefined()
      expect(ResearchQueue.find(sourceID, sourceURL)?.status).toBe("studying")
      expect(ReportKnowledge.search({
        query: "Long IDOR research article " + marker,
        sourceKind: "external_report",
        limit: 5,
      }).some((row) => row.title.includes(marker))).toBe(false)

      const skippedChunk = await executeResearchTool(tool, {
        action: "read",
        source: sourceID,
        public_id: claimed.public_id,
        lease_owner: claimed.lease_owner,
        offset: (claimed.next_text_offset as number) + 1,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
      }, context)
      expect(skippedChunk.metadata.error).toBe("unexpected_offset")

      const chunks = [claimed.text as string]
      let offset = claimed.next_text_offset as number
      let hasMore = claimed.has_more_text as boolean
      let reads = 0
      while (hasMore) {
        const read = await executeResearchTool(tool, {
          action: "read",
          source: sourceID,
          public_id: claimed.public_id,
          lease_owner: claimed.lease_owner,
          offset,
          pages: 1,
          depth: 1,
          limit: 3,
          continue_after_save: false,
        }, context)
        const part = JSON.parse(read.output)
        expect(read.metadata.truncated).toBe(false)
        expect(part.start_offset).toBe(offset)
        expect(part.text.length).toBeGreaterThan(0)
        chunks.push(part.text)
        offset = part.next_offset
        hasMore = part.has_more_text
        reads++
        expect(reads).toBeLessThan(100)
      }
      expect(chunks.join("")).toBe(sourceText)
      expect(chunks[chunks.length - 1]).toContain(lastMarker)
      expect(reads).toBeGreaterThan(1)
      expect(ResearchQueue.renewClaim(claimed.public_id, claimed.lease_owner, 20 * 60_000)).toBe(true)
      const finalSave = await executeResearchTool(tool, {
        action: "save",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 1,
        continue_after_save: true,
        items: [{
          public_id: claimed.public_id,
          lease_owner: claimed.lease_owner,
          decision: "rejected",
          reason: "Chunk streaming integration test cleanup after the complete document was read.",
        }],
      }, context)
      const finalResult = JSON.parse(finalSave.output)
      expect(finalResult.rejected).toBe(1)
      expect(finalResult.results[0].result).toBe("rejected")
      expect(finalResult.next_batch.batch_size).toBe(0)
      expect(ResearchQueue.find(sourceID, sourceURL)?.status).toBe("rejected")
      await Instance.dispose()
    },
  })
})


test("agent-led next limits each response to one item even with escape-heavy source text", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sourceID = "portswigger-study-test-" + marker
      const baseSource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!baseSource) throw new Error("PortSwigger test source is not configured")
      RESEARCH_SOURCES.push({
        ...baseSource,
        id: sourceID,
        seedUrls: ["https://portswigger.net/web-security/"],
      })
      const context = {
        sessionID: "ses_escape_batch_" + marker.replace(/-/g, "").slice(0, 18),
        messageID: "msg_escape_batch_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const sourceText = "\0".repeat(4000) + " XSS security vulnerability test procedure and evidence."
      const urls = [1, 2, 3].map((n) => "https://portswigger.net/web-security/control-heavy-" + n + "-" + marker)
      for (const [index, sourceURL] of urls.entries()) {
        ResearchQueue.enqueue({
          sourceID,
          sourceURL,
          title: "Control-heavy security research article " + index,
          payload: {
            cached_text: sourceText,
            cached_text_truncated: false,
            content_length: sourceText.length,
            content_fingerprint: String(index + 1).repeat(40),
            source_kind: "academy",
            source_trust: 100,
          },
        })
      }
      const tool = await ResearchStudyTool.init()
      const next = await executeResearchTool(tool, {
        action: "next",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
      }, context)
      expect(next.metadata.truncated).toBe(false)
      const result = JSON.parse(next.output)
      expect(result.batch_size).toBe(1)
      expect(result.items).toHaveLength(1)
      expect(result.items[0].text).toBe(sourceText)
      expect(result.items[0].has_more_text).toBe(false)
      expect(ResearchQueue.stats(sourceID).studying).toBe(1)
      expect(ResearchQueue.stats(sourceID).queued).toBe(2)
      await Instance.dispose()
    },
  })
})


test("agent-led study terminally blocks queued URLs outside their configured source host", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const sourceURL = "https://example.invalid/outside-configured-source"
      const queued = ResearchQueue.enqueue({
        sourceID: "portswigger",
        sourceURL,
        title: "Queued URL with contradictory source provenance",
      })
      const context = {
        sessionID: "ses_bad_source_url_" + crypto.randomUUID().replace(/-/g, "").slice(0, 18),
        messageID: "msg_bad_source_url_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const tool = await ResearchStudyTool.init()
      const response = await executeResearchTool(tool, {
        action: "next",
        source: "portswigger",
        pages: 1,
        depth: 1,
        limit: 1,
        continue_after_save: false,
      }, context)
      const result = JSON.parse(response.output)
      expect(result.issues.some((issue: string) => issue.includes("blocked_fetch"))).toBe(true)
      expect(ResearchQueue.find("portswigger", sourceURL)?.status).toBe("blocked_fetch")
      expect(ResearchQueue.stats("portswigger").retry).toBe(0)
      expect(ResearchQueue.stats("portswigger").blocked_fetch).toBe(1)
      await Instance.dispose()
    },
  })
})


test("preflight skips are counted separately from model-studied reports", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sourceID = "unconfigured-source-" + marker
      const sourceURL = "https://legacy.example.test/" + marker
      const queued = ResearchQueue.enqueue({
        sourceID,
        sourceURL,
        title: "Legacy report from an unknown source",
        payload: { cached_text: "An untrusted source excerpt that must not be studied because its host is no longer configured. ".repeat(5) },
      })
      expect(queued.created).toBe(true)

      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID: "ses_preflight_skip_" + marker.replace(/-/g, "").slice(0, 18),
        messageID: "msg_preflight_skip_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const next = await executeResearchTool(tool, {
        action: "next",
        pages: 5,
        depth: 2,
        limit: 3,
        continue_after_save: false,
      }, context)
      const result = JSON.parse(next.output)
      expect(result.batch_size).toBe(0)
      expect(result.issues).toEqual(expect.arrayContaining([queued.id + ": unknown source id"]))

      const row = ResearchQueue.find(sourceID, sourceURL)
      expect(row?.status).toBe("rejected")
      expect(row?.payload?.model_study_method).toBe("preflight-skip")
      expect(row?.payload?.model_study_decision).toBe("skipped")
      expect(ResearchQueue.stats(sourceID).model_study_skipped).toBe(1)
      expect(ResearchQueue.stats(sourceID).model_study_completed).toBe(0)
      await Instance.dispose()
    },
  })
})


test("source-scoped model-study save refuses a lease from another source", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_source_filter_" + marker.replace(/-/g, "").slice(0, 18)
      const baseSource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!baseSource) throw new Error("PortSwigger test source is not configured")
      const sourceID = "portswigger-filter-test-" + marker
      RESEARCH_SOURCES.push({
        ...baseSource,
        id: sourceID,
        // Make test URLs belong to this temporary alias even while the real
        // PortSwigger source is registered; production source resolution stays strict.
        seedUrls: ["https://portswigger.net/web-security/"],
      })
      const sourceURL = "https://portswigger.net/web-security/source-filter-" + marker
      const sourceText = ("A reusable access-control security lesson. ").repeat(12)
      const queued = ResearchQueue.enqueue({
        sourceID,
        sourceURL,
        title: "Access-control source filter test " + marker,
        payload: { cached_text: sourceText, content_length: sourceText.length, content_fingerprint: "b".repeat(40) },
      })
      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID,
        messageID: "msg_source_filter_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const next = await executeResearchTool(tool, {
        action: "next", source: sourceID, pages: 5, depth: 2, limit: 3, continue_after_save: false,
      }, context)
      const batch = JSON.parse(next.output)
      const claimed = batch.items.find((item: { public_id: string }) => item.public_id === queued.id)
      expect(claimed).toBeDefined()
      if (!claimed) throw new Error("the PortSwigger fixture was not claimed")

      const save = await executeResearchTool(tool, {
        action: "save", source: "hackerone-blog", pages: 5, depth: 2, limit: 3, continue_after_save: false,
        items: [{
          public_id: claimed.public_id,
          lease_owner: claimed.lease_owner,
          decision: "learned",
          vulnerability_class: "access-control",
          lesson: "The source mismatch must not be persisted as a lesson.",
        }],
      }, context)
      const summary = JSON.parse(save.output)
      expect(summary.saved).toBe(0)
      expect(summary.results[0].result).toBe("source-filter-mismatch")
      expect(ResearchQueue.find(sourceID, sourceURL)?.status).toBe("retry")
      await Instance.dispose()
    },
  })
})


test("legacy model-study backfill drains multiple 500-row batches", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID().replace(/-/g, "")
      const baseSource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!baseSource) throw new Error("PortSwigger test source is not configured")
      const sourceID = "portswigger-backfill-test-" + marker
      RESEARCH_SOURCES.push({
        ...baseSource,
        id: sourceID,
        // Make test URLs belong to this temporary alias even while the real
        // PortSwigger source is registered; production source resolution stays strict.
        seedUrls: ["https://portswigger.net/web-security/"],
      })
      const legacyCount = 501
      for (let index = 0; index < legacyCount; index++) {
        const row = ReportKnowledge.ingestExternalDetailed({
          title: "Legacy IDOR model-study backfill " + marker + "-" + index,
          severity: "unknown",
          vulnerabilityClass: "idor",
          sourceURL: "https://portswigger.net/web-security/backfill/" + marker + "/" + index,
          lesson: "Legacy heuristic note without active-model study marker.",
          sourceTrust: 100,
          tags: ["idor"],
          metadata: {
            research_source: sourceID,
            source_trust: 100,
            study_method: "bounded-heuristic-extraction",
            extraction_version: 7,
          },
        })
        expect(row).not.toBeNull()
      }

      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID: "ses_legacy_backfill_" + marker.slice(0, 18),
        messageID: "msg_legacy_backfill_" + marker.slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const result = await executeResearchTool(tool, {
        action: "backfill",
        source: sourceID,
        pages: 5,
        depth: 2,
        limit: 3,
        continue_after_save: false,
      }, context)
      const summary = JSON.parse(result.output)
      expect(summary.legacy_knowledge_queued_for_model_study).toBe(legacyCount)
      expect(summary.legacy_knowledge_examined).toBe(legacyCount)
      expect(summary.current.queue.queued).toBe(legacyCount)
      expect(ResearchQueue.stats(sourceID).queued).toBe(legacyCount)
      await Instance.dispose()
    },
  })
})


test("legacy source filtering happens before the batch limit for shared hosts", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID().replace(/-/g, "")
      const hacktivity = ReportKnowledge.ingestExternalDetailed({
        title: "Older HackerOne Hacktivity record " + marker,
        severity: "unknown",
        sourceURL: "https://hackerone.com/hacktivity/legacy-" + marker,
        lesson: "Legacy report from the disclosures feed.",
        sourceTrust: 95,
        metadata: {
          research_source: "hackerone-hacktivity",
          source_trust: 95,
          study_method: "bounded-heuristic-extraction",
        },
      })
      const blog = ReportKnowledge.ingestExternalDetailed({
        title: "HackerOne Blog record " + marker,
        severity: "unknown",
        sourceURL: "https://www.hackerone.com/blog/legacy-" + marker,
        lesson: "Legacy blog post with separate configured source provenance.",
        sourceTrust: 90,
        metadata: {
          research_source: "hackerone-blog",
          source_trust: 90,
          study_method: "bounded-heuristic-extraction",
        },
      })
      const pathOnlyHacktivity = ReportKnowledge.ingestExternalDetailed({
        title: "HackerOne Hacktivity record missing legacy source tag " + marker,
        severity: "unknown",
        sourceURL: "https://hackerone.com/hacktivity/untagged-" + marker,
        lesson: "Older disclosure row has no explicit source metadata.",
        sourceTrust: 95,
      })
      const pathOnlyBlog = ReportKnowledge.ingestExternalDetailed({
        title: "HackerOne Blog record missing legacy source tag " + marker,
        severity: "unknown",
        sourceURL: "https://www.hackerone.com/blog/untagged-" + marker,
        lesson: "Older blog row has no explicit source metadata.",
        sourceTrust: 90,
      })
      expect(hacktivity).not.toBeNull()
      expect(blog).not.toBeNull()
      expect(pathOnlyHacktivity).not.toBeNull()
      expect(pathOnlyBlog).not.toBeNull()
      if (!blog || !pathOnlyBlog || !pathOnlyHacktivity) throw new Error("legacy fixtures were not persisted")

      const candidates = ReportKnowledge.externalRecordsForModelStudy(10, 1, ["hackerone.com"], "hackerone-blog")
      expect(candidates.some((row) => row.id === blog.id)).toBe(true)
      expect(candidates.some((row) => row.id === pathOnlyBlog.id)).toBe(true)
      expect(candidates.some((row) => row.id === pathOnlyHacktivity.id)).toBe(false)

      const boundedBatch = ReportKnowledge.externalRecordsForModelStudy(1, 1, ["hackerone.com"], "hackerone-blog")
      expect(boundedBatch).toHaveLength(1)
      expect(boundedBatch[0]?.metadata?.research_source).toBe("hackerone-blog")
      await Instance.dispose()
    },
  })
})


test("model-study backfill includes old reports with missing excerpts for safe refetch", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sourceURL = "https://portswigger.net/web-security/access-control/idor?legacy-empty=" + marker
      const legacy = ReportKnowledge.ingestExternalDetailed({
        title: "Legacy report without cached excerpt " + marker,
        severity: "unknown",
        vulnerabilityClass: "idor",
        sourceURL,
        lesson: "Older record predates source-text caching.",
        sourceTrust: 100,
        tags: ["idor"],
        metadata: {
          research_source: "portswigger",
          research_source_name: "PortSwigger Web Security Academy",
          source_trust: 100,
          study_method: "bounded-heuristic-extraction",
          extraction_version: 7,
        },
      })
      expect(legacy).not.toBeNull()
      if (!legacy) throw new Error("legacy knowledge fixture was not persisted")

      const first = await queueLegacyKnowledgeForModelStudy("portswigger")
      expect(first.queued).toBeGreaterThanOrEqual(1)
      const queued = ResearchQueue.find("portswigger", sourceURL)
      expect(queued?.status).toBe("queued")
      expect(queued?.payload?.cached_text).toBe("")
      expect(queued?.payload?.legacy_knowledge_id).toBe(legacy.id)

      await queueLegacyKnowledgeForModelStudy("portswigger")
      const stillQueued = ResearchQueue.find("portswigger", sourceURL)
      expect(stillQueued?.sequence).toBe(queued?.sequence)
      expect(stillQueued?.status).toBe("queued")
      expect(stillQueued?.payload?.legacy_knowledge_id).toBe(legacy.id)
      await Instance.dispose()
    },
  })
})

test("model-led update queues legacy shared reports once without refetching or changing source truth", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_legacy_model_study_" + marker.replace(/-/g, "").slice(0, 16)
      const baseSource = RESEARCH_SOURCES.find((source) => source.id === "portswigger")
      if (!baseSource) throw new Error("PortSwigger test source is not configured")
      const sourceID = "portswigger-legacy-study-test-" + marker
      RESEARCH_SOURCES.push({
        ...baseSource,
        id: sourceID,
        // Make test URLs belong to this temporary alias even while the real
        // PortSwigger source is registered; production source resolution stays strict.
        seedUrls: ["https://portswigger.net/web-security/"],
      })
      const now = Date.now()
      Database.use((db) => db.insert(SessionTable).values({
        id: sessionID,
        project_id: Instance.project.id,
        slug: "legacy-model-study",
        directory: dir.path,
        title: "Legacy model study backfill test",
        version: "1",
        time_created: now,
        time_updated: now,
      }).run())
      const sourceURL = "https://portswigger.net/web-security/access-control/idor?legacy-study=" + marker
      const excerpt = [
        "IDOR occurs when object-level authorization is not enforced by the server.",
        "CWE-639: Authorization bypass through a user-controlled object key.",
        "Severity: High.",
        "Prerequisites: two controlled accounts with different object ownership.",
        "Reproduction: capture the owner request and replay it using the second account, then compare object ownership and response content.",
        "Impact: the second account may access private data belonging to the first account.",
        "False-positive caution: an intentionally shared object or public record is not evidence of an authorization bypass.",
      ].join(" ")

      const legacy = ReportKnowledge.ingestExternalDetailed({
        title: "Legacy heuristic IDOR report " + marker,
        severity: "unknown",
        vulnerabilityClass: "idor",
        sourceURL,
        lesson: "Legacy heuristic lesson that should be reviewed by the current model.",
        sourceTrust: 100,
        tags: ["idor"],
        metadata: {
          research_source: sourceID,
          research_source_name: "PortSwigger Web Security Academy",
          source_trust: 100,
          study_method: "bounded-heuristic-extraction",
          extraction_version: 7,
          content_length: excerpt.length,
          content_fingerprint: "b".repeat(40),
          excerpt,
          extracted: { retrieval_signals: ["idor", "CWE-639"] },
        },
      })
      expect(legacy).not.toBeNull()
      if (!legacy) throw new Error("legacy knowledge fixture was not persisted")

      const first = await queueLegacyKnowledgeForModelStudy(sourceID)
      expect(first.queued).toBeGreaterThanOrEqual(1)
      const queued = ResearchQueue.find(sourceID, sourceURL)
      expect(queued?.status).toBe("queued")
      expect(queued?.payload?.legacy_knowledge_id).toBe(legacy.id)
      expect(queued?.payload?.cached_text).toBe(excerpt)
      expect(queued?.payload?.model_study_requested_version).toBe(3)

      const currentKnowledge = Database.use((db) =>
        db.select().from(ReportKnowledgeTable).where(eq(ReportKnowledgeTable.id, legacy.id)).get(),
      )
      expect(currentKnowledge?.status).toBe("observed")
      expect(currentKnowledge?.metadata?.model_study_requested_version).toBe(3)

      await queueLegacyKnowledgeForModelStudy(sourceID)
      const stillQueued = ResearchQueue.find(sourceID, sourceURL)
      expect(stillQueued?.sequence).toBe(queued?.sequence)
      expect(stillQueued?.status).toBe("queued")
      expect(stillQueued?.payload?.legacy_knowledge_id).toBe(legacy.id)

      const studyTool = await ResearchStudyTool.init()
      const context = {
        sessionID,
        messageID: "msg_legacy_study_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const next = await executeResearchTool(studyTool, {
        action: "next",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
      }, context)
      const batch = JSON.parse(next.output)
      expect(batch.batch_size).toBeGreaterThanOrEqual(1)
      if (!queued) throw new Error("legacy research queue record was not found")
      const claimed = batch.items.find((item: { source_url: string }) => item.source_url === sourceURL)
      expect(claimed).toBeDefined()
      if (!claimed) throw new Error("the specific legacy report was not claimed")
      expect(claimed.source_url).toBe(sourceURL)
      expect(claimed.public_id).toMatch(/^RPT-\d+$/)

      const save = await executeResearchTool(studyTool, {
        action: "save",
        source: sourceID,
        pages: 1,
        depth: 1,
        limit: 3,
        continue_after_save: false,
        items: [{
          public_id: claimed.public_id,
          lease_owner: claimed.lease_owner,
          decision: "rejected",
          reason: "legacy fixture is intentionally rejected by the model in this integration test",
        }],
      }, context)
      expect(JSON.parse(save.output).rejected).toBe(1)
      const finishedLegacy = Database.use((db) =>
        db.select().from(ReportKnowledgeTable).where(eq(ReportKnowledgeTable.id, legacy.id)).get(),
      )
      expect(finishedLegacy?.status).toBe("observed")
      expect(finishedLegacy?.metadata?.model_study_version).toBe(3)
      expect(finishedLegacy?.metadata?.model_study_decision).toBe("rejected")
      const finishedQueue = ResearchQueue.find(sourceID, sourceURL)
      expect(finishedQueue?.status).toBe("rejected")
      expect(finishedQueue?.payload?.model_study_version).toBe(3)
      await queueLegacyKnowledgeForModelStudy(sourceID)
      const noDuplicateRequeue = ResearchQueue.find(sourceID, sourceURL)
      expect(noDuplicateRequeue?.status).toBe("rejected")
      expect(noDuplicateRequeue?.payload?.model_study_version).toBe(3)
      await Instance.dispose()
    },
  })
})


test("begin resumes a collecting cycle without discarding source progress", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const ids = RESEARCH_SOURCES.map((source) => source.id)
      const first = ResearchCycle.begin(ids)
      const sourceID = ids[0]!
      ResearchCycle.recordDiscovery({
        cycleID: first.cycle_id, sourceID, pageWindow: 20, pages: 20, candidates: 7, queuedNew: 2,
        documentTypes: { writeup: 3, report: 2 }, duplicateURLsSkipped: 4,
        blockedAuth: 0, errorCount: 0, errors: [],
      })
      const resumed = ResearchCycle.begin(ids)
      expect(resumed.cycle_id).toBe(first.cycle_id)
      expect(resumed.phase).toBe("collecting")
      expect(resumed.source_states[sourceID]?.passes.length).toBe(1)
      expect(resumed.source_states[sourceID]?.queued_new).toBe(2)
      expect(resumed.source_states[sourceID]?.next_page_window).toBe(40)
      expect(resumed.source_states[sourceID]?.document_types).toEqual({ writeup: 3, report: 2 })
      expect(resumed.source_states[sourceID]?.duplicate_urls_skipped).toBe(4)
      await Instance.dispose()
    },
  })
})
test("research collection enforces expanding per-source windows without a global work ceiling", () => {
  const ids = RESEARCH_SOURCES.map((source) => source.id)
  const cycle = ResearchCycle.begin(ids)
  const firstSource = ids[0]!
  const outOfSequence = ResearchCycle.recordDiscovery({
    cycleID: cycle.cycle_id, sourceID: firstSource, pageWindow: 1, pages: 0, candidates: 0, queuedNew: 0,
    blockedAuth: 0, errorCount: 0, errors: [],
  })
  expect(outOfSequence).toMatchObject({ ok: false, reason: "page_window_out_of_sequence", expected_page_window: 20 })
  const fullWindow = ResearchCycle.recordDiscovery({
    cycleID: cycle.cycle_id, sourceID: firstSource, pageWindow: 20, pages: 20, candidates: 100, queuedNew: 80,
    blockedAuth: 0, errorCount: 0, errors: [],
  })
  expect(fullWindow).toMatchObject({ ok: true, phase: "collecting", source_state: { status: "collecting", next_page_window: 40 } })
})
test("research study is blocked until every source has a durable collection outcome", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const cycle = ResearchCycle.begin(RESEARCH_SOURCES.map((source) => source.id))
      const queued = ResearchQueue.enqueue({
        sourceID: "portswigger",
        sourceURL: "https://portswigger.net/web-security/access-control/idor?cycle-gate=" + marker,
        title: "Cycle gate fixture",
        payload: { cached_text: "A safely cached fixture document used to test the durable collection-to-study transition. The study worker must claim the full sanitized document only after all configured sources have reached a terminal collection state. Repeated references and source indexes remain out of this queue. ".repeat(4) },
      })
      expect(queued.created).toBe(true)
      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID: "ses_cycle_gate_" + marker.replace(/-/g, "").slice(0, 16),
        messageID: "msg_cycle_gate_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any

      const premature = await executeResearchTool(tool, {
        action: "next", cycle_id: cycle.cycle_id, pages: 1, depth: 1, limit: 1, continue_after_save: false,
      }, context)
      expect(premature.output).toContain("Do not claim or save research items")
      expect(ResearchQueue.stats("portswigger").queued).toBe(1)

      for (const source of RESEARCH_SOURCES) {
        ResearchCycle.recordDiscovery({
          cycleID: cycle.cycle_id, sourceID: source.id, pageWindow: 20, pages: 0, candidates: 0, queuedNew: 0,
          blockedAuth: 0, errorCount: 0, errors: [],
        })
      }
      expect(ResearchCycle.current()?.phase).toBe("studying")

      const allowed = await executeResearchTool(tool, {
        action: "next", cycle_id: cycle.cycle_id, source: "portswigger", pages: 1, depth: 1, limit: 1, continue_after_save: false,
      }, context)
      expect(JSON.parse(allowed.output).batch_size).toBe(1)
      await Instance.dispose()
    },
  })
})
test("completion remains partial when a source collection was partial even if queue blockers cleared", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const cycle = ResearchCycle.begin(RESEARCH_SOURCES.map((source) => source.id))
      for (const source of RESEARCH_SOURCES) {
        const partial = source.id === RESEARCH_SOURCES[0]!.id
        ResearchCycle.recordDiscovery({
          cycleID: cycle.cycle_id, sourceID: source.id, pageWindow: 20, pages: 0, candidates: 0, queuedNew: 0,
          blockedAuth: 0, errorCount: partial ? 1 : 0, errors: partial ? ["source page fetch failed"] : [],
          unresolvedAuth: 0, unresolvedErrors: partial ? 1 : 0,
        })
      }
      expect(ResearchCycle.current()?.phase).toBe("studying")
      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID: "ses_cycle_complete_partial_test",
        messageID: "msg_cycle_complete_partial",
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      const result = await executeResearchTool(tool, {
        action: "complete", cycle_id: cycle.cycle_id, pages: 20, depth: 1, limit: 1, continue_after_save: false,
      }, context)
      const summary = JSON.parse(result.output)
      expect(summary.phase).toBe("partial")
      expect(summary.completed).toBe(false)
      expect(summary.collection_partial_sources).toContainEqual(expect.objectContaining({ status: "partial" }))
      await Instance.dispose()
    },
  })
})

test("explicit research reset removes queued imports and external research but preserves target findings", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const localID = ReportKnowledge.ingest({
        title: "Local target finding " + marker,
        severity: "high",
        sourceKind: "finding",
        lesson: "Evidence observed on the user's authorized target.",
      })
      const externalID = ReportKnowledge.ingest({
        title: "Imported public research " + marker,
        severity: "medium",
        sourceKind: "external_report",
        sourceURL: "https://portswigger.net/web-security/access-control/idor?reset-test=" + marker,
        lesson: "Reusable public methodology example.",
      })
      expect(localID).toBeTruthy()
      expect(externalID).toBeTruthy()
      ResearchQueue.enqueue({
        sourceID: "portswigger",
        sourceURL: "https://portswigger.net/web-security/access-control/idor?queued-reset=" + marker,
        title: "Queued public report " + marker,
        payload: { cached_text: "Sanitized fixture content" },
      })

      const tool = await ResearchStudyTool.init()
      const context = {
        sessionID: "ses_research_reset_" + marker.replace(/-/g, "").slice(0, 16),
        messageID: "msg_research_reset_" + marker.replace(/-/g, "").slice(0, 12),
        agent: "cyberstrike",
        abort: new AbortController().signal,
        messages: [],
        metadata: () => {},
        ask: async () => {},
      } as any
      ResearchCycle.begin(RESEARCH_SOURCES.map((source) => source.id))
      const result = await executeResearchTool(tool, { action: "reset", pages: 1, depth: 0, limit: 1, continue_after_save: false }, context)
      const summary = JSON.parse(result.output)
      expect(summary.queue_rows_removed).toBe(1)
      expect(summary.external_research_records_removed).toBe(1)
      expect(ResearchCycle.current()).toBeNull()
      expect(ResearchQueue.stats().total).toBe(0)
      expect(Database.use((db) => db.select().from(ReportKnowledgeTable)
        .where(eq(ReportKnowledgeTable.id, externalID!)).get())).toBeUndefined()
      expect(Database.use((db) => db.select().from(ReportKnowledgeTable)
        .where(eq(ReportKnowledgeTable.id, localID!)).get())).toBeDefined()
      await Instance.dispose()
    },
  })
})

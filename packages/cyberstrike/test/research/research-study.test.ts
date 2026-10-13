import { expect, test } from "bun:test"
import { eq } from "drizzle-orm"
import { Instance } from "../../src/project/instance"
import { Database } from "../../src/storage/db"
import { SessionTable } from "../../src/session/session.sql"
import { ReportKnowledgeEventTable, ReportKnowledgeTable } from "../../src/learning/report-knowledge.sql"
import { ReportKnowledge } from "../../src/learning/report-knowledge"
import { ResearchQueue } from "../../src/research/queue"
import { queueLegacyKnowledgeForModelStudy, ResearchStudyTool } from "../../src/tool/research-study"
import { tmpdir } from "../fixture/fixture"

test("agent-led research study persists model analysis and completes its queue lease", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const marker = crypto.randomUUID()
      const sessionID = "ses_agent_research_study_" + marker.replace(/-/g, "").slice(0, 18)
      const sourceID = "portswigger"
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

      const next = await tool.execute({
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

      const save = await tool.execute({
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
          vulnerability_class: "idor",
          cwe_id: "CWE-639",
          severity: "high",
          lesson: "Compare the same object request between two controlled identities and verify ownership before treating cross-account access as an authorization flaw.",
          attack_vector: "A caller changes an object identifier in an authenticated request.",
          impact: "Private data may be disclosed across account boundaries.",
          prerequisites: "Two controlled accounts with different object ownership and a valid baseline request.",
          reproduction_steps: "Capture the owner request, replay it with the second account, and compare the object identity and response body.",
          root_cause: "The server relies on a caller-controlled object key without enforcing ownership authorization.",
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
      expect(knowledge?.metadata?.model_study_version).toBe(1)
      expect(knowledge?.metadata?.excerpt).toContain("two controlled accounts")
      const completedQueueRow = ResearchQueue.find(sourceID, sourceURL)
      expect(completedQueueRow?.status).toBe("learned")
      expect(completedQueueRow?.payload?.model_study_version).toBe(1)
      expect(ResearchQueue.stats(sourceID).model_study_learned).toBe(1)
      expect(ResearchQueue.stats(sourceID).model_study_completed).toBe(1)
      expect(ResearchQueue.stats(sourceID).model_study_pending).toBe(0)

      const events = Database.use((db) => db.select().from(ReportKnowledgeEventTable)
        .where(eq(ReportKnowledgeEventTable.report_id, knowledgeID)).all())
      expect(events.some((event) => event.hook === "research-study" && event.outcome === "observed")).toBe(false)
      expect(ReportKnowledge.stats().external).toBeGreaterThanOrEqual(1)

      const status = JSON.parse((await tool.execute({ action: "stats", source: sourceID, pages: 1000, depth: 3, limit: 3, continue_after_save: false }, context)).output)
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
      const next = await tool.execute({
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
      const sourceURL = "https://portswigger.net/web-security/source-filter-" + marker
      const sourceText = ("A reusable access-control security lesson. ").repeat(12)
      const queued = ResearchQueue.enqueue({
        sourceID: "portswigger",
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
      const next = await tool.execute({
        action: "next", source: "portswigger", pages: 5, depth: 2, limit: 3, continue_after_save: false,
      }, context)
      const batch = JSON.parse(next.output)
      const claimed = batch.items.find((item: { public_id: string }) => item.public_id === queued.id)
      expect(claimed).toBeDefined()
      if (!claimed) throw new Error("the PortSwigger fixture was not claimed")

      const save = await tool.execute({
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
      expect(ResearchQueue.find("portswigger", sourceURL)?.status).toBe("retry")
      expect(ReportKnowledge.stats().external).toBe(0)
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
            research_source: "portswigger",
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
      const result = await tool.execute({
        action: "backfill",
        pages: 5,
        depth: 2,
        limit: 3,
        continue_after_save: false,
      }, context)
      const summary = JSON.parse(result.output)
      expect(summary.legacy_knowledge_queued_for_model_study).toBe(legacyCount)
      expect(summary.legacy_knowledge_examined).toBe(legacyCount)
      expect(summary.current.queue.queued).toBe(legacyCount)
      expect(ResearchQueue.stats("portswigger").queued).toBe(legacyCount)
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
          research_source: "portswigger",
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

      const first = await queueLegacyKnowledgeForModelStudy("portswigger")
      expect(first.queued).toBeGreaterThanOrEqual(1)
      const queued = ResearchQueue.find("portswigger", sourceURL)
      expect(queued?.status).toBe("queued")
      expect(queued?.payload?.legacy_knowledge_id).toBe(legacy.id)
      expect(queued?.payload?.cached_text).toBe(excerpt)
      expect(queued?.payload?.model_study_requested_version).toBe(1)

      const currentKnowledge = Database.use((db) =>
        db.select().from(ReportKnowledgeTable).where(eq(ReportKnowledgeTable.id, legacy.id)).get(),
      )
      expect(currentKnowledge?.status).toBe("observed")
      expect(currentKnowledge?.metadata?.model_study_requested_version).toBe(1)

      await queueLegacyKnowledgeForModelStudy("portswigger")
      const stillQueued = ResearchQueue.find("portswigger", sourceURL)
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
      const next = await studyTool.execute({
        action: "next",
        source: "portswigger",
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

      const save = await studyTool.execute({
        action: "save",
        source: "portswigger",
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
      expect(finishedLegacy?.metadata?.model_study_version).toBe(1)
      expect(finishedLegacy?.metadata?.model_study_decision).toBe("rejected")
      const finishedQueue = ResearchQueue.find("portswigger", sourceURL)
      expect(finishedQueue?.status).toBe("rejected")
      expect(finishedQueue?.payload?.model_study_version).toBe(1)
      await queueLegacyKnowledgeForModelStudy("portswigger")
      const noDuplicateRequeue = ResearchQueue.find("portswigger", sourceURL)
      expect(noDuplicateRequeue?.status).toBe("rejected")
      expect(noDuplicateRequeue?.payload?.model_study_version).toBe(1)
      await Instance.dispose()
    },
  })
})

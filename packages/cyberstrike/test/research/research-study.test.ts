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

      const events = Database.use((db) => db.select().from(ReportKnowledgeEventTable)
        .where(eq(ReportKnowledgeEventTable.report_id, knowledgeID)).all())
      expect(events.some((event) => event.hook === "research-study" && event.outcome === "observed")).toBe(true)
      expect(ReportKnowledge.stats().external).toBeGreaterThanOrEqual(1)
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

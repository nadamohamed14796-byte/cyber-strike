import { expect, test } from "bun:test"
import { eq } from "drizzle-orm"
import { Instance } from "../../src/project/instance"
import { Database } from "../../src/storage/db"
import { SessionTable } from "../../src/session/session.sql"
import { ReportKnowledgeEventTable, ReportKnowledgeTable } from "../../src/learning/report-knowledge.sql"
import { ReportKnowledge } from "../../src/learning/report-knowledge"
import { ResearchQueue } from "../../src/research/queue"
import { ResearchStudyTool } from "../../src/tool/research-study"
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
      expect(batch.batch_size).toBe(1)
      const claimed = batch.items[0]
      expect(claimed.public_id).toBe(queued.id)
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
      expect(knowledge?.metadata?.excerpt).toContain("two controlled accounts")
      expect(ResearchQueue.find(sourceID, sourceURL)?.status).toBe("learned")

      const events = Database.use((db) => db.select().from(ReportKnowledgeEventTable)
        .where(eq(ReportKnowledgeEventTable.report_id, knowledgeID)).all())
      expect(events.some((event) => event.hook === "research-study" && event.outcome === "observed")).toBe(true)
      expect(ReportKnowledge.stats().external).toBeGreaterThanOrEqual(1)
      await Instance.dispose()
    },
  })
})

import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Database } from "../../src/storage/db"
import { FalsePositiveKnowledgeTable } from "../../src/methodology/false-positive-knowledge.sql"
import { FalsePositiveKnowledge } from "../../src/methodology/false-positive-knowledge"
import { tmpdir } from "../fixture/fixture"

test("false-positive memory persists normalized lessons across targets and redacts secrets", async () => {
  await using dir = await tmpdir({ git: true })
  await Instance.provide({
    directory: dir.path,
    fn: async () => {
      const finding = {
        id: "finding-source-1",
        title: "IDOR: user can read another account's private profile",
        description: "Broken access control allows a cross-account profile read.",
        endpoint: "GET /api/users/12345/profile",
      }
      const checks = [
        { id: "reproducible", status: "fail", reason: "The behavior was not reproducible", evidence: "Controlled replays matched the expected response" },
        { id: "unexpected_behavior", status: "fail", reason: "The response matches intended policy", evidence: "Owner and non-owner controls showed the documented behavior" },
        { id: "benign_behavior_ruled_out", status: "fail", reason: "Expected policy explains the response", evidence: "Authorization: Bearer secret-token-value" },
      ]
      const record = {
        finding,
        validationID: "validation-source-1",
        failedCheckIDs: ["reproducible", "unexpected_behavior"],
        checks,
        summary: "The controlled owner/non-owner comparison matched intended policy.",
      }
      FalsePositiveKnowledge.record(record)
      FalsePositiveKnowledge.record({ ...record, validationID: "validation-source-2" })

      const matches = FalsePositiveKnowledge.similar({
        title: "IDOR: user can read another account's private profile",
        description: "Possible broken access control",
        endpoint: "GET /api/users/98765/profile",
      })
      expect(matches.length).toBe(1)
      expect(matches[0]?.occurrences).toBe(2)
      expect(matches[0]?.endpointPattern).toBe("/api/users/{n}/profile")
      expect(matches[0]?.benignExplanation).not.toContain("secret-token-value")
      expect(matches[0]?.benignExplanation).toContain("[REDACTED]")
      const rows = Database.use((db) => db.select().from(FalsePositiveKnowledgeTable).all())
      expect(rows).toHaveLength(1)
      expect(rows[0]?.source_validation_id).toBe("validation-source-2")
    },
  })
})

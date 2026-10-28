import { expect, test } from "bun:test"
import { tmpdir } from "../fixture/fixture"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { Intel } from "../../src/methodology/intel"
import { Chain } from "../../src/methodology/chain"
import { Vulnerability } from "../../src/session/vulnerability"
import { FindingValidationTable } from "../../src/methodology/finding-validation.sql"
import { Database } from "../../src/storage/db"
import { Identifier } from "../../src/id/id"

test("an INFO-to-INFO chain remains a hypothesis until the combined finding is validated and approved", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      try {
        Intel.add({ sessionID: session.id, data: {
          type: "configuration",
          severity: "info",
          title: "Internal service configuration",
          detail: "Deployment metadata identifies internal-api.staging.example.com",
          asset: "app.example.com",
          source: "test",
          confidenceLevel: "high",
        }})
        Intel.add({ sessionID: session.id, data: {
          type: "api_schema",
          severity: "info",
          title: "Internal API schema",
          detail: "A public schema describes internal account-management routes",
          asset: "app.example.com",
          source: "test",
          confidenceLevel: "high",
        }})

        const candidates = Chain.detectAndPersist(session.id)
        const chain = candidates.find((item) => item.pattern === "information_amplification")
        expect(chain).toBeDefined()
        if (!chain) throw new Error("Expected informational chain candidate")

        const combined = Vulnerability.add({
          sessionID: session.id,
          data: {
            severity: "high",
            title: "Combined internal API exposure",
            description: "A validated combined-impact finding with redacted evidence.",
            endpoint: "https://app.example.com/",
          },
        })

        const beforeTriage = Chain.recordValidation({
          sessionID: session.id,
          chainID: chain.id,
          outcome: "confirmed",
          evidence: "Observed combined path with baseline and negative control and concrete impact.",
          validatedBy: "test",
          combinedFindingID: combined.id,
        })
        expect(beforeTriage).toEqual({ ok: false, reason: "finding_not_approved" })

        expect(Vulnerability.update({
          sessionID: session.id,
          id: combined.id,
          status: "approved",
          expectedStatus: "new",
        })).toBe(true)

        const beforeValidation = Chain.recordValidation({
          sessionID: session.id,
          chainID: chain.id,
          outcome: "confirmed",
          evidence: "Observed combined path with baseline and negative control and concrete impact.",
          validatedBy: "test",
          combinedFindingID: combined.id,
        })
        expect(beforeValidation).toEqual({ ok: false, reason: "finding_validation_required" })

        const now = Date.now()
        Database.use((db) => db.insert(FindingValidationTable).values({
          id: Identifier.ascending("finding_validation"),
          session_id: session.id,
          vulnerability_id: combined.id,
          verdict: "confirmed",
          confidence: 95,
          checks: [] as any,
          attempts: [] as any,
          attempt_count: 1,
          failed_check_ids: [] as any,
          unknown_check_ids: [] as any,
          summary: "Combined impact confirmed in a controlled test fixture.",
          next_step: "Record the final chain outcome.",
          time_created: now,
          time_updated: now,
        }).run())

        const confirmed = Chain.recordValidation({
          sessionID: session.id,
          chainID: chain.id,
          outcome: "confirmed",
          evidence: "Observed combined path with baseline and negative control and concrete impact.",
          validatedBy: "test",
          combinedFindingID: combined.id,
        })
        expect(confirmed).toEqual({
          ok: true,
          outcome: "confirmed",
          chainID: chain.id,
          combinedFindingID: combined.id,
        })

        const saved = Chain.load(session.id).find((item) => item.id === chain.id)
        expect(saved?.status).toBe("confirmed")
        expect(saved?.validation?.outcome).toBe("confirmed")
        expect(saved?.validation?.combinedFindingID).toBe(combined.id)

        expect(Chain.recordValidation({
          sessionID: session.id,
          chainID: chain.id,
          outcome: "disproven",
          evidence: "New contradictory evidence has not been accepted because this chain is terminal.",
          validatedBy: "test",
        })).toEqual({ ok: false, reason: "chain_terminal" })
      } finally {
        await Session.remove(session.id)
      }
    },
  })
})

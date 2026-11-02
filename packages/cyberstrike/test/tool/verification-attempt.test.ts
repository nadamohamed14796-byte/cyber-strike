import { expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Request } from "../../src/session/request"
import { Session } from "../../src/session"
import { VerificationLedger } from "../../src/session/verification-ledger"
import { VerificationAttemptTool } from "../../src/tool/verification-attempt"
import { tmpdir } from "../fixture/fixture"

function toolContext(sessionID: string) {
  return {
    sessionID,
    messageID: "msg_verification_attempt_test",
    agent: "test",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => undefined,
    ask: async () => undefined,
  } as never
}

function recordParams(evidenceRef: string) {
  return {
    action: "record" as const,
    hypothesis_key: "verification-request-reference",
    asset: "https://example.test",
    endpoint: "/api/profile",
    vulnerability_class: "idor",
    strategy_id: "idor.owner-vs-non-owner",
    variant_key: "controlled-user-pair",
    rationale: "Compare the same resource across two controlled identities.",
    result_summary: "The captured response was reviewed.",
    evidence_ref: evidenceRef,
    valid_conditions: true,
  }
}

test("verification evidence_ref must identify a captured request in the same session", async () => {
  await using tmp = await tmpdir()
  await Instance.provide({
    directory: tmp.path,
    async fn() {
      const session = await Session.create({})
      const otherSession = await Session.create({})
      try {
        const foreignRequest = Request.add({
          sessionID: otherSession.id,
          method: "GET",
          normalizedPath: "/api/profile",
          origin: "https://example.test",
          scheme: "https",
          host: "example.test",
        })
        expect(foreignRequest).toBeDefined()

        const localRequest = Request.add({
          sessionID: session.id,
          method: "GET",
          normalizedPath: "/api/profile",
          origin: "https://example.test",
          scheme: "https",
          host: "example.test",
        })
        expect(localRequest).toBeDefined()

        const tool = await VerificationAttemptTool.init()
        const ctx = toolContext(session.id)

        const freeForm = await tool.execute(recordParams("evidence://not-a-request"), ctx)
        expect(freeForm.title).toContain("request reference not found")
        expect(VerificationLedger.list({
          sessionID: session.id,
          hypothesisKey: "verification-request-reference",
        })).toHaveLength(0)

        const crossSession = await tool.execute(recordParams(foreignRequest!.id), ctx)
        expect(crossSession.title).toContain("request reference not found")
        expect(VerificationLedger.list({
          sessionID: session.id,
          hypothesisKey: "verification-request-reference",
        })).toHaveLength(0)

        const valid = await tool.execute(recordParams("  " + localRequest!.id + "  "), ctx)
        expect(valid.title).toContain("Verification (1 evidence-backed attempts)")
        const attempts = VerificationLedger.list({
          sessionID: session.id,
          hypothesisKey: "verification-request-reference",
        })
        expect(attempts).toHaveLength(1)
        expect(attempts[0]?.evidenceRef).toBe(localRequest!.id)
      } finally {
        await Session.remove(otherSession.id)
        await Session.remove(session.id)
      }
    },
  })
})

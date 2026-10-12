import { describe, expect, test } from "bun:test"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { VerificationLedger } from "../../src/session/verification-ledger"
import { tmpdir } from "../fixture/fixture"

function attempt(strategyID: string, evidenceRef?: string) {
  return {
    strategyID,
    variantKey: "controlled-valid-session",
    rationale: "Verify one specific hypothesis with a distinct strategy",
    resultSummary: "Observed a controlled response",
    evidenceRef,
    validConditions: true,
  }
}

describe("VerificationLedger terminal outcomes", () => {
  test("a confirmed hypothesis cannot accept another attempt", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const session = await Session.createNext({ directory: tmp.path, title: "verification-ledger-confirmed-test" })
        const first = VerificationLedger.record({
          sessionID: session.id,
          hypothesisKey: "confirmed-hypothesis",
          asset: "https://example.test",
          endpoint: "/api/profile",
          vulnerabilityClass: "idor",
          attempt: attempt("idor.owner-vs-non-owner", "evidence://confirmed"),
          decisiveResult: "confirmed",
        })

        expect(first.decision.outcome).toBe("confirmed")
        expect(VerificationLedger.list({ sessionID: session.id, hypothesisKey: "confirmed-hypothesis" }))
          .toHaveLength(1)
        expect(() => VerificationLedger.record({
          sessionID: session.id,
          hypothesisKey: "confirmed-hypothesis",
          asset: "https://example.test",
          endpoint: "/api/profile",
          vulnerabilityClass: "idor",
          attempt: attempt("idor.second-independent-check", "evidence://second"),
        })).toThrow(/already confirmed; terminal hypotheses cannot accept more attempts/i)
        await Instance.dispose()
      },
    })
  })

  test("a disproven hypothesis becomes terminal only after 20 valid distinct attempts", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const session = await Session.createNext({ directory: tmp.path, title: "verification-ledger-disproven-test" })
        const common = {
          sessionID: session.id,
          hypothesisKey: "disproven-hypothesis",
          asset: "https://example.test",
          endpoint: "/api/profile",
          vulnerabilityClass: "idor",
        }
        for (let i = 0; i < 19; i++) {
          const result = VerificationLedger.record({
            ...common,
            attempt: attempt("idor.control-" + i),
          })
          expect(result.decision.outcome).toBe("inconclusive")
        }

        const final = VerificationLedger.record({
          ...common,
          attempt: attempt("idor.control-19", "evidence://direct-disproof"),
          decisiveResult: "disproven",
        })
        expect(final.decision.outcome).toBe("disproven")
        expect(final.decision.attemptsUsed).toBe(20)
        expect(VerificationLedger.list({ sessionID: session.id, hypothesisKey: common.hypothesisKey })
          .every((item) => item.outcome === "disproven")).toBe(true)

        expect(() => VerificationLedger.record({
          ...common,
          attempt: attempt("idor.control-20", "evidence://late-attempt"),
        })).toThrow(/already disproven; terminal hypotheses cannot accept more attempts/i)
        await Instance.dispose()
      },
    })
  })
})

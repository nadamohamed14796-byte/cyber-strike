import { describe, expect, test } from "bun:test"
import { Database, and, eq } from "../../src/storage/db"
import { VerificationAttemptTable } from "../../src/methodology/methodology.sql"
import { Instance } from "../../src/project/instance"
import { Session } from "../../src/session"
import { VerificationLedger } from "../../src/session/verification-ledger"
import { tmpdir } from "../fixture/fixture"

function attempt(strategyID: string, evidenceRef?: string, validConditions = true) {
  return {
    strategyID,
    variantKey: "controlled-valid-session",
    rationale: "Verify one specific hypothesis with a distinct strategy",
    resultSummary: "Observed a controlled response",
    evidenceRef,
    validConditions,
  }
}

describe("VerificationLedger terminal outcomes", () => {
  test("invalid attempts do not exhaust the budget before valid attempts can run", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const session = await Session.createNext({ directory: tmp.path, title: "verification-ledger-invalid-budget-test" })
        const common = {
          sessionID: session.id,
          hypothesisKey: "invalid-budget-hypothesis",
          asset: "https://example.test",
          endpoint: "/api/profile",
          vulnerabilityClass: "idor",
        }
        for (let i = 0; i < 20; i++) {
          const result = VerificationLedger.record({
            ...common,
            attempt: attempt("invalid-setup-" + i, undefined, false),
          })
          expect(result.decision.attemptsUsed).toBe(0)
          expect(result.decision.remainingAttempts).toBe(20)
        }
        for (let i = 0; i < 20; i++) {
          const result = VerificationLedger.record({
            ...common,
            attempt: attempt("valid-strategy-" + i, i === 19 ? "evidence://direct-disproof" : undefined),
            ...(i === 19 ? { decisiveResult: "disproven" as const } : {}),
          })
          expect(result.decision.attemptsUsed).toBe(i + 1)
          if (i < 19) expect(result.decision.outcome).toBe("inconclusive")
          else expect(result.decision.outcome).toBe("disproven")
        }
        await Instance.dispose()
      },
    })
  })

  test("legacy disproven verdicts with fewer than 20 valid attempts are downgraded and resumable", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const session = await Session.createNext({ directory: tmp.path, title: "verification-ledger-legacy-disproof-test" })
        const common = {
          sessionID: session.id,
          hypothesisKey: "legacy-disproven-hypothesis",
          asset: "https://example.test",
          endpoint: "/api/profile",
          vulnerabilityClass: "idor",
        }
        VerificationLedger.record({
          ...common,
          attempt: attempt("legacy-single-check", "evidence://old-disproof"),
        })
        Database.use((db) => db.update(VerificationAttemptTable).set({
          outcome: "disproven",
        }).where(and(
          eq(VerificationAttemptTable.session_id, session.id),
          eq(VerificationAttemptTable.hypothesis_key, common.hypothesisKey),
        )).run())

        expect(VerificationLedger.list({ sessionID: session.id, hypothesisKey: common.hypothesisKey })
          .every((item) => item.outcome === "inconclusive")).toBe(true)

        const duplicateRetry = VerificationLedger.record({
          ...common,
          attempt: attempt("legacy-single-check", "evidence://old-disproof"),
        })
        expect(duplicateRetry.attempt.outcome).toBe("inconclusive")
        expect(duplicateRetry.decision.outcome).toBe("inconclusive")

        const resumed = VerificationLedger.record({
          ...common,
          attempt: attempt("new-valid-check"),
        })
        expect(resumed.decision.outcome).toBe("inconclusive")
        expect(resumed.decision.attemptsUsed).toBe(2)
        expect(VerificationLedger.list({ sessionID: session.id, hypothesisKey: common.hypothesisKey })
          .every((item) => item.outcome === "inconclusive")).toBe(true)
        await Instance.dispose()
      },
    })
  })

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
  test("a duplicate invalid retry cannot downgrade valid evidence or reopen the budget", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const session = await Session.createNext({ directory: tmp.path, title: "verification-ledger-no-downgrade-test" })
        const common = {
          sessionID: session.id,
          hypothesisKey: "no-downgrade-hypothesis",
          asset: "https://example.test",
          endpoint: "/api/profile",
          vulnerabilityClass: "idor",
        }
        for (let i = 0; i < 20; i++) {
          VerificationLedger.record({
            ...common,
            attempt: attempt("valid-strategy-" + i, "evidence://valid-" + i),
          })
        }
        const duplicate = VerificationLedger.record({
          ...common,
          attempt: attempt("valid-strategy-0", undefined, false),
        })
        expect(duplicate.duplicate).toBe(true)
        expect(VerificationLedger.list({ sessionID: session.id, hypothesisKey: common.hypothesisKey })
          .find((item) => item.strategyID === "valid-strategy-0")?.validConditions).toBe(true)
        expect(() => VerificationLedger.record({
          ...common,
          attempt: attempt("valid-strategy-20", "evidence://late-valid"),
        })).toThrow(/20-valid-distinct-attempt budget is exhausted/i)
        await Instance.dispose()
      },
    })
  })

  test("an invalid attempt cannot be upgraded into a 21st valid attempt", async () => {
    await using tmp = await tmpdir()
    await Instance.provide({
      directory: tmp.path,
      async fn() {
        const session = await Session.createNext({ directory: tmp.path, title: "verification-ledger-no-upgrade-test" })
        const common = {
          sessionID: session.id,
          hypothesisKey: "no-upgrade-hypothesis",
          asset: "https://example.test",
          endpoint: "/api/profile",
          vulnerabilityClass: "idor",
        }
        for (let i = 0; i < 20; i++) {
          VerificationLedger.record({
            ...common,
            attempt: attempt("valid-strategy-" + i, "evidence://valid-" + i),
          })
        }
        VerificationLedger.record({
          ...common,
          attempt: attempt("invalid-candidate", undefined, false),
        })
        expect(() => VerificationLedger.record({
          ...common,
          attempt: attempt("invalid-candidate", "evidence://late-valid", true),
        })).toThrow(/20-valid-distinct-attempt budget is exhausted/i)
        await Instance.dispose()
      },
    })
  })

})

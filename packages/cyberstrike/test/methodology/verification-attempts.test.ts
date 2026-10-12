import { describe, expect, test } from "bun:test"
import { VerificationAttempts as VA } from "../../src/methodology/verification-attempts"

const attempt = (strategyID: string, variantKey: string, validConditions = true): VA.Attempt => ({
  strategyID,
  variantKey,
  rationale: "Test a distinct hypothesis path",
  resultSummary: "No decisive signal observed",
  validConditions,
})

describe("VerificationAttempts", () => {
  test("caps distinct strategies at 20 and does not count exact duplicates", () => {
    const attempts = Array.from({ length: 20 }, (_, i) => attempt("strategy-" + i, "baseline"))
    expect(VA.uniqueAttempts([...attempts, attempts[0]]).length).toBe(20)
    expect(VA.canRunAttempt(attempts, { strategyID: "strategy-0", variantKey: "baseline" })).toBe(false)
    expect(VA.canRunAttempt(attempts, { strategyID: "strategy-new", variantKey: "baseline" })).toBe(false)
  })

  test("normalizes strategy and variant identity to avoid case/whitespace retry inflation", () => {
    const first = attempt(" IDOR.Owner-Check ", "Account-A")
    const duplicate = attempt("idor.owner-check", "account-a")
    expect(VA.uniqueAttempts([first, duplicate])).toHaveLength(1)
    expect(VA.canRunAttempt([first], { strategyID: "IDOR.OWNER-CHECK", variantKey: " account-a " })).toBe(false)
  })

  test("ignores malformed blank strategy identities instead of counting them", () => {
    expect(VA.uniqueAttempts([attempt(" ", "variant"), attempt("strategy", "  ")])).toHaveLength(0)
    expect(VA.canRunAttempt([], { strategyID: " ", variantKey: "variant" })).toBe(false)
  })

  test("allows a meaningful variant as a distinct attempt", () => {
    expect(VA.canRunAttempt([attempt("idor.owner-check", "account-a")], {
      strategyID: "idor.owner-check",
      variantKey: "account-b",
    })).toBe(true)
  })

  test("budget exhaustion is inconclusive, never automatic false positive", () => {
    const result = VA.decide({ attempts: Array.from({ length: 20 }, (_, i) => attempt("strategy-" + i, "v1")) })
    expect(result.outcome).toBe("inconclusive")
    expect(result.canContinue).toBe(false)
    expect(result.reason).toContain("do not label this a false positive")
  })

  test("disproof requires valid test conditions", () => {
    const result = VA.decide({
      attempts: [attempt("auth-check", "expired-session", false)],
      decisiveDisproof: true,
    })
    expect(result.outcome).toBe("inconclusive")
    expect(result.canContinue).toBe(true)
  })

  test("decisive confirmation stops early", () => {
    const result = VA.decide({ attempts: [attempt("xss.execution-check", "benign-marker")], decisiveConfirmation: true })
    expect(result.outcome).toBe("confirmed")
    expect(result.canContinue).toBe(false)
  })

  test("confirmation without valid preconditions remains inconclusive", () => {
    const result = VA.decide({
      attempts: [attempt("xss.execution-check", "marker", false)],
      decisiveConfirmation: true,
    })
    expect(result.outcome).toBe("inconclusive")
    expect(result.canContinue).toBe(true)
  })

  test("blocked prerequisites stop safely without false-positive verdict", () => {
    const result = VA.decide({
      attempts: [attempt("auth-check", "missing-credential", false)],
      blockedReason: "Required authorized test account is unavailable.",
    })
    expect(result.outcome).toBe("inconclusive")
    expect(result.canContinue).toBe(false)
    expect(result.reason).toContain("unavailable")
  })
})

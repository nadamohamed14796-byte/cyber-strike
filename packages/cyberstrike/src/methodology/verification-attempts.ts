/**
 * Shared policy for adaptive vulnerability verification.
 *
 * This module deliberately separates "attempt budget exhausted" from a
 * false-positive verdict: exhausting the budget can only produce INCONCLUSIVE.
 */
export namespace VerificationAttempts {
  export const MAX_ATTEMPTS = 20

  export type Outcome = "confirmed" | "disproven" | "inconclusive"

  export interface Attempt {
    /** Stable strategy identifier, e.g. "idor.owner-vs-non-owner". */
    strategyID: string
    /** Distinguishes meaningful variants of a strategy without counting retries. */
    variantKey: string
    rationale: string
    resultSummary: string
    evidenceRef?: string
    /** True only when this attempt ran under valid preconditions. */
    validConditions: boolean
  }

  export interface DecisionInput {
    attempts: Attempt[]
    /** Evidence directly supports the stated vulnerability hypothesis. */
    decisiveConfirmation?: boolean
    /** Evidence directly contradicts the stated hypothesis under valid conditions. */
    decisiveDisproof?: boolean
    /** Durable reference to the direct request/response evidence that justifies either verdict. */
    decisiveEvidenceRef?: string
    /** A hard stop such as out-of-scope, unsafe, or unavailable target. */
    blockedReason?: string
  }

  export interface Decision {
    outcome: Outcome
    attemptsUsed: number
    remainingAttempts: number
    canContinue: boolean
    reason: string
  }

  /** Identity includes the variant: exact retries never consume the budget. */
  export function attemptKey(attempt: Pick<Attempt, "strategyID" | "variantKey">): string {
    return `${attempt.strategyID.trim().toLowerCase()}::${attempt.variantKey.trim().toLowerCase()}`
  }

  export function uniqueAttempts(attempts: Attempt[]): Attempt[] {
    const seen = new Set<string>()
    return attempts.filter((attempt) => {
      const key = attemptKey(attempt)
      if (!attempt.strategyID.trim() || !attempt.variantKey.trim() || seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  export function canRunAttempt(attempts: Attempt[], next: Pick<Attempt, "strategyID" | "variantKey">): boolean {
    const unique = uniqueAttempts(attempts)
    return unique.length < MAX_ATTEMPTS && Boolean(next.strategyID.trim() && next.variantKey.trim()) &&
      !unique.some((attempt) => attemptKey(attempt) === attemptKey(next))
  }

  export function decide(input: DecisionInput): Decision {
    const attempts = uniqueAttempts(input.attempts)
    const attemptsUsed = attempts.length
    const remainingAttempts = Math.max(0, MAX_ATTEMPTS - attemptsUsed)

    const hasDecisiveEvidence = Boolean(input.decisiveEvidenceRef?.trim())

    if (input.decisiveConfirmation && hasDecisiveEvidence && attempts[attempts.length - 1]?.validConditions) {
      return { outcome: "confirmed", attemptsUsed, remainingAttempts, canContinue: false, reason: "Decisive evidence supports the vulnerability hypothesis." }
    }

    const hasValidDisproof = input.decisiveDisproof && hasDecisiveEvidence && attempts[attempts.length - 1]?.validConditions
    if (hasValidDisproof) {
      return { outcome: "disproven", attemptsUsed, remainingAttempts, canContinue: false, reason: "Direct evidence contradicts the hypothesis under valid test conditions." }
    }

    if (input.blockedReason) {
      return { outcome: "inconclusive", attemptsUsed, remainingAttempts, canContinue: false, reason: input.blockedReason }
    }

    if (attemptsUsed >= MAX_ATTEMPTS) {
      return { outcome: "inconclusive", attemptsUsed, remainingAttempts: 0, canContinue: false, reason: "The 20-distinct-attempt budget is exhausted without decisive evidence; do not label this a false positive." }
    }

    return { outcome: "inconclusive", attemptsUsed, remainingAttempts, canContinue: true, reason: "More adaptive, non-duplicate verification is required before a final verdict." }
  }
}
